package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseValidConfig(t *testing.T) {
	yaml := `
groups:
  - name: test-group
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: |
          SELECT service, countIf(status >= 500) / count() AS value
          FROM http_requests
          WHERE timestamp > now() - INTERVAL 5 MINUTE
          GROUP BY service
          HAVING value > 0.05
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "Error rate {{ $value }} on {{ $labels.service }}"

      - alert: SimpleAlert
        expr: SELECT 'test' AS scope, 1 AS value
`

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	groups, err := Parse([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	g := groups[0]
	if g.Name != "test-group" {
		t.Errorf("expected name 'test-group', got %q", g.Name)
	}
	if g.Interval.Duration() != 30*time.Second {
		t.Errorf("expected interval 30s, got %s", g.Interval.Duration())
	}
	if len(g.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(g.Rules))
	}

	r := g.Rules[0]
	if r.Alert != "HighErrorRate" {
		t.Errorf("expected alert 'HighErrorRate', got %q", r.Alert)
	}
	if r.For.Duration() != 3*time.Minute {
		t.Errorf("expected for 3m, got %s", r.For.Duration())
	}
	if r.Labels["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %q", r.Labels["severity"])
	}
	if r.ID == 0 {
		t.Error("expected non-zero rule ID")
	}

	// Verify IDs are different
	if g.Rules[0].ID == g.Rules[1].ID {
		t.Error("expected different rule IDs")
	}
}

func TestParseInvalidRule(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "missing alert and record",
			yaml: `
groups:
  - name: g
    rules:
      - expr: SELECT 1 AS value
`,
		},
		{
			name: "both alert and record",
			yaml: `
groups:
  - name: g
    rules:
      - alert: foo
        record: bar
        expr: SELECT 1 AS value
`,
		},
		{
			name: "empty expression",
			yaml: `
groups:
  - name: g
    rules:
      - alert: foo
        expr: ""
`,
		},
		{
			name: "non-SELECT expression",
			yaml: `
groups:
  - name: g
    rules:
      - alert: foo
        expr: INSERT INTO bad VALUES (1)
`,
		},
		{
			name: "recording rule with annotations",
			yaml: `
groups:
  - name: g
    rules:
      - record: foo
        expr: SELECT 1 AS value
        annotations:
          summary: "nope"
`,
		},
		{
			name: "recording rule with for",
			yaml: `
groups:
  - name: g
    rules:
      - record: foo
        expr: SELECT 1 AS value
        for: 5m
`,
		},
		{
			name: "empty group name",
			yaml: `
groups:
  - name: ""
    rules:
      - alert: foo
        expr: SELECT 1 AS value
`,
		},
		{
			name: "duplicate rules",
			yaml: `
groups:
  - name: g
    rules:
      - alert: foo
        expr: SELECT 1 AS value
      - alert: foo
        expr: SELECT 1 AS value
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "rules.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := Parse([]string{path})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			t.Logf("got expected error: %s", err)
		})
	}
}

func TestEnvSubstitution(t *testing.T) {
	os.Setenv("CHALERT_TEST_TABLE", "my_table")
	defer os.Unsetenv("CHALERT_TEST_TABLE")

	yaml := `
groups:
  - name: env-test
    rules:
      - alert: EnvAlert
        expr: SELECT 1 AS value FROM %{CHALERT_TEST_TABLE}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	groups, err := Parse([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expr := groups[0].Rules[0].Expr
	if expected := "SELECT 1 AS value FROM my_table"; expr != expected {
		t.Errorf("expected %q, got %q", expected, expr)
	}
}

func TestHashRuleDeterminism(t *testing.T) {
	r := Rule{
		Alert: "TestAlert",
		Expr:  "SELECT 1 AS value",
		Labels: map[string]string{
			"b": "2",
			"a": "1",
		},
	}

	h1 := HashRule(r)
	h2 := HashRule(r)
	if h1 != h2 {
		t.Errorf("hash not deterministic: %d != %d", h1, h2)
	}

	// Different expression = different hash
	r2 := r
	r2.Expr = "SELECT 2 AS value"
	if HashRule(r2) == h1 {
		t.Error("different expressions should produce different hashes")
	}
}

func TestMultiDocumentYAML(t *testing.T) {
	yaml := `
groups:
  - name: group-a
    rules:
      - alert: AlertA
        expr: SELECT 1 AS value
---
groups:
  - name: group-b
    rules:
      - alert: AlertB
        expr: SELECT 2 AS value
`
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	groups, err := Parse([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Name != "group-a" || groups[1].Name != "group-b" {
		t.Errorf("unexpected group names: %q, %q", groups[0].Name, groups[1].Name)
	}
}
