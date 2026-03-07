package notifier

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/garbett1/chalert/rule"
)

func TestBuildPayload_EndsAtFromInterval(t *testing.T) {
	am := &AlertManager{externalURL: "http://localhost"}

	now := time.Now()
	alerts := []rule.AlertInstance{
		{
			State:              rule.StateFiring,
			Labels:             map[string]string{"alertname": "Test"},
			ActiveAt:           now.Add(-time.Minute),
			EvaluationInterval: 10 * time.Second,
		},
	}

	payload, err := am.buildPayload(alerts)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}

	var parsed []amAlert
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(parsed))
	}

	// EndsAt should be ~40s from now (4 * 10s), not ~4min
	diff := parsed[0].EndsAt.Sub(now)
	if diff < 30*time.Second || diff > 50*time.Second {
		t.Errorf("expected EndsAt ~40s from now, got diff=%s", diff)
	}
}

func TestBuildPayload_EndsAtFallback(t *testing.T) {
	am := &AlertManager{}

	now := time.Now()
	alerts := []rule.AlertInstance{
		{
			State:    rule.StateFiring,
			Labels:   map[string]string{"alertname": "Test"},
			ActiveAt: now.Add(-time.Minute),
		},
	}

	payload, err := am.buildPayload(alerts)
	if err != nil {
		t.Fatal(err)
	}

	var parsed []amAlert
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(parsed))
	}

	diff := parsed[0].EndsAt.Sub(now)
	if diff < 3*time.Minute || diff > 5*time.Minute {
		t.Errorf("expected EndsAt ~4min from now (fallback), got diff=%s", diff)
	}
}

func TestBuildPayload_ResolvedEndsAt(t *testing.T) {
	am := &AlertManager{}

	resolvedAt := time.Now().Add(-30 * time.Second)
	alerts := []rule.AlertInstance{
		{
			State:      rule.StateInactive,
			Labels:     map[string]string{"alertname": "Test"},
			ActiveAt:   time.Now().Add(-5 * time.Minute),
			ResolvedAt: resolvedAt,
		},
	}

	payload, err := am.buildPayload(alerts)
	if err != nil {
		t.Fatal(err)
	}

	var parsed []amAlert
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(parsed))
	}

	if parsed[0].Status != "resolved" {
		t.Errorf("expected resolved status, got %q", parsed[0].Status)
	}
	if !parsed[0].EndsAt.Equal(resolvedAt) {
		t.Errorf("expected EndsAt=%v, got %v", resolvedAt, parsed[0].EndsAt)
	}
}
