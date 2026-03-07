package rule

import (
	"context"
	"testing"
	"time"

	"github.com/garbett1/chalert/config"
	"github.com/garbett1/chalert/datasource"
)

// fakeQuerier returns predefined results for testing.
type fakeQuerier struct {
	results datasource.Result
	err     error
}

func (f *fakeQuerier) Query(_ context.Context, _ string, _ time.Time) (datasource.Result, error) {
	return f.results, f.err
}

func (f *fakeQuerier) QueryRange(_ context.Context, _ string, _, _ time.Time) (datasource.Result, error) {
	return f.results, f.err
}

type fakeQuerierBuilder struct {
	q datasource.Querier
}

func (f *fakeQuerierBuilder) BuildWithParams(_ datasource.QuerierParams) datasource.Querier {
	return f.q
}

func TestAlertingRule_PendingToFiring(t *testing.T) {
	q := &fakeQuerier{
		results: datasource.Result{
			Data: []datasource.Metric{
				{
					Labels:     []datasource.Label{{Name: "service", Value: "api"}},
					Values:     []float64{0.1},
					Timestamps: []int64{time.Now().Unix()},
				},
			},
		},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "test-group", time.Minute, config.Rule{
		Alert: "TestAlert",
		Expr:  "SELECT 'api' AS service, 0.1 AS value",
		For:   config.Duration{D: 2 * time.Minute},
		ID:    12345,
	})

	now := time.Now()

	// First eval: should create Pending alert
	alerts, err := rule.Exec(context.Background(), now, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts to send (pending), got %d", len(alerts))
	}

	allAlerts := rule.GetAlerts()
	if len(allAlerts) != 1 {
		t.Fatalf("expected 1 alert instance, got %d", len(allAlerts))
	}
	if allAlerts[0].State != StatePending {
		t.Errorf("expected Pending, got %s", allAlerts[0].State)
	}

	// Second eval at now+1m: still pending (for=2m)
	alerts, err = rule.Exec(context.Background(), now.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts (still pending), got %d", len(alerts))
	}

	// Third eval at now+2m: should transition to Firing
	alerts, err = rule.Exec(context.Background(), now.Add(2*time.Minute), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 firing alert, got %d", len(alerts))
	}
	if alerts[0].State != StateFiring {
		t.Errorf("expected Firing, got %s", alerts[0].State)
	}
	if alerts[0].Labels["alertname"] != "TestAlert" {
		t.Errorf("expected alertname=TestAlert, got %q", alerts[0].Labels["alertname"])
	}
	if alerts[0].Labels["service"] != "api" {
		t.Errorf("expected service=api, got %q", alerts[0].Labels["service"])
	}
}

func TestAlertingRule_ForZero_ImmediateFiring(t *testing.T) {
	q := &fakeQuerier{
		results: datasource.Result{
			Data: []datasource.Metric{
				{
					Labels:     []datasource.Label{{Name: "host", Value: "node1"}},
					Values:     []float64{42},
					Timestamps: []int64{time.Now().Unix()},
				},
			},
		},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "test-group", time.Minute, config.Rule{
		Alert: "InstantAlert",
		Expr:  "SELECT 'node1' AS host, 42 AS value",
		// No "for" duration — fires immediately
		ID: 99999,
	})

	alerts, err := rule.Exec(context.Background(), time.Now(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert (immediate fire), got %d", len(alerts))
	}
	if alerts[0].State != StateFiring {
		t.Errorf("expected Firing, got %s", alerts[0].State)
	}
}

func TestAlertingRule_Resolution(t *testing.T) {
	q := &fakeQuerier{
		results: datasource.Result{
			Data: []datasource.Metric{
				{
					Labels:     []datasource.Label{{Name: "svc", Value: "a"}},
					Values:     []float64{1},
					Timestamps: []int64{time.Now().Unix()},
				},
			},
		},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "g", time.Minute, config.Rule{
		Alert: "ResTest",
		Expr:  "SELECT 'a' AS svc, 1 AS value",
		ID:    111,
	})

	now := time.Now()

	// Fire the alert
	alerts, err := rule.Exec(context.Background(), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].State != StateFiring {
		t.Fatal("expected 1 firing alert")
	}

	// Expression stops matching (empty results)
	q.results = datasource.Result{Data: nil}

	alerts, err = rule.Exec(context.Background(), now.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}

	// Should get a resolved alert notification
	found := false
	for _, a := range alerts {
		if a.State == StateInactive {
			found = true
		}
	}
	if !found {
		t.Error("expected resolved (inactive) alert to be sent")
	}
}

func TestAlertingRule_LabelConflict(t *testing.T) {
	q := &fakeQuerier{
		results: datasource.Result{
			Data: []datasource.Metric{
				{
					Labels:     []datasource.Label{{Name: "env", Value: "from-query"}},
					Values:     []float64{1},
					Timestamps: []int64{time.Now().Unix()},
				},
			},
		},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "g", time.Minute, config.Rule{
		Alert:  "LabelTest",
		Expr:   "SELECT 'from-query' AS env, 1 AS value",
		Labels: map[string]string{"env": "from-config"},
		ID:     222,
	})

	alerts, err := rule.Exec(context.Background(), time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Config label should win, original gets "exported_" prefix
	if alerts[0].Labels["env"] != "from-config" {
		t.Errorf("expected env=from-config, got %q", alerts[0].Labels["env"])
	}
	if alerts[0].Labels["exported_env"] != "from-query" {
		t.Errorf("expected exported_env=from-query, got %q", alerts[0].Labels["exported_env"])
	}
}

func TestAlertingRule_Limit(t *testing.T) {
	metrics := make([]datasource.Metric, 10)
	for i := range metrics {
		metrics[i] = datasource.Metric{
			Labels:     []datasource.Label{{Name: "id", Value: string(rune('a' + i))}},
			Values:     []float64{float64(i)},
			Timestamps: []int64{time.Now().Unix()},
		}
	}

	q := &fakeQuerier{
		results: datasource.Result{Data: metrics},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "g", time.Minute, config.Rule{
		Alert: "LimitTest",
		Expr:  "SELECT ...",
		ID:    333,
	})

	// Should fail with limit=5
	_, err := rule.Exec(context.Background(), time.Now(), 5)
	if err == nil {
		t.Fatal("expected limit exceeded error")
	}
	t.Logf("got expected error: %s", err)
}

func TestAlertingRule_KeepFiringFor(t *testing.T) {
	q := &fakeQuerier{
		results: datasource.Result{
			Data: []datasource.Metric{
				{
					Labels:     []datasource.Label{{Name: "x", Value: "1"}},
					Values:     []float64{1},
					Timestamps: []int64{time.Now().Unix()},
				},
			},
		},
	}
	qb := &fakeQuerierBuilder{q: q}

	rule := NewAlertingRule(qb, "g", time.Minute, config.Rule{
		Alert:         "KeepFireTest",
		Expr:          "SELECT '1' AS x, 1 AS value",
		KeepFiringFor: config.Duration{D: 5 * time.Minute},
		ID:            444,
	})

	now := time.Now()

	// Fire the alert
	_, err := rule.Exec(context.Background(), now, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Expression stops matching
	q.results = datasource.Result{Data: nil}

	// At now+1m: should still be firing (keep_firing_for=5m)
	alerts, err := rule.Exec(context.Background(), now.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}

	firing := false
	for _, a := range alerts {
		if a.State == StateFiring {
			firing = true
		}
	}
	if !firing {
		t.Error("expected alert to keep firing")
	}

	// At now+6m: should resolve
	alerts, err = rule.Exec(context.Background(), now.Add(6*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}

	stillFiring := false
	for _, a := range alerts {
		if a.State == StateFiring {
			stillFiring = true
		}
	}
	if stillFiring {
		t.Error("expected alert to stop firing after keep_firing_for elapsed")
	}
}
