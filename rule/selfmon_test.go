package rule

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/garbett1/chalert/config"
	"github.com/garbett1/chalert/datasource"
)

// errQuerier always returns an error from Query.
type errQuerier struct{ err error }

func (e *errQuerier) Query(_ context.Context, _ string, _ time.Time) (datasource.Result, error) {
	return datasource.Result{}, e.err
}

func (e *errQuerier) QueryRange(_ context.Context, _ string, _, _ time.Time) (datasource.Result, error) {
	return datasource.Result{}, e.err
}

type errQuerierBuilder struct{ q datasource.Querier }

func (b *errQuerierBuilder) BuildWithParams(_ datasource.QuerierParams) datasource.Querier {
	return b.q
}

// makeGroupWithRules constructs a *Group containing the given pre-built rules
// without going through NewGroup (which expects a config.Group).
func makeGroupWithRules(name string, rules ...*AlertingRule) *Group {
	return &Group{
		Name:     name,
		File:     "(test)",
		Rules:    rules,
		Interval: time.Minute,
	}
}

func TestSelfMonQuerier_NoEvalsYet(t *testing.T) {
	q := &SelfMonQuerier{}
	r := NewAlertingRule(&errQuerierBuilder{q: &errQuerier{err: errors.New("boom")}}, "g", time.Minute, config.Rule{
		Alert: "X", Expr: "SELECT 1 AS value", ID: 1,
	})
	q.SetGroups([]*Group{makeGroupWithRules("g", r)})

	res, err := q.Query(context.Background(), "", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Data) != 0 {
		t.Fatalf("expected no synthetic metric before any rule has run, got %d", len(res.Data))
	}
}

func TestSelfMonQuerier_AllFailing(t *testing.T) {
	eq := &errQuerier{err: errors.New("clickhouse unreachable")}
	qb := &errQuerierBuilder{q: eq}

	r1 := NewAlertingRule(qb, "g", time.Minute, config.Rule{Alert: "A", Expr: "SELECT 1 AS value", ID: 1})
	r2 := NewAlertingRule(qb, "g", time.Minute, config.Rule{Alert: "B", Expr: "SELECT 1 AS value", ID: 2})

	if _, err := r1.Exec(context.Background(), time.Now(), 0); err == nil {
		t.Fatal("expected rule eval to fail")
	}
	if _, err := r2.Exec(context.Background(), time.Now(), 0); err == nil {
		t.Fatal("expected rule eval to fail")
	}

	q := &SelfMonQuerier{}
	q.SetGroups([]*Group{makeGroupWithRules("g", r1, r2)})

	res, err := q.Query(context.Background(), "", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Data) != 1 {
		t.Fatalf("expected synthetic metric when all rules fail, got %d", len(res.Data))
	}
	if got := res.Data[0].Values[0]; got != 2 {
		t.Errorf("expected value=2 (failing rule count), got %v", got)
	}
}

func TestSelfMonQuerier_SomeSucceeding(t *testing.T) {
	failing := NewAlertingRule(&errQuerierBuilder{q: &errQuerier{err: errors.New("boom")}}, "g", time.Minute, config.Rule{
		Alert: "Failing", Expr: "SELECT 1 AS value", ID: 10,
	})
	succeeding := NewAlertingRule(&fakeQuerierBuilder{q: &fakeQuerier{}}, "g", time.Minute, config.Rule{
		Alert: "OK", Expr: "SELECT 1 AS value", ID: 11,
	})

	if _, err := failing.Exec(context.Background(), time.Now(), 0); err == nil {
		t.Fatal("expected failing rule to error")
	}
	if _, err := succeeding.Exec(context.Background(), time.Now(), 0); err != nil {
		t.Fatalf("succeeding rule errored unexpectedly: %v", err)
	}

	q := &SelfMonQuerier{}
	q.SetGroups([]*Group{makeGroupWithRules("g", failing, succeeding)})

	res, err := q.Query(context.Background(), "", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Data) != 0 {
		t.Fatalf("expected no synthetic metric when at least one rule succeeds, got %d", len(res.Data))
	}
}

func TestBuildSelfMonGroup_FiresAfterFor(t *testing.T) {
	eq := &errQuerier{err: errors.New("ch down")}
	failing := NewAlertingRule(&errQuerierBuilder{q: eq}, "user-group", time.Minute, config.Rule{
		Alert: "UserAlert", Expr: "SELECT 1 AS value", ID: 42,
	})
	if _, err := failing.Exec(context.Background(), time.Now(), 0); err == nil {
		t.Fatal("expected failing rule to error")
	}

	smGroup, smQ := BuildSelfMonGroup(time.Minute, nil)
	smQ.SetGroups([]*Group{makeGroupWithRules("user-group", failing)})

	if len(smGroup.Rules) != 1 {
		t.Fatalf("expected 1 inbuilt rule, got %d", len(smGroup.Rules))
	}
	smRule := smGroup.Rules[0]
	if smRule.Name() != SelfMonAlertName {
		t.Errorf("unexpected inbuilt alert name: %q", smRule.Name())
	}

	now := time.Now()

	// First eval: should create a Pending alert (the for=5m gate has not elapsed).
	alerts, err := smRule.Exec(context.Background(), now, 0)
	if err != nil {
		t.Fatalf("self-mon Exec failed: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts to send while pending, got %d", len(alerts))
	}
	active := smRule.GetAlerts()
	if len(active) != 1 || active[0].State != StatePending {
		t.Fatalf("expected one pending alert, got %+v", active)
	}

	// Advance past the for=5m window — should transition to firing.
	alerts, err = smRule.Exec(context.Background(), now.Add(6*time.Minute), 0)
	if err != nil {
		t.Fatalf("self-mon Exec failed: %v", err)
	}
	if len(alerts) != 1 || alerts[0].State != StateFiring {
		t.Fatalf("expected one firing alert after for window, got %+v", alerts)
	}
	if alerts[0].Labels["alertname"] != SelfMonAlertName {
		t.Errorf("unexpected alertname: %q", alerts[0].Labels["alertname"])
	}
	if alerts[0].Labels["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %q", alerts[0].Labels["severity"])
	}
}
