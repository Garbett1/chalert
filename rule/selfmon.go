package rule

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/garbett1/chalert/config"
	"github.com/garbett1/chalert/datasource"
)

// SelfMonGroupName is the name of the inbuilt self-monitoring group.
const SelfMonGroupName = "chalert.self"

// SelfMonAlertName is the name of the inbuilt self-monitoring alert.
const SelfMonAlertName = "ChalertRuleEvaluationFailing"

// SelfMonQuerier produces a synthetic alert metric when chalert is unable to
// successfully evaluate any of its configured rules. It does not query
// ClickHouse — it inspects the in-memory eval state of the registered user
// groups directly.
//
// The fire condition is intentionally strict: at least one rule must have
// completed an evaluation, and every rule that has completed an evaluation
// must have returned an error on its most recent attempt. Rules that have
// never run (e.g. just-loaded after a reload) are ignored so that a fresh
// boot doesn't immediately trip the alert before any user rule has had a
// chance to evaluate.
type SelfMonQuerier struct {
	mu     sync.RWMutex
	groups []*Group
}

// SetGroups registers the user groups whose evaluation health should be
// monitored. Pass only user groups — never include the self-monitoring
// group itself, or its successful evals will mask user-rule failures.
func (s *SelfMonQuerier) SetGroups(groups []*Group) {
	s.mu.Lock()
	s.groups = groups
	s.mu.Unlock()
}

// Query returns a single synthetic Metric when the fire condition holds,
// otherwise an empty result. The metric's value is the count of failing rules.
func (s *SelfMonQuerier) Query(_ context.Context, _ string, _ time.Time) (datasource.Result, error) {
	s.mu.RLock()
	groups := s.groups
	s.mu.RUnlock()

	var evaluated, failing int
	for _, g := range groups {
		g.mu.RLock()
		rules := g.Rules
		g.mu.RUnlock()
		for _, r := range rules {
			r.mu.RLock()
			ran := !r.lastEval.IsZero()
			err := r.lastErr
			r.mu.RUnlock()
			if !ran {
				continue
			}
			evaluated++
			if err != nil {
				failing++
			}
		}
	}

	if evaluated == 0 || failing < evaluated {
		return datasource.Result{}, nil
	}

	return datasource.Result{
		Data: []datasource.Metric{
			{
				Values: []float64{float64(failing)},
			},
		},
	}, nil
}

// QueryRange is unsupported for the self-monitoring querier.
func (s *SelfMonQuerier) QueryRange(_ context.Context, _ string, _, _ time.Time) (datasource.Result, error) {
	return datasource.Result{}, fmt.Errorf("range queries not supported by self-monitoring querier")
}

type selfMonBuilder struct{ q *SelfMonQuerier }

func (b *selfMonBuilder) BuildWithParams(_ datasource.QuerierParams) datasource.Querier {
	return b.q
}

// BuildSelfMonGroup constructs the inbuilt self-monitoring group.
//
// The returned Group contains a single AlertingRule that fires when the
// SelfMonQuerier's condition holds. The caller is responsible for calling
// SetGroups on the querier with the user groups, starting the group, and
// refreshing the querier registration whenever the user group set changes
// (e.g. on SIGHUP reload).
func BuildSelfMonGroup(interval time.Duration, externalLabels map[string]string) (*Group, *SelfMonQuerier) {
	if interval <= 0 {
		interval = time.Minute
	}

	q := &SelfMonQuerier{}
	qb := &selfMonBuilder{q: q}

	labels := map[string]string{"severity": "critical"}
	for k, v := range externalLabels {
		if _, ok := labels[k]; !ok {
			labels[k] = v
		}
	}

	cfg := config.Rule{
		Alert: SelfMonAlertName,
		Expr:  "<chalert self-monitoring>",
		For:   config.Duration{D: 5 * time.Minute},
		Labels: labels,
		Annotations: map[string]string{
			"summary":     "chalert is failing to evaluate any alert rules",
			"description": "All {{ $value }} configured chalert rules have failed their most recent evaluation. The alerting pipeline is effectively offline — investigate ClickHouse connectivity or rule expressions.",
		},
	}
	cfg.ID = config.HashRule(cfg)

	ar := NewAlertingRule(qb, SelfMonGroupName, interval, cfg)

	g := &Group{
		Name:        SelfMonGroupName,
		File:        "(builtin)",
		Rules:       []*AlertingRule{ar},
		Interval:    interval,
		Concurrency: 1,
		Labels:      nil,
		doneCh:      make(chan struct{}),
		finishedCh:  make(chan struct{}),
		updateCh:    make(chan *Group),
	}
	h := fnv.New64a()
	h.Write([]byte(g.File))
	h.Write([]byte("\xff"))
	h.Write([]byte(g.Name))
	h.Write([]byte(g.Interval.String()))
	g.id = h.Sum64()

	return g, q
}
