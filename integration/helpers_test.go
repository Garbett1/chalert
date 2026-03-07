//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// capturedAlert matches the Alertmanager webhook payload format.
type capturedAlert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

// webhookCapture records all alerts posted by Alertmanager.
type webhookCapture struct {
	mu     sync.Mutex
	alerts []capturedAlert
}

// alertmanagerWebhookPayload matches the AlertManager webhook receiver format.
// See: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
type alertmanagerWebhookPayload struct {
	Alerts []capturedAlert `json:"alerts"`
}

func (w *webhookCapture) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload alertmanagerWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	w.mu.Lock()
	w.alerts = append(w.alerts, payload.Alerts...)
	w.mu.Unlock()
	rw.WriteHeader(http.StatusOK)
}

func (w *webhookCapture) getAlerts() []capturedAlert {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]capturedAlert, len(w.alerts))
	copy(out, w.alerts)
	return out
}

func (w *webhookCapture) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alerts = nil
}

// waitFor polls condition until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, interval time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, desc)
		}
		time.Sleep(interval)
	}
}

// insertHTTPRequests inserts rows into the http_requests table.
func insertHTTPRequests(ctx context.Context, conn driver.Conn, service string, status uint16, count int) error {
	batch, err := conn.PrepareBatch(ctx, "INSERT INTO http_requests (timestamp, service, endpoint, status, duration_ms)")
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}
	now := time.Now()
	for i := 0; i < count; i++ {
		if err := batch.Append(now, service, "/api", status, 100.0); err != nil {
			return fmt.Errorf("append: %w", err)
		}
	}
	return batch.Send()
}

// createHTTPRequestsTable creates the test table in ClickHouse.
func createHTTPRequestsTable(ctx context.Context, conn driver.Conn) error {
	return conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS http_requests (
			timestamp   DateTime DEFAULT now(),
			service     LowCardinality(String),
			endpoint    String,
			status      UInt16,
			duration_ms Float64
		) ENGINE = MergeTree()
		ORDER BY (service, timestamp)
	`)
}
