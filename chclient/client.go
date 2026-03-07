// Package chclient provides the ClickHouse connection pool and query execution layer.
//
// # Design Decisions
//
//   - Uses the official clickhouse-go v2 driver with native protocol (not HTTP).
//     The native protocol is more efficient for the kind of queries we run (aggregations
//     returning moderate result sets).
//
//   - Supports separate read and write connections. Alert evaluation queries should hit
//     a read replica to avoid competing with ingestion. State writes (alert_state,
//     alert_history) are low volume and go to the primary.
//
//   - Connection-level settings (max_execution_time, max_memory_usage) are configured
//     per-pool to prevent runaway alert queries from impacting the cluster.
//
// # Assumptions
//
//   - ClickHouse is accessible via native protocol (default port 9000/9440 for TLS).
//   - Read replicas (if used) are eventually consistent — this is fine for alert evaluation
//     since we already account for ingestion delay via eval_delay.
//   - Connection strings follow the clickhouse-go DSN format:
//     clickhouse://user:pass@host:9000/database?dial_timeout=5s&max_execution_time=30
package chclient

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Config holds ClickHouse connection configuration.
type Config struct {
	// DSN is the primary ClickHouse connection string used for writes and
	// default reads. Required.
	DSN string

	// ReadDSN is an optional separate connection string for alert evaluation
	// queries. If empty, DSN is used for reads too. Point this at a read
	// replica to isolate alert query load from ingestion.
	ReadDSN string

	// MaxQueryTime limits the maximum execution time for any single alert
	// evaluation query. Prevents runaway queries from consuming cluster
	// resources. Default: 30s.
	MaxQueryTime time.Duration

	// MaxOpenConns limits the number of open connections in each pool.
	// Default: 10.
	MaxOpenConns int

	// MaxRowsToRead limits rows ClickHouse may read per query (server-side
	// max_rows_to_read setting). Guards against full table scans from poorly
	// written alert expressions. 0 means unlimited.
	MaxRowsToRead int64

	// MaxThreads limits threads per query on the ClickHouse side (server-side
	// max_threads setting). 0 means use ClickHouse default.
	MaxThreads int
}

// Client provides ClickHouse connectivity with separate read/write pools.
type Client struct {
	write driver.Conn
	read  driver.Conn

	maxQueryTime time.Duration
}

func New(cfg Config) (*Client, error) {
	if cfg.MaxQueryTime == 0 {
		cfg.MaxQueryTime = 30 * time.Second
	}
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 10
	}

	// Build guard rail settings for the read connection.
	// These are applied at the ClickHouse connection level so every alert
	// evaluation query inherits them automatically.
	readSettings := make(clickhouse.Settings)
	if secs := int(cfg.MaxQueryTime.Seconds()); secs > 0 {
		readSettings["max_execution_time"] = secs
	}
	if cfg.MaxRowsToRead > 0 {
		readSettings["max_rows_to_read"] = cfg.MaxRowsToRead
	}
	if cfg.MaxThreads > 0 {
		readSettings["max_threads"] = cfg.MaxThreads
	}

	writeConn, err := openConn(cfg.DSN, cfg.MaxOpenConns, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open write connection: %w", err)
	}

	readConn := writeConn
	if cfg.ReadDSN != "" {
		readConn, err = openConn(cfg.ReadDSN, cfg.MaxOpenConns, readSettings)
		if err != nil {
			writeConn.Close()
			return nil, fmt.Errorf("failed to open read connection: %w", err)
		}
	} else if len(readSettings) > 0 {
		// Same DSN but with guard rail settings for reads.
		readConn, err = openConn(cfg.DSN, cfg.MaxOpenConns, readSettings)
		if err != nil {
			writeConn.Close()
			return nil, fmt.Errorf("failed to open read connection: %w", err)
		}
	}

	return &Client{
		write:        writeConn,
		read:         readConn,
		maxQueryTime: cfg.MaxQueryTime,
	}, nil
}

func openConn(dsn string, maxOpen int, settings clickhouse.Settings) (driver.Conn, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid DSN: %w", err)
	}
	opts.MaxOpenConns = maxOpen
	if len(settings) > 0 {
		if opts.Settings == nil {
			opts.Settings = make(clickhouse.Settings)
		}
		for k, v := range settings {
			opts.Settings[k] = v
		}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping failed: %w", err)
	}
	return conn, nil
}

// ReadConn returns the read connection (may be same as write if no read replica configured).
func (c *Client) ReadConn() driver.Conn {
	return c.read
}

// WriteConn returns the write connection.
func (c *Client) WriteConn() driver.Conn {
	return c.write
}

// MaxQueryTime returns the configured max query execution time.
func (c *Client) MaxQueryTime() time.Duration {
	return c.maxQueryTime
}

// Close closes both connection pools.
func (c *Client) Close() error {
	var errs []error
	if err := c.write.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing write conn: %w", err))
	}
	if c.read != c.write {
		if err := c.read.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing read conn: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}
