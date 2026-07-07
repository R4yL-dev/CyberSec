// Package store is the domain-B backbone: a per-host state store plus a work
// queue that lets any palier schedule work for any stage (forward or backward),
// with leases, retries/backoff and dead-lettering. The Store interface keeps
// the workers ignorant of the backend so SQLite can later be swapped for
// Postgres.
package store

import (
	"context"
	"net/netip"
	"time"

	"netscan/internal/model"
)

// Work item states.
const (
	StatePending = "pending"
	StateLeased  = "leased"
	StateDone    = "done"
	StateFailed  = "failed" // dead-lettered
)

// WorkItem is a claimed unit of work for one host at one stage.
type WorkItem struct {
	ID       int64
	IP       netip.Addr
	Stage    string
	Attempts int
}

// RunStat is a heartbeat/progress record for a running binary instance.
type RunStat struct {
	Tool      string
	PID       int
	Counter   int64
	Note      string
	UpdatedAt time.Time
}

// HostSummary is a compact host view for ns-status.
type HostSummary struct {
	IP        netip.Addr
	OpenPorts []uint16
	LastSeen  time.Time
}

// Stats is a snapshot for ns-status.
type Stats struct {
	Hosts          int64
	WorkByState    map[string]int64
	PendingByStage map[string]int64
	Runs           []RunStat
	RecentHosts    []HostSummary
}

// Store is the persistence + queue contract. A single SQLite implementation is
// provided today; the interface is the seam for a future Postgres backend.
type Store interface {
	// Ingest upserts a discovered host and ensures a pending work item exists
	// for stage (idempotent — no duplicate pending items).
	Ingest(ctx context.Context, rec model.WireRecord, stage string) error

	// Claim leases up to n claimable items for stage (pending, or leased with an
	// expired lease), bumping their attempt count.
	Claim(ctx context.Context, stage string, n int, lease time.Duration) ([]WorkItem, error)

	// Host loads the durable record for ip (nil if unknown).
	Host(ctx context.Context, ip netip.Addr) (*model.HostRecord, error)

	// Complete persists the host's accumulated enrichment and marks the item done.
	Complete(ctx context.Context, id int64, host *model.HostRecord) error

	// Fail reschedules the item with exponential backoff, or dead-letters it once
	// its attempts reach maxAttempts.
	Fail(ctx context.Context, id int64, maxAttempts int, base time.Duration) error

	// Reschedule enqueues a pending item for ip at stage — the "backward"
	// primitive (idempotent).
	Reschedule(ctx context.Context, ip netip.Addr, stage string) error

	// Heartbeat records liveness/progress for a binary instance.
	Heartbeat(ctx context.Context, r RunStat) error

	// Stats returns a snapshot for monitoring.
	Stats(ctx context.Context) (Stats, error)

	Close() error
}
