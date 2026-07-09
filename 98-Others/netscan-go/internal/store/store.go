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

// Coordination keys/values for the meta table. ns-ingest publishes its state so
// a following ns-enrich knows when no more work is coming; ns-discover stamps the
// scan start so ns-status can show elapsed time.
const (
	MetaIngestState = "ingest.state"
	IngestRunning   = "running"
	IngestDone      = "done"

	MetaScanStarted = "scan.started" // Unix millis, written once by ns-discover
)

// WorkItem is a claimed unit of work for one host at one stage.
type WorkItem struct {
	ID       int64
	IP       netip.Addr
	Stage    string
	Attempts int
}

// RunStat is a heartbeat/progress record for a running binary instance.
// Counter is the primary progress number (addresses scanned, hosts ingested,
// items enriched); Total is its denominator when known (0 = unknown).
type RunStat struct {
	Tool      string
	PID       int
	Counter   int64
	Total     int64
	Note      string
	UpdatedAt time.Time
}

// HostSummary is a compact host view for ns-status.
type HostSummary struct {
	IP        netip.Addr
	OpenPorts []uint16
	LastSeen  time.Time
}

// PortCount is a port and the number of hosts exposing it.
type PortCount struct {
	Port  uint16
	Count int64
}

// LabelCount is a generic label with a count (protocol, country, …).
type LabelCount struct {
	Label string
	Count int64
}

// Summary is a monitoring snapshot for ns-status: queue progress plus an
// aggregated view of what the scan has found so far.
type Summary struct {
	Hosts       int64
	WorkByState map[string]int64            // pending / leased / done / failed
	QueueByStage map[string]map[string]int64 // stage -> state -> count
	StageCoverage map[string]int64           // stage -> hosts that completed it
	Runs        []RunStat
	RecentHosts []HostSummary

	// Findings — aggregated from the hosts' enrichment JSON.
	TopPorts       []PortCount
	Protocols      []LabelCount
	Countries      []LabelCount
	WebServers     int64 // ports carrying an HTTP response
	TLSPorts       int64 // ports carrying a TLS cert
	TLSExpired     int64 // hosts with an expired cert in a chain
	TLSWeak        int64 // hosts with weak-crypto TLS warnings
	SensitivePaths int64 // sensitive paths found by the crawl palier
}

// Store is the persistence + queue contract. A single SQLite implementation is
// provided today; the interface is the seam for a future Postgres backend.
type Store interface {
	// Ingest upserts a discovered host and ensures a pending work item exists
	// for stage (idempotent — no duplicate pending items). geo (may be nil) is
	// IP-level context written on first insert only.
	Ingest(ctx context.Context, rec model.WireRecord, stage string, geo *model.GeoInfo) error

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

	// SetMeta / GetMeta store small key/value coordination state (e.g. whether
	// ingestion is still running). GetMeta returns "" for a missing key.
	SetMeta(ctx context.Context, key, value string) error
	GetMeta(ctx context.Context, key string) (string, error)

	// Summary returns a monitoring snapshot (queue progress + findings).
	Summary(ctx context.Context) (Summary, error)

	Close() error
}
