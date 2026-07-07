// Package scan holds the discovery backends (domain A). A Prober consumes a
// stream of addresses, checks its configured ports, and emits one record per
// host that answers — it never touches the work queue.
package scan

import (
	"context"
	"iter"
	"net/netip"

	"netscan/internal/model"
)

// Prober is a discovery backend. Implementations: ConnectProber (full TCP
// connect, unprivileged) and, later, a stateless SYN prober.
type Prober interface {
	// Run consumes addresses from addrs, scans the prober's ports, and sends a
	// WireRecord for each host with at least one open port. It returns when
	// addrs is exhausted or ctx is cancelled.
	Run(ctx context.Context, addrs iter.Seq[netip.Addr], out chan<- model.WireRecord) error
}
