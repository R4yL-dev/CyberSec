package enrich

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"netscan/internal/model"
)

// Portscan is a deep per-host port sweep (domain B, connect-based, unprivileged).
// It scans a configurable port set and unions any newly-open ports into the
// host's OpenPorts; the pipeline then re-enters detect to classify/enrich them.
// It is the most aggressive palier (many connects per host) — opt-in via
// --all-ports, and bounded by a GLOBAL connection cap (sem, shared across every
// host in flight) plus a short per-connect Timeout. The global cap is the deep
// scan's equivalent of ns-discover's --rate: without it, concurrency is
// multiplicative (per-host fan-out × enrich workers) and floods NAT/conntrack.
type Portscan struct {
	Ports   []uint16
	Timeout time.Duration
	sem     chan struct{} // global concurrency cap, shared across all hosts
}

// NewPortscan builds the palier. conc is the global cap on simultaneous connect
// probes across all hosts (<=0 → 500). timeout is the per-connect deadline
// (<=0 → 2s).
func NewPortscan(ports []uint16, timeout time.Duration, conc int) *Portscan {
	if timeout <= 0 {
		timeout = 2 * time.Second // sane default for a port sweep
	}
	if conc < 1 {
		conc = 500 // sane global default (~ns-discover's --rate)
	}
	return &Portscan{Ports: ports, Timeout: timeout, sem: make(chan struct{}, conc)}
}

func (p *Portscan) Stage() string { return model.StagePortscan }

func (p *Portscan) Enrich(ctx context.Context, host *model.HostRecord) error {
	found := p.scan(ctx, host.IP)
	if len(found) > 0 {
		host.OpenPorts = model.UnionPorts(host.OpenPorts, found)
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StagePortscan] = "ok"
	return nil
}

// scan connect-probes p.Ports and returns the open ones. Concurrency is bounded
// by the shared p.sem, so the total in-flight connects stay capped no matter how
// many hosts sweep at once.
func (p *Portscan) scan(ctx context.Context, ip netip.Addr) []uint16 {
	var (
		mu   sync.Mutex
		open []uint16
		wg   sync.WaitGroup
	)
loop:
	for _, port := range p.Ports {
		// Acquire a global slot (or bail on cancel). Blocking here is the
		// throttle: when 500 connects are already in flight across all hosts,
		// this host waits its turn instead of piling on.
		select {
		case p.sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			defer func() { <-p.sem }()
			if p.dial(ctx, ip, port) {
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func (p *Portscan) dial(ctx context.Context, ip netip.Addr, port uint16) bool {
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
