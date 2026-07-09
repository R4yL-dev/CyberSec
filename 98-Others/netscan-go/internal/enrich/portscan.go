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
// It is the most aggressive palier (many connects per host) — opt-in via a
// config profile, and bounded here by Concurrency + a short Timeout.
type Portscan struct {
	Ports       []uint16
	Timeout     time.Duration
	Concurrency int
}

func NewPortscan(ports []uint16, timeout time.Duration) *Portscan {
	if timeout <= 0 {
		timeout = 2 * time.Second // sane default for a port sweep
	}
	return &Portscan{Ports: ports, Timeout: timeout, Concurrency: 200}
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

// scan connect-probes p.Ports with bounded concurrency and returns the open ones.
func (p *Portscan) scan(ctx context.Context, ip netip.Addr) []uint16 {
	conc := p.Concurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var (
		mu   sync.Mutex
		open []uint16
		wg   sync.WaitGroup
	)
	for _, port := range p.Ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port uint16) {
			defer wg.Done()
			defer func() { <-sem }()
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
