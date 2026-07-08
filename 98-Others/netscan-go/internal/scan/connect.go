package scan

import (
	"context"
	"iter"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"netscan/internal/model"
)

// ConnectProber discovers open ports with full TCP connects. It needs no
// privileges, so it is the default backend and the correctness reference for
// the SYN prober.
type ConnectProber struct {
	Ports    []uint16
	Workers  int
	Timeout  time.Duration
	Limiter  *rate.Limiter // optional throttle; nil means unthrottled
	Progress *int64        // optional: incremented once per host actually probed
}

// Run fans addresses out to a worker pool; each worker probes every port of a
// host and emits a record if any port is open.
func (p *ConnectProber) Run(ctx context.Context, addrs iter.Seq[netip.Addr], out chan<- model.WireRecord) error {
	workers := p.Workers
	if workers < 1 {
		workers = 1
	}
	addrCh := make(chan netip.Addr, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range addrCh {
				open := p.scanHost(ctx, addr)
				if p.Progress != nil {
					atomic.AddInt64(p.Progress, 1)
				}
				if len(open) == 0 {
					continue
				}
				rec := model.WireRecord{IP: addr, OpenPorts: open, DiscoveredAt: time.Now().UTC()}
				select {
				case out <- rec:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for addr := range addrs {
		select {
		case addrCh <- addr:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(addrCh)
	wg.Wait()
	return ctx.Err()
}

func (p *ConnectProber) scanHost(ctx context.Context, addr netip.Addr) []uint16 {
	// Single-port fast path avoids goroutine overhead.
	if len(p.Ports) == 1 {
		if p.waitDial(ctx, addr, p.Ports[0]) {
			return []uint16{p.Ports[0]}
		}
		return nil
	}
	// Probe a host's ports concurrently so one slow/timing-out port doesn't
	// serialize the others; per-host latency becomes max(timeouts), not the sum.
	var (
		mu   sync.Mutex
		open []uint16
		wg   sync.WaitGroup
	)
	for _, port := range p.Ports {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			if p.waitDial(ctx, addr, port) {
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i] < open[j] })
	return open
}

// waitDial applies the rate limit then dials one port, reporting whether it is open.
func (p *ConnectProber) waitDial(ctx context.Context, addr netip.Addr, port uint16) bool {
	if p.Limiter != nil {
		if err := p.Limiter.Wait(ctx); err != nil {
			return false
		}
	}
	return p.dial(ctx, addr, port)
}

func (p *ConnectProber) dial(ctx context.Context, addr netip.Addr, port uint16) bool {
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, port).String())
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
