package scan

import (
	"context"
	"iter"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"netscan/internal/model"
)

// ConnectProber discovers open ports with full TCP connects. It needs no
// privileges, so it is the default backend and the correctness reference for
// the SYN prober.
type ConnectProber struct {
	Ports   []uint16
	Workers int
	Timeout time.Duration
	Limiter *rate.Limiter // optional throttle; nil means unthrottled
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
	var open []uint16
	for _, port := range p.Ports {
		if p.Limiter != nil {
			if err := p.Limiter.Wait(ctx); err != nil {
				return open
			}
		}
		if p.dial(ctx, addr, port) {
			open = append(open, port)
		}
	}
	return open
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
