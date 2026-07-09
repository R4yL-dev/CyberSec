package scan

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"netscan/internal/model"
)

func TestConnectProber(t *testing.T) {
	// Two open ports on loopback, plus a closed one.
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()
	p1 := netip.MustParseAddrPort(ln1.Addr().String()).Port()
	p2 := netip.MustParseAddrPort(ln2.Addr().String()).Port()

	lnc, _ := net.Listen("tcp", "127.0.0.1:0")
	pClosed := netip.MustParseAddrPort(lnc.Addr().String()).Port()
	lnc.Close()

	prober := &ConnectProber{Ports: []uint16{p1, p2, pClosed}, Workers: 8, Timeout: time.Second}

	addrs := func(yield func(netip.Addr) bool) { yield(netip.MustParseAddr("127.0.0.1")) }
	out := make(chan model.WireRecord, 1)
	done := make(chan struct{})
	var recs []model.WireRecord
	go func() {
		for r := range out {
			recs = append(recs, r)
		}
		close(done)
	}()
	if err := prober.Run(context.Background(), addrs, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	<-done

	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	op := recs[0].OpenPorts
	if !slices.Contains(op, p1) || !slices.Contains(op, p2) {
		t.Fatalf("open ports = %v, want %d and %d", op, p1, p2)
	}
	if slices.Contains(op, pClosed) {
		t.Fatalf("closed port %d reported open: %v", pClosed, op)
	}
}
