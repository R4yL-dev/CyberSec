package enrich

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"netscan/internal/model"
)

func TestPortscanFindsAndUnions(t *testing.T) {
	// Two listeners on distinct ports; a third port is left closed.
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()
	p1 := netip.MustParseAddrPort(ln1.Addr().String()).Port()
	p2 := netip.MustParseAddrPort(ln2.Addr().String()).Port()

	// closed port: grab one then release it
	lnc, _ := net.Listen("tcp", "127.0.0.1:0")
	pClosed := netip.MustParseAddrPort(lnc.Addr().String()).Port()
	lnc.Close()

	host := &model.HostRecord{
		IP:        netip.MustParseAddr("127.0.0.1"),
		OpenPorts: []uint16{p1}, // discovery already knew p1
	}
	ps := NewPortscan([]uint16{p1, p2, pClosed}, 500*time.Millisecond, 0)
	if err := ps.Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	got := map[uint16]bool{}
	for _, p := range host.OpenPorts {
		got[p] = true
	}
	if !got[p1] || !got[p2] {
		t.Fatalf("open ports = %v, want both %d and %d", host.OpenPorts, p1, p2)
	}
	if got[pClosed] {
		t.Fatalf("closed port %d should not be found: %v", pClosed, host.OpenPorts)
	}
	if host.Status[model.StagePortscan] != "ok" {
		t.Fatalf("status = %v", host.Status)
	}
}
