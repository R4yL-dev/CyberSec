package scan

import (
	"net/netip"
	"testing"
	"time"
)

// TestICMPCookie: the stateless validation cookie must be deterministic per
// prober (so an echo reply's echoed seq can be re-derived and matched) and vary
// across targets (so a stray reply for another host isn't accepted).
func TestICMPCookie(t *testing.T) {
	p := NewICMPProber(1, time.Second, nil)

	a := netip.MustParseAddr("1.2.3.4")
	b := netip.MustParseAddr("1.2.3.5")

	if p.cookie(a) != p.cookie(a) {
		t.Fatal("cookie is not deterministic for the same address")
	}
	if p.cookie(a) == p.cookie(b) {
		t.Fatal("cookie collides across adjacent addresses")
	}
	// A different prober (different secret) should not share cookies.
	if q := NewICMPProber(1, time.Second, nil); q.secret != p.secret && q.cookie(a) == p.cookie(a) {
		t.Fatal("cookie does not depend on the per-run secret")
	}
	if p.id == 0 {
		t.Fatal("ICMP id must be non-zero (scopes our probes)")
	}
}
