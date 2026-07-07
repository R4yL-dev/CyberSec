package target

import (
	"net/netip"
	"testing"
)

func collect(t *testing.T, targets, excludes []string, skipReserved bool) []netip.Addr {
	t.Helper()
	s, err := NewSpace(targets, excludes, skipReserved)
	if err != nil {
		t.Fatalf("NewSpace(%v): %v", targets, err)
	}
	var out []netip.Addr
	for addr := range s.Ordered() {
		out = append(out, addr)
	}
	return out
}

func TestReservedRangeExcluded(t *testing.T) {
	// A fully private /24, with reserved-skipping on, yields nothing.
	if got := len(collect(t, []string{"10.0.0.0/24"}, nil, true)); got != 0 {
		t.Fatalf("10.0.0.0/24 skip=on: got %d addresses, want 0", got)
	}
}

func TestNoSkipReservedIncludesAll(t *testing.T) {
	// With skipping off, every address of the block is produced (all 256,
	// network and broadcast included — masscan-style whole-range scanning).
	if got := len(collect(t, []string{"10.0.0.0/24"}, nil, false)); got != 256 {
		t.Fatalf("10.0.0.0/24 skip=off: got %d addresses, want 256", got)
	}
}

func TestPublicRangeKept(t *testing.T) {
	// 1.1.1.0/30 is genuinely public (not in any reserved block).
	got := collect(t, []string{"1.1.1.0/30"}, nil, true)
	want := []netip.Addr{
		netip.MustParseAddr("1.1.1.0"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
	}
	if len(got) != len(want) {
		t.Fatalf("1.1.1.0/30: got %d addresses, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addr[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestUserExclude(t *testing.T) {
	// Excluding the lower half of a public /30 leaves the upper two addresses.
	got := collect(t, []string{"1.1.1.0/30"}, []string{"1.1.1.0/31"}, true)
	want := []netip.Addr{
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
	}
	if len(got) != len(want) {
		t.Fatalf("exclude 1.1.1.0/31: got %d addresses, want 2", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addr[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestMultipleBlocks(t *testing.T) {
	got := collect(t, []string{"1.1.1.0/31", "8.8.8.0/31"}, nil, true)
	want := []netip.Addr{
		netip.MustParseAddr("1.1.1.0"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.0"),
		netip.MustParseAddr("8.8.8.1"),
	}
	if len(got) != len(want) {
		t.Fatalf("two /31 blocks: got %d, want 4", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addr[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestRandomizedIsBijection(t *testing.T) {
	// Over a /16 the randomized order must produce every address exactly once.
	s, err := NewSpace([]string{"1.2.0.0/16"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[netip.Addr]bool, 1<<16)
	n := 0
	sequential := true
	for addr := range s.Randomized(0xC0FFEE) {
		if seen[addr] {
			t.Fatalf("duplicate address %v", addr)
		}
		seen[addr] = true
		if addr != s.AddrAt(uint64(n)) {
			sequential = false
		}
		n++
	}
	if n != 1<<16 {
		t.Fatalf("randomized count = %d, want %d", n, 1<<16)
	}
	if sequential {
		t.Fatal("randomized order was sequential; permutation not shuffling")
	}
}

func TestPermutationSmallTotals(t *testing.T) {
	// Non-power-of-two and tiny totals (e.g. a /32 has total 1) must still map
	// every position to a distinct index within [0, total).
	for _, total := range []uint64{1, 2, 3, 5, 7, 100, 257} {
		p := NewPermutation(total, 0xABCD)
		seen := make(map[uint64]bool, total)
		for pos := uint64(0); pos < total; pos++ {
			got := p.Shuffle(pos)
			if got >= total {
				t.Fatalf("total=%d: Shuffle(%d)=%d out of range", total, pos, got)
			}
			if seen[got] {
				t.Fatalf("total=%d: Shuffle produced duplicate %d", total, got)
			}
			seen[got] = true
		}
	}
}

func TestSingleHostRange(t *testing.T) {
	// A /32 must yield exactly its one address in randomized order.
	s, err := NewSpace([]string{"8.8.8.8/32"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []netip.Addr
	for addr := range s.Randomized(1) {
		got = append(got, addr)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("/32 randomized = %v, want [8.8.8.8]", got)
	}
}

func TestSeedReproducible(t *testing.T) {
	s, err := NewSpace([]string{"1.2.0.0/20"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var first, second []netip.Addr
	for addr := range s.Randomized(42) {
		first = append(first, addr)
	}
	for addr := range s.Randomized(42) {
		second = append(second, addr)
	}
	if len(first) != len(second) {
		t.Fatalf("length mismatch: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("seed not reproducible at %d: %v vs %v", i, first[i], second[i])
		}
	}
}

func TestIPv6Rejected(t *testing.T) {
	if _, err := NewSpace([]string{"2001:db8::/32"}, nil, true); err == nil {
		t.Fatal("expected IPv6 target to be rejected")
	}
}
