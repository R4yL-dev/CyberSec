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

func TestWithinAllowlist(t *testing.T) {
	// Space over the whole /24, clipped to a /26 → only .0-.63 may be scanned.
	s, err := NewSpace([]string{"1.2.3.0/24"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetWithin([]string{"1.2.3.0/26"}); err != nil {
		t.Fatal(err)
	}
	if !s.Allowed(netip.MustParseAddr("1.2.3.10")) {
		t.Fatal("in-scope .10 must be allowed")
	}
	if s.Allowed(netip.MustParseAddr("1.2.3.100")) {
		t.Fatal("out-of-scope .100 must be blocked by within")
	}
	// Iteration must never emit an address outside the /26.
	var pos uint64
	n := 0
	for addr := range s.RandomizedFrom(1, 0, &pos) {
		if !netip.MustParsePrefix("1.2.3.0/26").Contains(addr) {
			t.Fatalf("emitted out-of-scope address %s", addr)
		}
		n++
	}
	if n != 64 {
		t.Fatalf("emitted %d addresses, want 64 (the /26)", n)
	}
	// Empty within = no restriction.
	if err := s.SetWithin(nil); err != nil {
		t.Fatal(err)
	}
	if !s.Allowed(netip.MustParseAddr("1.2.3.100")) {
		t.Fatal("cleared within must allow the whole space again")
	}
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

func TestRandomizedFromResumes(t *testing.T) {
	// With reserved-skipping off, position == yielded index, so RandomizedFrom
	// at position k must equal the tail of Randomized from k onward.
	s, err := NewSpace([]string{"1.2.0.0/24"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var full []netip.Addr
	for a := range s.Randomized(7) {
		full = append(full, a)
	}
	const k = 100
	var tail []netip.Addr
	var pos uint64
	for a := range s.RandomizedFrom(7, k, &pos) {
		tail = append(tail, a)
	}
	if len(tail) != len(full)-k {
		t.Fatalf("tail length %d, want %d", len(tail), len(full)-k)
	}
	for i := range tail {
		if tail[i] != full[k+i] {
			t.Fatalf("resume mismatch at %d: %v vs %v", i, tail[i], full[k+i])
		}
	}
	if pos != s.Total()-1 {
		t.Fatalf("final pos = %d, want %d", pos, s.Total()-1)
	}
}

func TestSignatureStableAndDistinct(t *testing.T) {
	mk := func(targets, excl []string, skip bool) string {
		s, err := NewSpace(targets, excl, skip)
		if err != nil {
			t.Fatal(err)
		}
		return s.Signature()
	}
	base := mk([]string{"1.2.0.0/24"}, nil, true)
	if base != mk([]string{"1.2.0.0/24"}, nil, true) {
		t.Fatal("signature not stable across identical spaces")
	}
	if base == mk([]string{"1.3.0.0/24"}, nil, true) {
		t.Fatal("different targets produced the same signature")
	}
	if base == mk([]string{"1.2.0.0/24"}, []string{"1.2.0.0/28"}, true) {
		t.Fatal("different excludes produced the same signature")
	}
	if base == mk([]string{"1.2.0.0/24"}, nil, false) {
		t.Fatal("different skip-reserved produced the same signature")
	}
}

func TestIPv6Rejected(t *testing.T) {
	if _, err := NewSpace([]string{"2001:db8::/32"}, nil, true); err == nil {
		t.Fatal("expected IPv6 target to be rejected")
	}
}
