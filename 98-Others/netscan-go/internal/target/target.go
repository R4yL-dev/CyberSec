// Package target turns a set of CIDR blocks into an ordered, indexable IPv4
// address space, filters out reserved and user-excluded ranges, and hands out
// addresses in a stateless pseudo-random order (see permute.go). Only IPv4 is
// supported in v1.
package target

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"iter"
	"net/netip"
	"sort"
	"sync/atomic"
)

// reservedCIDRs must never be scanned (RFC 5735/6890): "this network",
// private, CGNAT, loopback, link-local, IETF protocol assignments,
// documentation, benchmarking, multicast and the reserved/broadcast block.
// 240.0.0.0/4 also covers 255.255.255.255.
var reservedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

var reservedPrefixes = mustPrefixes(reservedCIDRs)

func mustPrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// Space is an ordered union of IPv4 CIDR blocks, addressable by index, with
// reserved and excluded ranges filtered at emission time.
type Space struct {
	prefixes     []netip.Prefix
	cum          []uint64 // cum[k] = addresses before prefix k; cum[len] = total
	total        uint64
	excludes     []netip.Prefix
	within       []netip.Prefix // optional allowlist: if set, only these are scanned
	skipReserved bool
}

// NewSpace builds a Space from target CIDRs and exclude CIDRs (all IPv4).
func NewSpace(targets, excludes []string, skipReserved bool) (*Space, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no target provided")
	}
	s := &Space{skipReserved: skipReserved, cum: []uint64{0}}
	for _, t := range targets {
		p, err := parseV4Prefix(t)
		if err != nil {
			return nil, err
		}
		s.prefixes = append(s.prefixes, p)
		s.total += prefixSize(p)
		s.cum = append(s.cum, s.total)
	}
	for _, e := range excludes {
		p, err := parseV4Prefix(e)
		if err != nil {
			return nil, fmt.Errorf("exclude: %w", err)
		}
		s.excludes = append(s.excludes, p)
	}
	return s, nil
}

// SetWithin restricts the space to an allowlist of CIDRs: after this, Allowed
// only passes addresses inside one of them (intersected with the space). Used to
// clip a derived target list (e.g. the adaptive widen's live /24 blocks) back to
// the original --targets scope, so a scan never probes outside what was asked.
func (s *Space) SetWithin(cidrs []string) error {
	s.within = nil
	for _, c := range cidrs {
		p, err := parseV4Prefix(c)
		if err != nil {
			return fmt.Errorf("within: %w", err)
		}
		s.within = append(s.within, p)
	}
	return nil
}

func parseV4Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("only IPv4 supported: %q", s)
	}
	return p.Masked(), nil
}

func prefixSize(p netip.Prefix) uint64 {
	return uint64(1) << uint(32-p.Bits())
}

// Total is the number of addresses in the space, before reserved/exclude
// filtering (the filtering happens lazily, per address, at emission).
func (s *Space) Total() uint64 { return s.total }

// AddrAt returns the i-th address of the ordered space (0 <= i < Total).
func (s *Space) AddrAt(i uint64) netip.Addr {
	// Locate block k with cum[k] <= i < cum[k+1].
	k := sort.Search(len(s.cum), func(j int) bool { return s.cum[j] > i }) - 1
	offset := i - s.cum[k]
	base := s.prefixes[k].Addr().As4()
	v := binary.BigEndian.Uint32(base[:]) + uint32(offset)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Allowed reports whether addr may be scanned: not reserved (unless disabled),
// not inside any user-excluded prefix, and — when a within allowlist is set —
// inside one of those prefixes.
func (s *Space) Allowed(addr netip.Addr) bool {
	if s.skipReserved && isReserved(addr) {
		return false
	}
	for _, e := range s.excludes {
		if e.Contains(addr) {
			return false
		}
	}
	if len(s.within) > 0 {
		in := false
		for _, w := range s.within {
			if w.Contains(addr) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return true
}

func isReserved(addr netip.Addr) bool {
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Randomized yields every allowed address exactly once, in a stateless
// pseudo-random order determined by seed. Reserved/excluded addresses are
// walked over (permuted then skipped), so no address list is materialized.
func (s *Space) Randomized(seed uint64) iter.Seq[netip.Addr] {
	return s.RandomizedFrom(seed, 0, nil)
}

// RandomizedFrom is Randomized starting at permutation position `start` (for
// resuming). If pos is non-nil it is updated to the current position as the
// sequence advances, so a checkpointer can record where the scan is; resuming
// with the same seed and that position replays the exact remaining sequence.
func (s *Space) RandomizedFrom(seed, start uint64, pos *uint64) iter.Seq[netip.Addr] {
	perm := NewPermutation(s.total, seed)
	return func(yield func(netip.Addr) bool) {
		for p := start; p < s.total; p++ {
			if pos != nil {
				atomic.StoreUint64(pos, p)
			}
			addr := s.AddrAt(perm.Shuffle(p))
			if !s.Allowed(addr) {
				continue
			}
			if !yield(addr) {
				return
			}
		}
	}
}

// Signature is a stable fingerprint of the scan's address space (target
// prefixes in order, excludes, and the reserved-skipping flag). Resuming is
// only valid against a checkpoint with the same signature — the prefix order
// determines the position→address mapping, so it must match exactly.
func (s *Space) Signature() string {
	h := sha256.New()
	for _, p := range s.prefixes {
		fmt.Fprintf(h, "t:%s;", p.String())
	}
	for _, e := range s.excludes {
		fmt.Fprintf(h, "x:%s;", e.String())
	}
	for _, w := range s.within {
		fmt.Fprintf(h, "w:%s;", w.String())
	}
	fmt.Fprintf(h, "r:%v", s.skipReserved)
	return hex.EncodeToString(h.Sum(nil))
}

// Ordered yields every allowed address in ascending order. Handy for tests and
// deterministic runs; production discovery uses Randomized.
func (s *Space) Ordered() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for pos := uint64(0); pos < s.total; pos++ {
			addr := s.AddrAt(pos)
			if !s.Allowed(addr) {
				continue
			}
			if !yield(addr) {
				return
			}
		}
	}
}
