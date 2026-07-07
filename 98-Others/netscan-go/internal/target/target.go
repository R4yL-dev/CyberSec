// Package target turns a set of CIDR blocks into an ordered, indexable IPv4
// address space, filters out reserved and user-excluded ranges, and hands out
// addresses in a stateless pseudo-random order (see permute.go). Only IPv4 is
// supported in v1.
package target

import (
	"encoding/binary"
	"fmt"
	"iter"
	"net/netip"
	"sort"
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

// Allowed reports whether addr may be scanned: not reserved (unless disabled)
// and not inside any user-excluded prefix.
func (s *Space) Allowed(addr netip.Addr) bool {
	if s.skipReserved && isReserved(addr) {
		return false
	}
	for _, e := range s.excludes {
		if e.Contains(addr) {
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
	perm := NewPermutation(s.total, seed)
	return func(yield func(netip.Addr) bool) {
		for pos := uint64(0); pos < s.total; pos++ {
			addr := s.AddrAt(perm.Shuffle(pos))
			if !s.Allowed(addr) {
				continue
			}
			if !yield(addr) {
				return
			}
		}
	}
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
