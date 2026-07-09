// Package ports holds the curated common-ports list, shared by discovery
// (ns-discover --top-ports) and the portscan palier. It is dependency-light on
// purpose so the discovery binary needn't pull the enrichment code.
package ports

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Parse turns a non-empty port spec into a sorted, de-duplicated port list.
// The spec is "all" (1-65535) or a comma-separated list of ports and ranges,
// e.g. "1-1024,3306,8000-8100". Callers handle the empty case (each has its own
// default: discovery uses --top-ports, portscan uses the common set).
func Parse(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	if spec == "all" {
		out := make([]uint16, 0, 65535)
		for p := 1; p <= 65535; p++ {
			out = append(out, uint16(p))
		}
		return out, nil
	}
	seen := map[uint16]struct{}{}
	var out []uint16
	add := func(p int) {
		u := uint16(p)
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, isRange := strings.Cut(part, "-"); isRange {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for p := a; p <= b; p++ {
				add(p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		add(p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid port in %q", spec)
	}
	return out, nil
}

//go:embed top-ports.txt
var topPortsFile string

var (
	commonOnce sync.Once
	common     []uint16
)

// Common returns the curated common TCP ports, ordered most-common-first and
// de-duplicated.
func Common() []uint16 {
	commonOnce.Do(func() {
		seen := map[uint16]struct{}{}
		for _, line := range strings.Split(topPortsFile, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			p, err := strconv.Atoi(line)
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			u := uint16(p)
			if _, dup := seen[u]; dup { // keep first (highest-ranked) occurrence
				continue
			}
			seen[u] = struct{}{}
			common = append(common, u)
		}
	})
	return common
}
