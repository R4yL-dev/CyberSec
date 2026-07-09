// Package ports holds the curated common-ports list, shared by discovery
// (ns-discover --top-ports) and the portscan palier. It is dependency-light on
// purpose so the discovery binary needn't pull the enrichment code.
package ports

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

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
