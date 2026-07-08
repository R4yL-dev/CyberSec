package enrich

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed top-ports.txt
var topPortsFile string

var (
	commonOnce  sync.Once
	commonPorts []uint16
)

// CommonPorts returns the curated common-ports list (embedded top-ports.txt),
// used as the portscan palier's default breadth and the ns-discover --top-ports
// source.
func CommonPorts() []uint16 {
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
			commonPorts = append(commonPorts, u)
		}
	})
	return commonPorts
}
