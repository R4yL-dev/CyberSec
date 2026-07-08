// Package fmtx holds small human-readable formatters shared by the CLIs.
package fmtx

import (
	"fmt"
	"strconv"
	"time"
)

// Count renders a large count compactly: 254, 1.2k, 16.8M, 4.3B.
func Count(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return strconv.FormatUint(n, 10)
	}
}

// Duration renders a duration compactly for progress/ETA: 45s, 17m36s, 14h02m.
func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d < time.Hour {
		return d.String() // e.g. 45s, 17m36s
	}
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	return fmt.Sprintf("%dh%02dm", h, m)
}
