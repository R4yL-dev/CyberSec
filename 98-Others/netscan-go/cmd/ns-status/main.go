// Command ns-status reads the scan store and prints a monitoring snapshot:
// host counts, work-queue depth by state/stage, recent hosts, and per-binary
// heartbeats. It is the CLI stand-in for a future web dashboard.
//
// Example:
//
//	ns-status --db scan.db
//	ns-status --db scan.db --interval 2s
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"netscan/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	interval := flag.Duration("interval", 0, "refresh interval (0 = one shot)")
	flag.Parse()
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "ns-status: --db is required")
		os.Exit(1)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ns-status: open store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	for {
		s, err := st.Stats(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ns-status: stats: %v\n", err)
			os.Exit(1)
		}
		if *interval > 0 {
			fmt.Print("\033[2J\033[H") // clear screen for watch mode
		}
		printStats(s)
		if *interval <= 0 {
			return
		}
		time.Sleep(*interval)
	}
}

func printStats(s store.Stats) {
	fmt.Printf("== netscan status @ %s ==\n", time.Now().Format("15:04:05"))
	fmt.Printf("hosts: %d\n", s.Hosts)

	fmt.Printf("work : %s\n", formatCounts(s.WorkByState))
	if len(s.PendingByStage) > 0 {
		fmt.Printf("queue: %s (pending by stage)\n", formatCounts(s.PendingByStage))
	}

	if len(s.Runs) > 0 {
		fmt.Println("runs :")
		for _, r := range s.Runs {
			age := time.Since(r.UpdatedAt).Round(time.Second)
			fmt.Printf("  %-12s pid=%-6d counter=%-8d %s ago\n", r.Tool, r.PID, r.Counter, age)
		}
	}

	if len(s.RecentHosts) > 0 {
		fmt.Println("recent hosts:")
		for _, h := range s.RecentHosts {
			fmt.Printf("  %-15s ports=%v\n", h.IP, h.OpenPorts)
		}
	}
}

func formatCounts(m map[string]int64) string {
	if len(m) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += "  "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	return out
}
