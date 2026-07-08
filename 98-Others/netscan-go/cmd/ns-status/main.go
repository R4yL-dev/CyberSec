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
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"netscan/internal/fmtx"
	"netscan/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	interval := flag.Duration("interval", 0, "refresh interval (0 = one shot)")
	hostIP := flag.String("host", "", "print the full record for this IP and exit")
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

	if *hostIP != "" {
		printHost(ctx, st, *hostIP)
		return
	}
	prev := map[string]sample{} // per-tool last counter, for rate computation
	for {
		s, err := st.Stats(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ns-status: stats: %v\n", err)
			os.Exit(1)
		}
		if *interval > 0 {
			fmt.Print("\033[2J\033[H") // clear screen for watch mode
		}
		printDashboard(s, prev)
		if *interval <= 0 {
			return
		}
		time.Sleep(*interval)
	}
}

func printHost(ctx context.Context, st *store.SQLite, ipStr string) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ns-status: bad IP %q: %v\n", ipStr, err)
		os.Exit(1)
	}
	h, err := st.Host(ctx, ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ns-status: %v\n", err)
		os.Exit(1)
	}
	if h == nil {
		fmt.Fprintf(os.Stderr, "ns-status: host %s not found\n", ipStr)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(h, "", "  ")
	fmt.Println(string(out))
}

type sample struct {
	counter int64
	at      time.Time
}

// printDashboard renders a live picture of both domains. Rates are derived from
// the change in each tool's heartbeat counter since the previous refresh, so
// they only appear from the second sample onward (interval mode).
func printDashboard(s store.Stats, prev map[string]sample) {
	now := time.Now()
	rate := func(r store.RunStat) (float64, bool) {
		p, ok := prev[r.Tool]
		prev[r.Tool] = sample{r.Counter, now}
		if !ok || !now.After(p.at) {
			return 0, false
		}
		return float64(r.Counter-p.counter) / now.Sub(p.at).Seconds(), true
	}

	fmt.Printf("== netscan status @ %s ==\n", now.Format("15:04:05"))

	if r, ok := findRun(s.Runs, "ns-discover"); ok {
		pps, live := rate(*r)
		pct := ""
		if r.Total > 0 {
			pct = fmt.Sprintf(" %.1f%% (%s/%s)", 100*float64(r.Counter)/float64(r.Total),
				fmtx.Count(uint64(r.Counter)), fmtx.Count(uint64(r.Total)))
		}
		eta := ""
		if live && pps > 0 && r.Total > r.Counter {
			remaining := time.Duration(float64(r.Total-r.Counter)/pps) * time.Second
			eta = "  ETA " + fmtx.Duration(remaining)
		}
		fmt.Printf("discovery :%s%s  %s%s\n", pct, rateStr(pps, live, "pps"), r.Note, eta)
	}
	if r, ok := findRun(s.Runs, "ns-ingest"); ok {
		v, live := rate(*r)
		fmt.Printf("ingest    : %d hosts%s\n", r.Counter, rateStr(v, live, "/s"))
	}
	fmt.Printf("queue     : %s\n", formatCounts(s.WorkByState))
	if r, ok := findRun(s.Runs, "ns-enrich"); ok {
		v, live := rate(*r)
		fmt.Printf("enrich    : %d done%s  %s\n", r.Counter, rateStr(v, live, "/s"), r.Note)
	}
	fmt.Printf("hosts     : %d\n", s.Hosts)

	if len(s.RecentHosts) > 0 {
		fmt.Println("recent    :")
		for _, h := range s.RecentHosts {
			fmt.Printf("  %-15s ports=%v\n", h.IP, h.OpenPorts)
		}
	}
}

func findRun(runs []store.RunStat, tool string) (*store.RunStat, bool) {
	for i := range runs {
		if runs[i].Tool == tool {
			return &runs[i], true
		}
	}
	return nil, false
}

func rateStr(v float64, live bool, unit string) string {
	if !live {
		return ""
	}
	return fmt.Sprintf("  %.0f %s", v, unit)
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
