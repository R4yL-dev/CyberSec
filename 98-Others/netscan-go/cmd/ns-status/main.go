// Command ns-status reads the scan store and prints a phase-aware monitoring
// dashboard: discovery/enrichment progress bars, the work queue by palier, and a
// findings summary (top ports, protocols, web/TLS, geo). In live mode
// (--interval) it refreshes in place and exits with a completion banner once the
// scan is done. With --host it prints one host's full record as raw JSON.
//
// Example:
//
//	ns-status --db scan.db                 # one-shot snapshot
//	ns-status --db scan.db --interval 2s   # live dashboard (auto-exits when done)
//	ns-status --db scan.db --host 1.1.1.1  # full record for one host (JSON)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netscan/internal/fmtx"
	"netscan/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	interval := flag.Duration("interval", 0, "refresh interval (0 = one shot)")
	hostIP := flag.String("host", "", "print the full record for this IP and exit")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	liveBlocks := flag.Int("live-blocks", 0, "print live /N blocks as CIDRs and exit (for the adaptive pass-2 target list); 0 = disabled")
	minHosts := flag.Int("min-hosts", 1, "with --live-blocks: minimum hosts a block needs to be listed")
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
	if *liveBlocks > 0 {
		printLiveBlocks(ctx, st, *liveBlocks, *minHosts)
		return
	}

	r := &renderer{
		db:   filepath.Base(*dbPath),
		col:  styler{on: !*noColor && isTTY(os.Stdout)},
		prev: map[string]sample{},
	}
	for {
		sm, err := st.Summary(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ns-status: summary: %v\n", err)
			os.Exit(1)
		}
		ingestState, _ := st.GetMeta(ctx, store.MetaIngestState)
		started := readStarted(ctx, st)

		pending := sm.WorkByState[store.StatePending]
		leased := sm.WorkByState[store.StateLeased]
		ph := phaseOf(ingestState, pending, leased)

		if *interval > 0 {
			fmt.Print("\033[2J\033[H") // clear screen for watch mode
		}
		r.render(sm, ph, started)

		if *interval <= 0 || ph == phaseComplete {
			return // one-shot, or live mode reached completion
		}
		time.Sleep(*interval)
	}
}

// ---- phases -----------------------------------------------------------------

type phase int

const (
	phaseDiscovering phase = iota // discovery still feeding the queue
	phaseEnriching                // discovery done, queue still draining
	phaseComplete                 // discovery done and queue empty
)

// phaseOf derives the scan lifecycle from ingestion state + queue depth.
func phaseOf(ingestState string, pending, leased int64) phase {
	if ingestState != store.IngestDone {
		return phaseDiscovering
	}
	if pending+leased > 0 {
		return phaseEnriching
	}
	return phaseComplete
}

// ---- rendering --------------------------------------------------------------

type renderer struct {
	db   string
	col  styler
	prev map[string]sample // per-tool last counter, for rate computation
}

type sample struct {
	counter int64
	at      time.Time
}

// rate derives a per-second rate from the change in a tool's heartbeat counter
// since the previous refresh (so it appears from the 2nd sample onward).
func (r *renderer) rate(rs store.RunStat, now time.Time) (float64, bool) {
	p, ok := r.prev[rs.Tool]
	r.prev[rs.Tool] = sample{rs.Counter, now}
	if !ok || !now.After(p.at) {
		return 0, false
	}
	return float64(rs.Counter-p.counter) / now.Sub(p.at).Seconds(), true
}

func (r *renderer) render(sm store.Summary, ph phase, started time.Time) {
	now := time.Now()
	c := r.col

	// Header: netscan · scan.db · 14:23:07 · elapsed 3m12s
	head := fmt.Sprintf("%s · %s · %s", c.bold("netscan"), r.db, now.Format("15:04:05"))
	if !started.IsZero() {
		head += " · " + c.dim("elapsed "+fmtx.Duration(now.Sub(started)))
	}
	fmt.Println(head)
	fmt.Println()

	done := sm.WorkByState[store.StateDone]
	pending := sm.WorkByState[store.StatePending]
	leased := sm.WorkByState[store.StateLeased]
	failed := sm.WorkByState[store.StateFailed]

	if ph == phaseComplete {
		banner := fmt.Sprintf("✓ SCAN COMPLETE · %s hosts", fmtx.Count(uint64(sm.Hosts)))
		if !started.IsZero() {
			banner += " · " + fmtx.Duration(now.Sub(started))
		}
		fmt.Println(c.green(c.bold(banner)))
	} else {
		r.discoveryBar(sm, ph, now)
		r.enrichmentBar(sm, now, done, pending+leased)
		r.workLines(sm, failed)
	}

	r.findings(sm)
}

// discoveryBar shows discovery progress (live %/pps/ETA while discovering, or a
// done marker once ingestion has finished).
func (r *renderer) discoveryBar(sm store.Summary, ph phase, now time.Time) {
	rs, ok := findRun(sm.Runs, "ns-discover")
	if !ok {
		return
	}
	if ph != phaseDiscovering {
		r.bar("discovery", 1, r.col.dim("done"))
		return
	}
	frac := 0.0
	right := ""
	if rs.Total > 0 {
		frac = float64(rs.Counter) / float64(rs.Total)
		right = fmt.Sprintf("%s/%s", fmtx.Count(uint64(rs.Counter)), fmtx.Count(uint64(rs.Total)))
	}
	if pps, live := r.rate(*rs, now); live {
		right += fmt.Sprintf("  %.0f pps", pps)
		if pps > 0 && rs.Total > rs.Counter {
			eta := time.Duration(float64(rs.Total-rs.Counter)/pps) * time.Second
			right += "  ETA " + fmtx.Duration(eta)
		}
	}
	if rs.Note != "" {
		right += "  " + r.col.dim(rs.Note)
	}
	r.bar("discovery", frac, right)
}

// enrichmentBar shows enrichment progress as done/(done+remaining), with rate
// and ETA once a second sample is available.
func (r *renderer) enrichmentBar(sm store.Summary, now time.Time, done, remaining int64) {
	total := done + remaining
	if total == 0 {
		return // nothing enqueued yet
	}
	frac := float64(done) / float64(total)
	right := fmt.Sprintf("%s/%s", fmtx.Count(uint64(done)), fmtx.Count(uint64(total)))
	if rs, ok := findRun(sm.Runs, "ns-enrich"); ok {
		if v, live := r.rate(*rs, now); live {
			right += fmt.Sprintf("  %.0f/s", v)
			if v > 0 && remaining > 0 {
				eta := time.Duration(float64(remaining)/v) * time.Second
				right += "  ETA " + fmtx.Duration(eta)
			}
		}
	}
	r.bar("enrichment", frac, right)
}

// stageOrder is the fixed display order for per-palier work lines.
var stageOrder = []string{"detect", "webinfo", "crawl", "tls-deep", "portscan", "ptr"}

// stageCounts returns "stage N" parts for every palier holding items in the
// given work state, in the fixed order (custom stages appended after).
func (r *renderer) stageCounts(sm store.Summary, state string) []string {
	seen := map[string]bool{}
	var parts []string
	add := func(stg string) {
		if n := sm.QueueByStage[stg][state]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", stg, n))
		}
	}
	for _, stg := range stageOrder {
		seen[stg] = true
		add(stg)
	}
	for stg := range sm.QueueByStage {
		if !seen[stg] {
			add(stg)
		}
	}
	return parts
}

// workLines shows enrichment work per palier: what is executing now (running =
// leased/in-flight), what is waiting (queue = pending), and the failed total.
func (r *renderer) workLines(sm store.Summary, failed int64) {
	line := func(label, val string) {
		fmt.Printf("  %s %s\n", r.col.dim(fmt.Sprintf("%-7s", label)), val)
	}
	if p := r.stageCounts(sm, store.StateLeased); len(p) > 0 {
		line("running", strings.Join(p, " · "))
	}
	if p := r.stageCounts(sm, store.StatePending); len(p) > 0 {
		line("queue", strings.Join(p, " · "))
	}
	if failed > 0 {
		line("failed", r.col.red(fmt.Sprintf("%d", failed)))
	}
}

// findings renders the HOSTS summary block: counts and what the scan found.
func (r *renderer) findings(sm store.Summary) {
	c := r.col
	fmt.Printf("\n%s %s\n", c.bold("HOSTS"), fmtx.Count(uint64(sm.Hosts)))

	row := func(label, val string) { // aligned "  label  value"
		fmt.Printf("  %s %s\n", c.dim(fmt.Sprintf("%-6s", label)), val)
	}

	if len(sm.TopPorts) > 0 {
		var b strings.Builder
		for i, p := range sm.TopPorts {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%d(%d)", p.Port, p.Count)
		}
		row("ports", b.String())
	}
	if len(sm.Protocols) > 0 {
		row("proto", joinLabels(sm.Protocols))
	}

	// web / tls / crawl line
	var wp []string
	if sm.WebServers > 0 {
		wp = append(wp, fmt.Sprintf("%d srv", sm.WebServers))
	}
	if sm.TLSPorts > 0 {
		tls := fmt.Sprintf("tls %d", sm.TLSPorts)
		var warn []string
		if sm.TLSExpired > 0 {
			warn = append(warn, fmt.Sprintf("%d expired", sm.TLSExpired))
		}
		if sm.TLSWeak > 0 {
			warn = append(warn, fmt.Sprintf("%d weak", sm.TLSWeak))
		}
		if len(warn) > 0 {
			tls += " (" + c.red(strings.Join(warn, ", ")) + ")"
		}
		wp = append(wp, tls)
	}
	if sm.SensitivePaths > 0 {
		wp = append(wp, c.red(fmt.Sprintf("crawl %d sensitive", sm.SensitivePaths)))
	}
	if len(wp) > 0 {
		row("web", strings.Join(wp, " · "))
	}
	if len(sm.Countries) > 0 {
		row("geo", joinLabels(sm.Countries))
	}

	if len(sm.RecentHosts) > 0 {
		row("latest", "")
		for i, h := range sm.RecentHosts {
			if i >= 5 {
				break
			}
			fmt.Printf("    %-15s %s\n", h.IP, portsList(h.OpenPorts))
		}
	}
	fmt.Printf("  %s\n", c.dim("→ details: netscan status --db "+r.db+" --host <IP>"))
}

func (r *renderer) bar(label string, frac float64, right string) {
	lab := r.col.dim(fmt.Sprintf("%-11s", label))
	bar := r.col.green(fmtx.Bar(frac, 18))
	fmt.Printf("%s %s %3.0f%%  %s\n", lab, bar, frac*100, right)
}

// ---- helpers ----------------------------------------------------------------

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

// printLiveBlocks emits the live /prefixBits blocks as CIDRs, one per line —
// the machine-readable pass-2 target list for the adaptive scan (@file intake).
func printLiveBlocks(ctx context.Context, st *store.SQLite, prefixBits, minHosts int) {
	if prefixBits < 1 || prefixBits > 32 {
		fmt.Fprintf(os.Stderr, "ns-status: --live-blocks must be 1..32\n")
		os.Exit(1)
	}
	blocks, err := st.LiveBlocks(ctx, prefixBits, minHosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ns-status: live-blocks: %v\n", err)
		os.Exit(1)
	}
	for _, b := range blocks {
		fmt.Println(b.String())
	}
}

func readStarted(ctx context.Context, st *store.SQLite) time.Time {
	v, _ := st.GetMeta(ctx, store.MetaScanStarted)
	if v == "" {
		return time.Time{}
	}
	ms, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func findRun(runs []store.RunStat, tool string) (*store.RunStat, bool) {
	for i := range runs {
		if runs[i].Tool == tool {
			return &runs[i], true
		}
	}
	return nil, false
}

func joinLabels(ls []store.LabelCount) string {
	parts := make([]string, len(ls))
	for i, l := range ls {
		parts[i] = fmt.Sprintf("%s %d", l.Label, l.Count)
	}
	return strings.Join(parts, " · ")
}

func portsList(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for i, p := range ports {
		if i >= 8 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, strconv.Itoa(int(p)))
	}
	return strings.Join(parts, ",")
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// styler applies optional ANSI styling.
type styler struct{ on bool }

func (s styler) wrap(code, t string) string {
	if !s.on {
		return t
	}
	return "\033[" + code + "m" + t + "\033[0m"
}
func (s styler) bold(t string) string  { return s.wrap("1", t) }
func (s styler) dim(t string) string   { return s.wrap("2", t) }
func (s styler) green(t string) string { return s.wrap("32", t) }
func (s styler) red(t string) string   { return s.wrap("31", t) }
