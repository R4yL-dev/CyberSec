// Command ns-discover is the domain-A firehose: it enumerates a set of CIDR
// targets in stateless random order, discovers hosts with open ports, and
// emits them as NDJSON on stdout. It never touches the work queue.
//
// Example:
//
//	ns-discover --targets 1.1.1.0/24 --ports 80,443 | ns-ingest --db scan.db
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"netscan/internal/model"
	"netscan/internal/scan"
	"netscan/internal/store"
	"netscan/internal/stream"
	"netscan/internal/target"
)

// bigScanThreshold guards against an accidental huge scan: above this many
// addresses, --yes is required.
const bigScanThreshold = uint64(1) << 16

func main() {
	var (
		targetsFlag = flag.String("targets", "", "comma-separated CIDRs, or @file (one per line)")
		excludeFlag = flag.String("exclude", "", "comma-separated CIDRs to exclude")
		excludeFile = flag.String("exclude-file", "", "file of CIDRs to exclude (one per line)")
		noReserved  = flag.Bool("no-skip-reserved", false, "do NOT skip reserved/private ranges")
		portsFlag   = flag.String("ports", "80,443", "comma-separated ports")
		mode        = flag.String("mode", "connect", "discovery mode: connect|syn")
		ratePPS     = flag.Float64("rate", 1000, "max probes per second (0 = unlimited)")
		workers     = flag.Int("workers", -1, "concurrent workers, connect mode (-1 = auto from rate x timeout, bounded by FDs)")
		dbPath      = flag.String("db", "", "optional SQLite DB to report scan progress into (for ns-status)")
		timeout     = flag.Duration("timeout", 1500*time.Millisecond, "per-connection timeout")
		seedFlag    = flag.Int64("seed", -1, "permutation seed for reproducible order (-1 = random)")
		retries     = flag.Int("retries", 1, "SYN retransmissions per probe (syn mode)")
		grace       = flag.Duration("grace", 3*time.Second, "wait for late replies after sending (syn mode)")
		synSrcPort  = flag.Int("src-port", 0, "SYN source port, 0 = random (syn mode; pin to scope the iptables RST rule)")
		resume      = flag.Bool("resume", false, "resume from the last checkpoint in --db (requires --db)")
		yes         = flag.Bool("yes", false, "confirm scans larger than the safety threshold")
	)
	flag.Parse()

	targets := gatherTargets(*targetsFlag, flag.Args())
	if len(targets) == 0 {
		fatal("no targets: use --targets CIDR[,CIDR...] or positional args")
	}
	excludes := parseList(*excludeFlag)
	if *excludeFile != "" {
		lines, err := readLines(*excludeFile)
		if err != nil {
			fatal("exclude-file: %v", err)
		}
		excludes = append(excludes, lines...)
	}

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		fatal("%v", err)
	}

	space, err := target.NewSpace(targets, excludes, !*noReserved)
	if err != nil {
		fatal("%v", err)
	}
	if space.Total() > bigScanThreshold && !*yes {
		fatal("target space is %d addresses (> %d); re-run with --yes to confirm",
			space.Total(), bigScanThreshold)
	}

	// --rate 0 (unlimited) is the top cause of self-inflicted outages: behind a
	// NAT it floods the router/host connection table until new flows (DNS) drop.
	if *ratePPS == 0 {
		if !*yes {
			fatal("--rate 0 means UNLIMITED. On a large scan behind NAT this can exhaust the\n" +
				"  router/host connection table and break your own connectivity (you keep pinging\n" +
				"  IPs but DNS fails). Pick a rate (e.g. --rate 1000), or pass --yes to run unlimited.")
		}
		fmt.Fprintln(os.Stderr, "[!] rate=0 (unlimited) — watch your connectivity; Ctrl-C if DNS stalls")
	}

	sig := space.Signature()

	// Open the optional progress/checkpoint store up front (also used for --resume).
	var st *store.SQLite
	if *dbPath != "" {
		st, err = store.Open(*dbPath)
		if err != nil {
			fatal("open store: %v", err)
		}
		defer st.Close()
	}

	seed := pickSeed(*seedFlag)
	var startPos uint64
	if *resume {
		if st == nil {
			fatal("--resume requires --db")
		}
		ck, ok, cerr := loadCheckpoint(st, sig)
		if cerr != nil {
			fatal("resume: %v", cerr)
		}
		if !ok {
			fatal("--resume: no checkpoint to resume in %s (already finished, or none written yet)", *dbPath)
		}
		seed, startPos = ck.Seed, ck.Pos // rewound below, once effWorkers is known
	}

	// Connect mode: lift the FD limit and size the worker pool so it can actually
	// sustain --rate (throughput ~= workers/timeout), bounded by available FDs.
	effWorkers := *workers
	if *mode == "connect" {
		effWorkers = autoWorkers(*workers, *ratePPS, *timeout, len(ports), raiseNOFILE())
		if *ratePPS > 0 {
			if achievable := float64(effWorkers) / timeout.Seconds(); achievable < *ratePPS*0.9 {
				fmt.Fprintf(os.Stderr, "[!] connect throughput capped at ~%.0f pps by workers/FDs "+
					"(rate=%.0f); raise ulimit -n or use --mode syn\n", achievable, *ratePPS)
			}
		}
	}

	// The checkpoint records the generator position, which reads ahead of what
	// was actually probed (by the connect feed buffer + in-flight workers). Rewind
	// past that window so resume re-covers those addresses instead of skipping them.
	if *resume {
		startPos = rewindPos(startPos, *mode, effWorkers)
		fmt.Fprintf(os.Stderr, "[*] resume  : from position %d / %d (seed=%d)\n", startPos, space.Total(), seed)
	}

	var limiter *rate.Limiter
	if *ratePPS > 0 {
		burst := effWorkers
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(*ratePPS), burst)
	}

	// scanned counts probes actually sent (dials / SYNs), so its rate matches
	// --rate; progTotal is the total probe count = addresses x ports (x retries
	// for SYN passes). The percentage is identical to address progress.
	var scanned, found int64
	var pos uint64 // current permutation position, for checkpointing / resume
	progTotal := space.Total() * uint64(len(ports))

	var prober scan.Prober
	switch *mode {
	case "connect":
		prober = &scan.ConnectProber{
			Ports:    ports,
			Workers:  effWorkers,
			Timeout:  *timeout,
			Limiter:  limiter,
			Progress: &scanned,
		}
	case "syn":
		if *synSrcPort < 0 || *synSrcPort > 65535 {
			fatal("src-port out of range: %d", *synSrcPort)
		}
		sp := scan.NewSYNProber(ports, *retries, *grace, uint16(*synSrcPort), limiter)
		sp.Progress = &scanned
		progTotal = space.Total() * uint64(len(ports)) * uint64(max(*retries, 1))
		fmt.Fprintf(os.Stderr, "[*] syn     : src-port=%d (scope iptables RST rule to this port)\n", sp.SrcPort())
		prober = sp
	default:
		fatal("unknown mode %q (want connect|syn)", *mode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "[*] targets : %d addresses (seed=%d)\n", space.Total(), seed)
	fmt.Fprintf(os.Stderr, "[*] ports   : %s | mode=%s | rate=%.0f pps | workers=%d\n",
		*portsFlag, *mode, *ratePPS, effWorkers)

	// Progress + checkpoint reporting into the store (read by ns-status). Discover
	// only writes its own heartbeat/checkpoint here — it never touches the work queue.
	var progStop func()
	if st != nil {
		progStop = startProgress(st, progTotal, &scanned, &found, sig, seed, &pos, space.Total())
	}

	// Encode discovered hosts to stdout while the prober runs, flushing each one
	// immediately so downstream (ns-ingest) sees hosts live, not at the end.
	out := make(chan model.WireRecord, 256)
	enc := stream.NewEncoder(os.Stdout)
	encDone := make(chan struct{})
	go func() {
		defer close(encDone)
		for rec := range out {
			if err := enc.Encode(rec); err != nil {
				fmt.Fprintf(os.Stderr, "[!] encode: %v\n", err)
			}
			if err := enc.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] flush: %v\n", err)
			}
			atomic.AddInt64(&found, 1)
		}
	}()

	start := time.Now()
	runErr := prober.Run(ctx, space.RandomizedFrom(seed, startPos, &pos), out)
	close(out)
	<-encDone
	if progStop != nil {
		progStop()
	}
	// Finished cleanly — drop the checkpoint so a later --resume has nothing to do.
	if st != nil && runErr == nil && ctx.Err() == nil {
		_ = clearCheckpoint(st)
	}

	fmt.Fprintf(os.Stderr, "[+] %d host(s) with open ports in %s\n",
		atomic.LoadInt64(&found), time.Since(start).Round(time.Millisecond))
	if runErr != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "[*] interrupted")
		} else {
			fatal("%v", runErr)
		}
	}
}

const workerHardCap = 4096

// autoWorkers picks the connect worker count. An explicit value (>0) wins.
// Otherwise it targets rate x timeout concurrent dials (what it takes to sustain
// the rate), bounded by the FD limit (each in-flight dial across all ports holds
// one) and a hard cap.
func autoWorkers(requested int, ratePPS float64, timeout time.Duration, nports int, nofile uint64) int {
	if requested > 0 {
		return requested
	}
	want := 100
	if ratePPS > 0 {
		want = int(math.Ceil(ratePPS * timeout.Seconds()))
	}
	if want < 1 {
		want = 1
	}
	fdCap := workerHardCap
	if nports > 0 && nofile > 128 {
		if c := (int(nofile) - 128) / nports; c < fdCap {
			fdCap = c
		}
	}
	if fdCap < 1 {
		fdCap = 1
	}
	if want > fdCap {
		want = fdCap
	}
	return want
}

// raiseNOFILE best-effort raises the soft open-files limit to the hard limit and
// returns the effective soft limit.
func raiseNOFILE() uint64 {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 1024
	}
	if lim.Cur < lim.Max {
		lim.Cur = lim.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
		_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
	return uint64(lim.Cur)
}

// checkpointKey stores discovery's resumable position in the meta table.
const checkpointKey = "discover.checkpoint"

type checkpoint struct {
	Sig   string `json:"sig"`
	Seed  uint64 `json:"seed"`
	Pos   uint64 `json:"pos"`
	Total uint64 `json:"total"`
}

// loadCheckpoint reads a checkpoint and validates it matches the current target
// signature. ok is false when there is nothing to resume; a non-nil error means
// a checkpoint exists but is for a different target set.
func loadCheckpoint(st *store.SQLite, sig string) (checkpoint, bool, error) {
	v, err := st.GetMeta(context.Background(), checkpointKey)
	if err != nil {
		return checkpoint{}, false, err
	}
	if v == "" {
		return checkpoint{}, false, nil
	}
	var ck checkpoint
	if err := json.Unmarshal([]byte(v), &ck); err != nil {
		return checkpoint{}, false, nil
	}
	if ck.Sig != sig {
		return checkpoint{}, false, fmt.Errorf("checkpoint is for a different target set")
	}
	return ck, true, nil
}

func writeCheckpoint(st *store.SQLite, sig string, seed uint64, pos *uint64, total uint64) {
	b, _ := json.Marshal(checkpoint{Sig: sig, Seed: seed, Pos: atomic.LoadUint64(pos), Total: total})
	_ = st.SetMeta(context.Background(), checkpointKey, string(b))
}

func clearCheckpoint(st *store.SQLite) error {
	return st.SetMeta(context.Background(), checkpointKey, "")
}

// rewindPos backs a resume position up past the prober's in-flight window so
// resume overlaps already-probed addresses rather than skipping a gap. The SYN
// sender consumes the sequence in order with no read-ahead (no rewind needed);
// connect reads ahead by its feed buffer (workers*2) plus in-flight workers.
func rewindPos(pos uint64, mode string, workers int) uint64 {
	if mode == "syn" {
		return pos
	}
	if workers < 1 {
		workers = 1
	}
	margin := uint64(workers)*4 + (1 << 14) // feed buffer + workers + slack
	if pos > margin {
		return pos - margin
	}
	return 0
}

// startProgress writes a discovery heartbeat (scanned/total, found) and a resume
// checkpoint every second until the returned stop func is called (which also
// writes a final one).
func startProgress(st *store.SQLite, total uint64, scanned, found *int64,
	sig string, seed uint64, pos *uint64, addrTotal uint64) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	write := func() {
		_ = st.Heartbeat(context.Background(), store.RunStat{
			Tool:      "ns-discover",
			PID:       os.Getpid(),
			Counter:   atomic.LoadInt64(scanned),
			Total:     int64(total),
			Note:      fmt.Sprintf("found=%d", atomic.LoadInt64(found)),
			UpdatedAt: time.Now().UTC(),
		})
		writeCheckpoint(st, sig, seed, pos, addrTotal)
	}
	go func() {
		defer close(stopped)
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-done:
				write()
				return
			case <-tk.C:
				write()
			}
		}
	}()
	return func() { close(done); <-stopped }
}

func gatherTargets(flagVal string, args []string) []string {
	var out []string
	for _, tok := range parseList(flagVal) {
		out = append(out, expandItem(tok)...)
	}
	for _, a := range args {
		out = append(out, expandItem(a)...)
	}
	return out
}

// expandItem returns the CIDRs for one token: the file lines if it starts with
// '@', otherwise the token itself.
func expandItem(tok string) []string {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil
	}
	if strings.HasPrefix(tok, "@") {
		lines, err := readLines(tok[1:])
		if err != nil {
			fatal("reading %s: %v", tok, err)
		}
		return lines
	}
	return []string{tok}
}

func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePorts(s string) ([]uint16, error) {
	var ports []uint16
	for _, part := range parseList(s) {
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, uint16(n))
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid port provided")
	}
	return ports, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func pickSeed(flagVal int64) uint64 {
	if flagVal >= 0 {
		return uint64(flagVal)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ns-discover: "+format+"\n", args...)
	os.Exit(1)
}
