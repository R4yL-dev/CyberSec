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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"netscan/internal/model"
	"netscan/internal/scan"
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
		workers     = flag.Int("workers", 100, "concurrent workers (connect mode)")
		timeout     = flag.Duration("timeout", 1500*time.Millisecond, "per-connection timeout")
		seedFlag    = flag.Int64("seed", -1, "permutation seed for reproducible order (-1 = random)")
		retries     = flag.Int("retries", 1, "SYN retransmissions per probe (syn mode)")
		grace       = flag.Duration("grace", 3*time.Second, "wait for late replies after sending (syn mode)")
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

	seed := pickSeed(*seedFlag)

	var limiter *rate.Limiter
	if *ratePPS > 0 {
		burst := *workers
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(*ratePPS), burst)
	}

	var prober scan.Prober
	switch *mode {
	case "connect":
		prober = &scan.ConnectProber{
			Ports:   ports,
			Workers: *workers,
			Timeout: *timeout,
			Limiter: limiter,
		}
	case "syn":
		prober = scan.NewSYNProber(ports, *retries, *grace, limiter)
	default:
		fatal("unknown mode %q (want connect|syn)", *mode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "[*] targets : %d addresses (seed=%d)\n", space.Total(), seed)
	fmt.Fprintf(os.Stderr, "[*] ports   : %s | mode=%s | rate=%.0f pps | workers=%d\n",
		*portsFlag, *mode, *ratePPS, *workers)

	// Encode discovered hosts to stdout while the prober runs.
	out := make(chan model.WireRecord, 256)
	enc := stream.NewEncoder(os.Stdout)
	var found int
	encDone := make(chan struct{})
	go func() {
		defer close(encDone)
		for rec := range out {
			if err := enc.Encode(rec); err != nil {
				fmt.Fprintf(os.Stderr, "[!] encode: %v\n", err)
			}
			found++
		}
		if err := enc.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] flush: %v\n", err)
		}
	}()

	start := time.Now()
	runErr := prober.Run(ctx, space.Randomized(seed), out)
	close(out)
	<-encDone

	fmt.Fprintf(os.Stderr, "[+] %d host(s) with open ports in %s\n", found, time.Since(start).Round(time.Millisecond))
	if runErr != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "[*] interrupted")
		} else {
			fatal("%v", runErr)
		}
	}
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
