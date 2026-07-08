// Command ns-ingest bridges domain A to domain B: it reads discovery NDJSON
// from stdin, upserts each responding host into the SQLite store, and enqueues
// a "light" enrichment work item for it.
//
// Example:
//
//	ns-discover --targets 1.1.1.0/24 | ns-ingest --db scan.db
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"netscan/internal/geoip"
	"netscan/internal/model"
	"netscan/internal/store"
	"netscan/internal/stream"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	geoPath := flag.String("geoip", "data/dbip-country.mmdb", "GeoIP .mmdb (country/city); \"\" to disable")
	asnPath := flag.String("asn", "data/dbip-asn.mmdb", "ASN .mmdb; \"\" to disable")
	flag.Parse()
	if *dbPath == "" {
		fatal("--db is required")
	}

	// Geo is on by default when the DBs exist (see `make geoip`); a missing file
	// is skipped silently with a one-time hint, never fatal.
	geo := geoip.Open(existing(*geoPath), existing(*asnPath))
	defer geo.Close()
	if geo.Enabled() {
		fmt.Fprintln(os.Stderr, "[*] geoip   : enabled")
	} else if *geoPath != "" || *asnPath != "" {
		fmt.Fprintln(os.Stderr, "[*] geoip   : no database found (run 'make geoip'); continuing without geo")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Publish "running" so a following ns-enrich keeps draining until we finish.
	_ = st.SetMeta(ctx, store.MetaIngestState, store.IngestRunning)

	var n int64
	stopHB := heartbeat(ctx, st, &n)

	err = stream.Decode(os.Stdin, func(rec model.WireRecord) error {
		if err := st.Ingest(ctx, rec, model.StageLight, geo.Annotate(rec.IP)); err != nil {
			return err
		}
		atomic.AddInt64(&n, 1)
		return ctx.Err()
	})
	stopHB()
	writeHeartbeat(context.Background(), st, atomic.LoadInt64(&n))

	fmt.Fprintf(os.Stderr, "[+] ingested %d host(s)\n", atomic.LoadInt64(&n))
	if err != nil && ctx.Err() == nil {
		fatal("ingest: %v", err)
	}
	// Signal completion only on a clean finish (all input consumed).
	if err == nil && ctx.Err() == nil {
		_ = st.SetMeta(context.Background(), store.MetaIngestState, store.IngestDone)
	}
}

// heartbeat records progress every 2s until the returned stop func is called.
func heartbeat(ctx context.Context, st *store.SQLite, n *int64) (stop func()) {
	done := make(chan struct{})
	go func() {
		tk := time.NewTicker(2 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				writeHeartbeat(ctx, st, atomic.LoadInt64(n))
			}
		}
	}()
	return func() { close(done) }
}

func writeHeartbeat(ctx context.Context, st *store.SQLite, counter int64) {
	_ = st.Heartbeat(ctx, store.RunStat{
		Tool:      "ns-ingest",
		PID:       os.Getpid(),
		Counter:   counter,
		UpdatedAt: time.Now().UTC(),
	})
}

// existing returns path if it points to a readable file, else "" (so a default
// path that isn't populated yet is treated as "disabled", not an error).
func existing(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ns-ingest: "+format+"\n", args...)
	os.Exit(1)
}
