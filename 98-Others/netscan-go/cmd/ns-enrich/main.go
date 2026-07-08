// Command ns-enrich is a domain-B worker: it claims hosts from the queue, runs
// the matching enrichment palier, writes the results back, and enqueues the next
// paliers whose selector passes. It drains the whole enrichment pipeline by
// default (a stage graph defined in internal/pipeline).
//
// Example:
//
//	ns-enrich --db scan.db --workers 50          # drain the whole pipeline
//	ns-enrich --db scan.db --stage webinfo       # only one stage (dedicated worker)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"netscan/internal/pipeline"
	"netscan/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	stageFlag := flag.String("stage", "", "comma-separated stages to drain (default: all pipeline stages)")
	workers := flag.Int("workers", 50, "concurrent enrichment workers")
	timeout := flag.Duration("timeout", 10*time.Second, "per-probe timeout")
	maxAttempts := flag.Int("max-attempts", 5, "attempts before dead-lettering")
	lease := flag.Duration("lease", 2*time.Minute, "work item lease duration")
	backoff := flag.Duration("backoff", 5*time.Second, "base retry backoff")
	drain := flag.Bool("drain", false, "exit once the queue is empty instead of polling")
	follow := flag.Bool("follow", false, "keep draining until ingestion is done, then exit")
	pipelinePath := flag.String("pipeline", "", "YAML pipeline config (default: built-in graph)")
	printPipeline := flag.Bool("print-pipeline", false, "print the default pipeline YAML and exit")
	flag.Parse()

	if *printPipeline {
		os.Stdout.Write(pipeline.DefaultYAML())
		return
	}
	if *dbPath == "" {
		fatal("--db is required")
	}

	pl, err := loadPipeline(*pipelinePath, *timeout)
	if err != nil {
		fatal("%v", err)
	}
	stages := pl.Stages()
	if *stageFlag != "" {
		stages = nil
		for _, s := range strings.Split(*stageFlag, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			if _, ok := pl[s]; !ok {
				fatal("unknown stage %q", s)
			}
			stages = append(stages, s)
		}
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var processed, inflight int64 // inflight = claimed but not yet fully processed
	itemCh := make(chan store.WorkItem, *workers)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range itemCh {
				process(ctx, st, pl, it, *maxAttempts, *backoff)
				atomic.AddInt64(&inflight, -1)
				atomic.AddInt64(&processed, 1)
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "[*] ns-enrich stages=%s workers=%d (drain=%v follow=%v)\n",
		strings.Join(stages, ","), *workers, *drain, *follow)
	dispatch(ctx, st, itemCh, stages, *workers, *lease, *drain, *follow, &processed, &inflight)

	close(itemCh)
	wg.Wait()
	writeHeartbeat(context.Background(), st, atomic.LoadInt64(&processed))
	fmt.Fprintf(os.Stderr, "[+] enriched %d item(s)\n", atomic.LoadInt64(&processed))
}

// dispatch claims work across all requested stages and feeds the worker pool. It
// returns when ctx is cancelled, (drain) on the first fully-empty pass, or
// (follow) once the queue is empty and ingestion has finished — after a startup
// grace, so a stale "done" from a previous run can't trigger a premature exit.
func dispatch(ctx context.Context, st *store.SQLite, itemCh chan<- store.WorkItem,
	stages []string, batch int, lease time.Duration, drain, follow bool, processed, inflight *int64) {

	start := time.Now()
	lastHB := time.Now()
	for ctx.Err() == nil {
		got := 0
		for _, stage := range stages {
			items, err := st.Claim(ctx, stage, batch, lease)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] claim %s: %v\n", stage, err)
				return
			}
			got += len(items)
			for _, it := range items {
				atomic.AddInt64(inflight, 1)
				select {
				case itemCh <- it:
				case <-ctx.Done():
					return
				}
			}
		}
		if got == 0 {
			// Only conclude the queue is drained when nothing is in flight either:
			// a busy worker may still enqueue downstream stages (light -> webinfo/ptr).
			idle := atomic.LoadInt64(inflight) == 0
			if idle && drain {
				return
			}
			if idle && follow && time.Since(start) > 3*time.Second {
				if v, _ := st.GetMeta(ctx, store.MetaIngestState); v == store.IngestDone {
					return
				}
			}
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}
		if time.Since(lastHB) > 2*time.Second {
			writeHeartbeat(ctx, st, atomic.LoadInt64(processed))
			lastHB = time.Now()
		}
	}
}

// process runs one work item through its stage's enricher, persists the result,
// then enqueues the next stages whose selector passes.
func process(ctx context.Context, st *store.SQLite, pl pipeline.Pipeline,
	it store.WorkItem, maxAttempts int, base time.Duration) {

	stg, ok := pl[it.Stage]
	if !ok {
		_ = st.Fail(ctx, it.ID, maxAttempts, base)
		return
	}
	host, err := st.Host(ctx, it.IP)
	if err != nil || host == nil {
		_ = st.Fail(ctx, it.ID, maxAttempts, base)
		return
	}
	if err := stg.Enricher.Enrich(ctx, host); err != nil {
		_ = st.Fail(ctx, it.ID, maxAttempts, base)
		return
	}
	host.Attempts = it.Attempts
	if err := st.Complete(ctx, it.ID, host); err != nil {
		fmt.Fprintf(os.Stderr, "[!] complete %s: %v\n", it.IP, err)
		return
	}
	for _, e := range stg.Next {
		if e.When == nil || e.When(host) {
			_ = st.Reschedule(ctx, it.IP, e.To)
		}
	}
}

// loadPipeline returns the built-in pipeline, or one parsed from a YAML file.
func loadPipeline(path string, timeout time.Duration) (pipeline.Pipeline, error) {
	if path == "" {
		return pipeline.Default(timeout), nil
	}
	return pipeline.LoadFile(path, timeout)
}

func writeHeartbeat(ctx context.Context, st *store.SQLite, counter int64) {
	_ = st.Heartbeat(ctx, store.RunStat{
		Tool:      "ns-enrich",
		PID:       os.Getpid(),
		Counter:   counter,
		UpdatedAt: time.Now().UTC(),
	})
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ns-enrich: "+format+"\n", args...)
	os.Exit(1)
}
