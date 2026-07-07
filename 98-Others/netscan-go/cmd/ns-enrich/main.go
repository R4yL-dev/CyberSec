// Command ns-enrich is a domain-B worker: it claims hosts from the queue for a
// given stage, runs the corresponding enrichment palier, and writes the results
// back — completing the item, or rescheduling it with backoff on failure. This
// is also where "backward" work (re-arming an earlier stage) would be scheduled.
//
// Example:
//
//	ns-enrich --db scan.db --stage light --workers 50
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"netscan/internal/enrich"
	"netscan/internal/model"
	"netscan/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	stage := flag.String("stage", model.StageLight, "queue stage to drain")
	workers := flag.Int("workers", 50, "concurrent enrichment workers")
	timeout := flag.Duration("timeout", 10*time.Second, "per-probe timeout")
	maxAttempts := flag.Int("max-attempts", 5, "attempts before dead-lettering")
	lease := flag.Duration("lease", 2*time.Minute, "work item lease duration")
	backoff := flag.Duration("backoff", 5*time.Second, "base retry backoff")
	drain := flag.Bool("drain", false, "exit once the queue is empty instead of polling")
	flag.Parse()
	if *dbPath == "" {
		fatal("--db is required")
	}

	enricher, err := newEnricher(*stage, *timeout)
	if err != nil {
		fatal("%v", err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var processed int64
	itemCh := make(chan store.WorkItem, *workers)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range itemCh {
				process(ctx, st, enricher, it, *maxAttempts, *backoff)
				atomic.AddInt64(&processed, 1)
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "[*] ns-enrich stage=%s workers=%d (drain=%v)\n", *stage, *workers, *drain)
	dispatch(ctx, st, itemCh, *stage, *workers, *lease, *drain, &processed)

	close(itemCh)
	wg.Wait()
	writeHeartbeat(context.Background(), st, *stage, atomic.LoadInt64(&processed))
	fmt.Fprintf(os.Stderr, "[+] enriched %d host(s)\n", atomic.LoadInt64(&processed))
}

// dispatch claims batches of work and feeds them to the worker pool until the
// context is cancelled or (in drain mode) the queue is empty.
func dispatch(ctx context.Context, st *store.SQLite, itemCh chan<- store.WorkItem,
	stage string, batch int, lease time.Duration, drain bool, processed *int64) {

	lastHB := time.Now()
	for ctx.Err() == nil {
		items, err := st.Claim(ctx, stage, batch, lease)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] claim: %v\n", err)
			return
		}
		if len(items) == 0 {
			if drain {
				return
			}
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}
		for _, it := range items {
			select {
			case itemCh <- it:
			case <-ctx.Done():
				return
			}
		}
		if time.Since(lastHB) > 2*time.Second {
			writeHeartbeat(ctx, st, stage, atomic.LoadInt64(processed))
			lastHB = time.Now()
		}
	}
}

func process(ctx context.Context, st *store.SQLite, en enrich.Enricher,
	it store.WorkItem, maxAttempts int, base time.Duration) {

	host, err := st.Host(ctx, it.IP)
	if err != nil || host == nil {
		_ = st.Fail(ctx, it.ID, maxAttempts, base)
		return
	}
	if err := en.Enrich(ctx, host); err != nil {
		_ = st.Fail(ctx, it.ID, maxAttempts, base)
		return
	}
	host.Attempts = it.Attempts
	if err := st.Complete(ctx, it.ID, host); err != nil {
		fmt.Fprintf(os.Stderr, "[!] complete %s: %v\n", it.IP, err)
	}
}

func newEnricher(stage string, timeout time.Duration) (enrich.Enricher, error) {
	switch stage {
	case model.StageLight:
		return enrich.NewLight(timeout), nil
	default:
		return nil, fmt.Errorf("unknown stage %q (v1 supports %q)", stage, model.StageLight)
	}
}

func writeHeartbeat(ctx context.Context, st *store.SQLite, stage string, counter int64) {
	_ = st.Heartbeat(ctx, store.RunStat{
		Tool:      "ns-enrich",
		PID:       os.Getpid(),
		Counter:   counter,
		Note:      "stage=" + stage,
		UpdatedAt: time.Now().UTC(),
	})
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ns-enrich: "+format+"\n", args...)
	os.Exit(1)
}
