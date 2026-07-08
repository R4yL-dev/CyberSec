package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"netscan/internal/model"
)

func openTest(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func rec(ip string, ports ...uint16) model.WireRecord {
	return model.WireRecord{
		IP:           netip.MustParseAddr(ip),
		OpenPorts:    ports,
		DiscoveredAt: time.Now().UTC(),
	}
}

func TestIngestClaimHost(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if err := s.Ingest(ctx, rec("1.1.1.1", 80, 443), model.StageLight); err != nil {
		t.Fatal(err)
	}
	items, err := s.Claim(ctx, model.StageLight, 10, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("claimed %d items, want 1", len(items))
	}
	if items[0].IP.String() != "1.1.1.1" || items[0].Attempts != 1 {
		t.Fatalf("unexpected item %+v", items[0])
	}

	h, err := s.Host(ctx, netip.MustParseAddr("1.1.1.1"))
	if err != nil || h == nil {
		t.Fatalf("Host: %v, %v", h, err)
	}
	if len(h.OpenPorts) != 2 || h.OpenPorts[0] != 80 {
		t.Fatalf("open ports = %v", h.OpenPorts)
	}
}

func TestIngestUnionsOpenPorts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	// SYN streaming ingests a host's ports in separate records; they must union.
	if err := s.Ingest(ctx, rec("9.9.9.9", 80), model.StageLight); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, rec("9.9.9.9", 443), model.StageLight); err != nil {
		t.Fatal(err)
	}
	h, err := s.Host(ctx, netip.MustParseAddr("9.9.9.9"))
	if err != nil || h == nil {
		t.Fatalf("Host: %v %v", h, err)
	}
	if len(h.OpenPorts) != 2 || h.OpenPorts[0] != 80 || h.OpenPorts[1] != 443 {
		t.Fatalf("open ports = %v, want [80 443]", h.OpenPorts)
	}
}

func TestDedupPending(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	for i := 0; i < 3; i++ {
		if err := s.Ingest(ctx, rec("2.2.2.2", 80), model.StageLight); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.Claim(ctx, model.StageLight, 10, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("dedup failed: claimed %d items, want 1", len(items))
	}
}

func TestCompleteRemovesFromQueue(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	s.Ingest(ctx, rec("3.3.3.3", 443), model.StageLight)
	items, _ := s.Claim(ctx, model.StageLight, 10, time.Second)

	h, _ := s.Host(ctx, items[0].IP)
	h.Ports = map[uint16]*model.PortInfo{443: {Port: 443, HTTP: &model.HTTPInfo{Status: 200}}}
	h.Status = map[string]string{model.StageLight: "ok"}
	if err := s.Complete(ctx, items[0].ID, h); err != nil {
		t.Fatal(err)
	}

	again, _ := s.Claim(ctx, model.StageLight, 10, time.Second)
	if len(again) != 0 {
		t.Fatalf("completed item was re-claimed: %d", len(again))
	}

	got, _ := s.Host(ctx, netip.MustParseAddr("3.3.3.3"))
	if got.Ports[443] == nil || got.Ports[443].HTTP.Status != 200 {
		t.Fatalf("enrichment not persisted: %+v", got.Ports)
	}
	if got.Status[model.StageLight] != "ok" {
		t.Fatalf("status not persisted: %v", got.Status)
	}
}

func TestFailBackoffThenDeadLetter(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	const maxAttempts = 2

	s.Ingest(ctx, rec("4.4.4.4", 80), model.StageLight)

	// attempt 1 -> fail -> still pending (attempts 1 < max)
	items, _ := s.Claim(ctx, model.StageLight, 1, time.Second)
	if err := s.Fail(ctx, items[0].ID, maxAttempts, 0); err != nil {
		t.Fatal(err)
	}
	// attempt 2 -> fail -> dead-lettered (attempts 2 >= max)
	items, _ = s.Claim(ctx, model.StageLight, 1, time.Second)
	if len(items) != 1 || items[0].Attempts != 2 {
		t.Fatalf("expected re-claim as attempt 2, got %+v", items)
	}
	if err := s.Fail(ctx, items[0].ID, maxAttempts, 0); err != nil {
		t.Fatal(err)
	}

	if again, _ := s.Claim(ctx, model.StageLight, 1, time.Second); len(again) != 0 {
		t.Fatalf("dead-lettered item was re-claimed: %d", len(again))
	}
	st, _ := s.Stats(ctx)
	if st.WorkByState[StateFailed] != 1 {
		t.Fatalf("want 1 failed item, got %v", st.WorkByState)
	}
}

func TestLeaseExpiryReclaim(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	s.Ingest(ctx, rec("5.5.5.5", 80), model.StageLight)
	// Claim with a tiny lease; simulate a crashed worker that never completes.
	if items, _ := s.Claim(ctx, model.StageLight, 1, time.Millisecond); len(items) != 1 {
		t.Fatalf("first claim failed: %d", len(items))
	}
	// Before expiry, not claimable.
	if items, _ := s.Claim(ctx, model.StageLight, 1, time.Second); len(items) != 0 {
		t.Fatalf("leased item claimed before expiry: %d", len(items))
	}
	time.Sleep(15 * time.Millisecond)
	// After expiry, reclaimable as a new attempt.
	items, _ := s.Claim(ctx, model.StageLight, 1, time.Second)
	if len(items) != 1 || items[0].Attempts != 2 {
		t.Fatalf("expired lease not reclaimed as attempt 2: %+v", items)
	}
}

func TestReschedule(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ip := netip.MustParseAddr("6.6.6.6")

	s.Ingest(ctx, rec("6.6.6.6", 80), model.StageLight)
	items, _ := s.Claim(ctx, model.StageLight, 1, time.Second)
	h, _ := s.Host(ctx, ip)
	s.Complete(ctx, items[0].ID, h)

	// Backward: re-arm the host for the same stage.
	if err := s.Reschedule(ctx, ip, model.StageLight); err != nil {
		t.Fatal(err)
	}
	again, _ := s.Claim(ctx, model.StageLight, 1, time.Second)
	if len(again) != 1 || again[0].IP != ip {
		t.Fatalf("reschedule did not re-enqueue: %+v", again)
	}
}

func TestMetaAndHeartbeatTotal(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if v, _ := s.GetMeta(ctx, "k"); v != "" {
		t.Fatalf("missing key should be empty, got %q", v)
	}
	if err := s.SetMeta(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetMeta(ctx, "k"); v != "v1" {
		t.Fatalf("got %q, want v1", v)
	}
	if err := s.SetMeta(ctx, "k", "v2"); err != nil { // upsert
		t.Fatal(err)
	}
	if v, _ := s.GetMeta(ctx, "k"); v != "v2" {
		t.Fatalf("got %q, want v2", v)
	}

	// Heartbeat carries counter + total + note, surfaced by Stats.
	if err := s.Heartbeat(ctx, RunStat{
		Tool: "ns-discover", PID: 1, Counter: 42, Total: 1000, Note: "found=3", UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, r := range st.Runs {
		if r.Tool == "ns-discover" {
			seen = true
			if r.Counter != 42 || r.Total != 1000 || r.Note != "found=3" {
				t.Fatalf("run mismatch: %+v", r)
			}
		}
	}
	if !seen {
		t.Fatal("ns-discover run not present in stats")
	}
}

func TestConcurrentIngestClaimNoLock(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			if err := s.Ingest(ctx, model.WireRecord{IP: ip, OpenPorts: []uint16{80}, DiscoveredAt: time.Now()}, model.StageLight); err != nil {
				errCh <- err
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Claim(ctx, model.StageLight, 4, time.Second); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent op failed (database locked?): %v", err)
	}
}
