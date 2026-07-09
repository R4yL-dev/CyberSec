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

	if err := s.Ingest(ctx, rec("1.1.1.1", 80, 443), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	items, err := s.Claim(ctx, model.StageDetect, 10, time.Second)
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
	if err := s.Ingest(ctx, rec("9.9.9.9", 80), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, rec("9.9.9.9", 443), model.StageDetect, nil); err != nil {
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

func TestGeoPersistedAndPreserved(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ip := netip.MustParseAddr("1.1.1.1")

	geo := &model.GeoInfo{Country: "US", ASN: 13335, Org: "Cloudflare"}
	if err := s.Ingest(ctx, rec("1.1.1.1", 443), model.StageDetect, geo); err != nil {
		t.Fatal(err)
	}
	// Re-ingest without geo must NOT wipe it (set once at first insert).
	if err := s.Ingest(ctx, rec("1.1.1.1", 80), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	// An enrichment Complete must preserve geo too.
	items, _ := s.Claim(ctx, model.StageDetect, 1, time.Second)
	h, _ := s.Host(ctx, ip)
	s.Complete(ctx, items[0].ID, h)

	got, _ := s.Host(ctx, ip)
	if got.Geo == nil || got.Geo.Country != "US" || got.Geo.ASN != 13335 || got.Geo.Org != "Cloudflare" {
		t.Fatalf("geo lost/altered: %+v", got.Geo)
	}
}

func TestDedupPending(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	for i := 0; i < 3; i++ {
		if err := s.Ingest(ctx, rec("2.2.2.2", 80), model.StageDetect, nil); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.Claim(ctx, model.StageDetect, 10, time.Second)
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

	s.Ingest(ctx, rec("3.3.3.3", 443), model.StageDetect, nil)
	items, _ := s.Claim(ctx, model.StageDetect, 10, time.Second)

	h, _ := s.Host(ctx, items[0].IP)
	h.Ports = map[uint16]*model.PortInfo{443: {Port: 443, HTTP: &model.HTTPInfo{Status: 200}}}
	h.Status = map[string]string{model.StageDetect: "ok"}
	if err := s.Complete(ctx, items[0].ID, h); err != nil {
		t.Fatal(err)
	}

	again, _ := s.Claim(ctx, model.StageDetect, 10, time.Second)
	if len(again) != 0 {
		t.Fatalf("completed item was re-claimed: %d", len(again))
	}

	got, _ := s.Host(ctx, netip.MustParseAddr("3.3.3.3"))
	if got.Ports[443] == nil || got.Ports[443].HTTP.Status != 200 {
		t.Fatalf("enrichment not persisted: %+v", got.Ports)
	}
	if got.Status[model.StageDetect] != "ok" {
		t.Fatalf("status not persisted: %v", got.Status)
	}
}

func TestFailBackoffThenDeadLetter(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	const maxAttempts = 2

	s.Ingest(ctx, rec("4.4.4.4", 80), model.StageDetect, nil)

	// attempt 1 -> fail -> still pending (attempts 1 < max)
	items, _ := s.Claim(ctx, model.StageDetect, 1, time.Second)
	if err := s.Fail(ctx, items[0].ID, maxAttempts, 0); err != nil {
		t.Fatal(err)
	}
	// attempt 2 -> fail -> dead-lettered (attempts 2 >= max)
	items, _ = s.Claim(ctx, model.StageDetect, 1, time.Second)
	if len(items) != 1 || items[0].Attempts != 2 {
		t.Fatalf("expected re-claim as attempt 2, got %+v", items)
	}
	if err := s.Fail(ctx, items[0].ID, maxAttempts, 0); err != nil {
		t.Fatal(err)
	}

	if again, _ := s.Claim(ctx, model.StageDetect, 1, time.Second); len(again) != 0 {
		t.Fatalf("dead-lettered item was re-claimed: %d", len(again))
	}
	st, _ := s.Summary(ctx)
	if st.WorkByState[StateFailed] != 1 {
		t.Fatalf("want 1 failed item, got %v", st.WorkByState)
	}
}

// completeWith claims the single pending detect item and completes it with h,
// persisting h's enrichment (Ports/Status/…) — used to seed Summary aggregations.
func completeWith(t *testing.T, s *SQLite, h *model.HostRecord) {
	t.Helper()
	ctx := context.Background()
	items, err := s.Claim(ctx, model.StageDetect, 1, time.Second)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim: %d items, err=%v", len(items), err)
	}
	if err := s.Complete(ctx, items[0].ID, h); err != nil {
		t.Fatalf("complete: %v", err)
	}
}

func TestSummaryFindings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	// Host A: web (80+443), an expired cert + weak-TLS warning, a sensitive path, FR.
	if err := s.Ingest(ctx, rec("1.1.1.1", 80, 443), model.StageDetect, &model.GeoInfo{Country: "FR"}); err != nil {
		t.Fatal(err)
	}
	completeWith(t, s, &model.HostRecord{
		IP: netip.MustParseAddr("1.1.1.1"),
		Ports: map[uint16]*model.PortInfo{
			80: {Port: 80, Protocol: "http", HTTP: &model.HTTPInfo{URL: "http://1.1.1.1", Server: "nginx"},
				Crawl: &model.CrawlInfo{Paths: []model.FoundPath{{Path: "/.git/config", Status: 200, Category: "sensitive"}}}},
			443: {Port: 443, Protocol: "https", HTTP: &model.HTTPInfo{URL: "https://1.1.1.1"},
				TLSDeep: &model.TLSDeepInfo{Chain: []model.CertSummary{{SubjectCN: "x", Expired: true}}, Warnings: []string{"TLS 1.0 enabled"}}},
		},
		Status: map[string]string{"detect": "ok", "webinfo": "ok", "crawl": "ok", "tls-deep": "ok"},
	})

	// Host B: ssh only, US.
	if err := s.Ingest(ctx, rec("2.2.2.2", 22), model.StageDetect, &model.GeoInfo{Country: "US"}); err != nil {
		t.Fatal(err)
	}
	completeWith(t, s, &model.HostRecord{
		IP:     netip.MustParseAddr("2.2.2.2"),
		Ports:  map[uint16]*model.PortInfo{22: {Port: 22, Protocol: "ssh", Banner: "OpenSSH_8.9"}},
		Status: map[string]string{"detect": "ok"},
	})

	sm, err := s.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if sm.Hosts != 2 {
		t.Fatalf("hosts=%d, want 2", sm.Hosts)
	}
	if len(sm.TopPorts) != 3 { // 22, 80, 443 each on one host
		t.Fatalf("top ports=%v, want 3 distinct", sm.TopPorts)
	}
	proto := map[string]int64{}
	for _, p := range sm.Protocols {
		proto[p.Label] = p.Count
	}
	if proto["http"] != 1 || proto["https"] != 1 || proto["ssh"] != 1 {
		t.Fatalf("protocols=%v", sm.Protocols)
	}
	if sm.WebServers != 2 { // 80 and 443 both carry an HTTP response
		t.Fatalf("web servers=%d, want 2", sm.WebServers)
	}
	if sm.TLSPorts != 1 {
		t.Fatalf("tls ports=%d, want 1", sm.TLSPorts)
	}
	if sm.TLSExpired != 1 {
		t.Fatalf("tls expired=%d, want 1", sm.TLSExpired)
	}
	if sm.TLSWeak != 1 {
		t.Fatalf("tls weak=%d, want 1", sm.TLSWeak)
	}
	if sm.SensitivePaths != 1 {
		t.Fatalf("sensitive paths=%d, want 1", sm.SensitivePaths)
	}
	if sm.StageCoverage["detect"] != 2 || sm.StageCoverage["webinfo"] != 1 {
		t.Fatalf("stage coverage=%v", sm.StageCoverage)
	}
	cc := map[string]int64{}
	for _, c := range sm.Countries {
		cc[c.Label] = c.Count
	}
	if cc["FR"] != 1 || cc["US"] != 1 {
		t.Fatalf("countries=%v", sm.Countries)
	}
	if sm.QueueByStage["detect"][StateDone] != 2 {
		t.Fatalf("queue detect done=%v, want 2", sm.QueueByStage["detect"])
	}
}

func TestLiveBlocksAndPortlessIngest(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	// Two hosts in 1.2.3.0/24 (with ports), one in 5.6.7.0/24, and a portless
	// (ICMP-alive) host in 9.9.9.0/24.
	if err := s.Ingest(ctx, rec("1.2.3.10", 80), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, rec("1.2.3.20", 443), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, rec("5.6.7.8", 22), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}
	// Portless liveness record: no open ports.
	if err := s.Ingest(ctx, rec("9.9.9.9"), model.StageDetect, nil); err != nil {
		t.Fatal(err)
	}

	// Portless record must NOT enqueue a detect work item, but the others must.
	items, _ := s.Claim(ctx, model.StageDetect, 10, time.Second)
	if len(items) != 3 {
		t.Fatalf("claimed %d detect items, want 3 (portless host must not enqueue)", len(items))
	}
	for _, it := range items {
		if it.IP.String() == "9.9.9.9" {
			t.Fatal("portless ICMP host was enqueued for enrichment")
		}
	}

	// /24 blocks with >= 2 hosts → only 1.2.3.0/24.
	blocks2, err := s.LiveBlocks(ctx, 24, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks2) != 1 || blocks2[0].String() != "1.2.3.0/24" {
		t.Fatalf("LiveBlocks(24,2) = %v, want [1.2.3.0/24]", blocks2)
	}

	// Summary must not choke on portless hosts (open_ports "[]", or legacy "null").
	if _, err := s.w.ExecContext(ctx, `UPDATE hosts SET open_ports='null' WHERE ip='9.9.9.9'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Summary(ctx); err != nil {
		t.Fatalf("Summary on a portless/null-open_ports host: %v", err)
	}

	// /24 blocks with >= 1 host → all three, sorted (portless host counts too).
	blocks1, err := s.LiveBlocks(ctx, 24, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, b := range blocks1 {
		got = append(got, b.String())
	}
	want := []string{"1.2.3.0/24", "5.6.7.0/24", "9.9.9.0/24"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("LiveBlocks(24,1) = %v, want %v", got, want)
	}
}

// TestReingestEnqueuesOnlyOnNewPorts: a later discovery pass (widen/deep) or the
// ICMP sweep re-reporting a host with the same ports must NOT re-enqueue detect;
// only genuinely new ports should.
func TestReingestEnqueuesOnlyOnNewPorts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ip := netip.MustParseAddr("7.7.7.7")

	// First sighting with a port → enqueues detect; run it to completion.
	s.Ingest(ctx, rec("7.7.7.7", 80), model.StageDetect, nil)
	items, _ := s.Claim(ctx, model.StageDetect, 10, time.Second)
	if len(items) != 1 {
		t.Fatalf("first ingest: %d detect item(s), want 1", len(items))
	}
	h, _ := s.Host(ctx, ip)
	s.Complete(ctx, items[0].ID, h)

	// Re-report the SAME port (another pass / the ICMP sweep) → no new detect.
	s.Ingest(ctx, rec("7.7.7.7", 80), model.StageDetect, nil)
	if again, _ := s.Claim(ctx, model.StageDetect, 10, time.Second); len(again) != 0 {
		t.Fatalf("re-ingest, same ports: %d detect item(s), want 0", len(again))
	}

	// Re-report with a NEW port (the deep sweep found one) → enqueues detect.
	s.Ingest(ctx, rec("7.7.7.7", 443), model.StageDetect, nil)
	if again, _ := s.Claim(ctx, model.StageDetect, 10, time.Second); len(again) != 1 {
		t.Fatalf("re-ingest, new port: %d detect item(s), want 1", len(again))
	}
}

func TestLeaseExpiryReclaim(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	s.Ingest(ctx, rec("5.5.5.5", 80), model.StageDetect, nil)
	// Claim with a tiny lease; simulate a crashed worker that never completes.
	if items, _ := s.Claim(ctx, model.StageDetect, 1, time.Millisecond); len(items) != 1 {
		t.Fatalf("first claim failed: %d", len(items))
	}
	// Before expiry, not claimable.
	if items, _ := s.Claim(ctx, model.StageDetect, 1, time.Second); len(items) != 0 {
		t.Fatalf("leased item claimed before expiry: %d", len(items))
	}
	time.Sleep(15 * time.Millisecond)
	// After expiry, reclaimable as a new attempt.
	items, _ := s.Claim(ctx, model.StageDetect, 1, time.Second)
	if len(items) != 1 || items[0].Attempts != 2 {
		t.Fatalf("expired lease not reclaimed as attempt 2: %+v", items)
	}
}

func TestReschedule(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ip := netip.MustParseAddr("6.6.6.6")

	s.Ingest(ctx, rec("6.6.6.6", 80), model.StageDetect, nil)
	items, _ := s.Claim(ctx, model.StageDetect, 1, time.Second)
	h, _ := s.Host(ctx, ip)
	s.Complete(ctx, items[0].ID, h)

	// Backward: re-arm the host for the same stage.
	if err := s.Reschedule(ctx, ip, model.StageDetect); err != nil {
		t.Fatal(err)
	}
	again, _ := s.Claim(ctx, model.StageDetect, 1, time.Second)
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
	st, err := s.Summary(ctx)
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

// TestConcurrentProcessesNoLock reproduces the cross-process write contention
// that a single-connection test misses: two store handles (like ns-ingest and
// ns-enrich) hammering writes on the same file. Ingest's read-then-write union
// must not fail with SQLITE_BUSY (requires the writer's BEGIN IMMEDIATE).
func TestConcurrentProcessesNoLock(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 400)
	for i := 0; i < 100; i++ {
		ip := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		wg.Add(1)
		go func() {
			defer wg.Done()
			// "process 1": the union path (SELECT + INSERT in one write tx), twice.
			for _, port := range []uint16{80, 443} {
				if err := s1.Ingest(ctx, model.WireRecord{IP: ip, OpenPorts: []uint16{port}, DiscoveredAt: time.Now()}, model.StageDetect, nil); err != nil {
					errCh <- err
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			// "process 2": concurrent claims + completes.
			items, err := s2.Claim(ctx, model.StageDetect, 5, time.Second)
			if err != nil {
				errCh <- err
				return
			}
			for _, it := range items {
				if h, err := s2.Host(ctx, it.IP); err != nil {
					errCh <- err
				} else if h != nil {
					if err := s2.Complete(ctx, it.ID, h); err != nil {
						errCh <- err
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent op failed (database locked?): %v", err)
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
			if err := s.Ingest(ctx, model.WireRecord{IP: ip, OpenPorts: []uint16{80}, DiscoveredAt: time.Now()}, model.StageDetect, nil); err != nil {
				errCh <- err
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Claim(ctx, model.StageDetect, 4, time.Second); err != nil {
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
