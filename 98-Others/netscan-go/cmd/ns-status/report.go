package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"netscan/internal/fmtx"
	"netscan/internal/model"
	"netscan/internal/store"
)

// printReport writes a complete, plain-text diagnostic of a scan db: an overview,
// queue health, a per-host table, findings, and auto-detected anomalies. It reads
// only, so it works mid-scan (WAL) as well as after.
func printReport(ctx context.Context, st *store.SQLite, db string) {
	sm, err := st.Summary(ctx)
	if err != nil {
		reportFatal("summary: %v", err)
	}
	hosts, err := st.AllHosts(ctx)
	if err != nil {
		reportFatal("hosts: %v", err)
	}
	failed, err := st.FailedItems(ctx)
	if err != nil {
		reportFatal("work: %v", err)
	}
	started := readStarted(ctx, st)
	ingestState, _ := st.GetMeta(ctx, store.MetaIngestState)

	w := os.Stdout
	fmt.Fprintf(w, "===== netscan report · %s · %s =====\n\n", db, time.Now().Format("2006-01-02 15:04:05"))

	// 1. Overview
	fmt.Fprintln(w, "## overview")
	if !started.IsZero() {
		fmt.Fprintf(w, "  elapsed        %s\n", fmtx.Duration(time.Since(started)))
	}
	if ingestState == "" {
		ingestState = "(unset)"
	}
	fmt.Fprintf(w, "  ingest.state   %s\n", ingestState)
	fmt.Fprintf(w, "  hosts          %d\n", sm.Hosts)
	for _, tool := range []string{"ns-discover", "ns-ingest", "ns-enrich"} {
		if r, ok := findRun(sm.Runs, tool); ok {
			line := fmt.Sprintf("  %-14s counter=%d", tool, r.Counter)
			if r.Total > 0 {
				line += fmt.Sprintf(" total=%d", r.Total)
			}
			if r.Note != "" {
				line += " · " + r.Note
			}
			fmt.Fprintln(w, line)
		}
	}

	// 2. Queue health
	fmt.Fprintln(w, "\n## queue (stage × state)")
	stages := sortedKeys(sm.QueueByStage)
	for _, stg := range stages {
		var parts []string
		for _, state := range []string{store.StatePending, store.StateLeased, store.StateDone, store.StateFailed} {
			if n := sm.QueueByStage[stg][state]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", state, n))
			}
		}
		fmt.Fprintf(w, "  %-9s %s\n", stg, strings.Join(parts, " "))
	}
	var failedItems, leasedItems []store.WorkItem
	for _, it := range failed {
		if it.State == store.StateFailed {
			failedItems = append(failedItems, it)
		} else {
			leasedItems = append(leasedItems, it)
		}
	}
	fmt.Fprintf(w, "  failed=%d  leased(in-flight/stuck)=%d\n", len(failedItems), len(leasedItems))
	for i, it := range failedItems {
		if i >= 40 {
			fmt.Fprintf(w, "    … +%d more failed\n", len(failedItems)-40)
			break
		}
		fmt.Fprintf(w, "    FAILED %s stage=%s attempts=%d\n", it.IP, it.Stage, it.Attempts)
	}

	// 3. Hosts
	withPorts, pingOnly := splitHosts(hosts)
	fmt.Fprintf(w, "\n## hosts: %d total · %d with ports · %d ping-only\n", len(hosts), len(withPorts), len(pingOnly))
	for _, h := range withPorts {
		fmt.Fprintf(w, "  %-15s ports=%s proto=%s services=%s stages=%s%s\n",
			h.IP, portsList(h.OpenPorts), hostProtos(h), hostServices(h), hostStages(h), ptrGeo(h))
	}
	if len(pingOnly) > 0 {
		fmt.Fprintf(w, "  ping-only (%d): %s\n", len(pingOnly), ipSample(pingOnly, 20))
	}

	// 4. Findings
	fmt.Fprintln(w, "\n## findings")
	if len(sm.TopPorts) > 0 {
		var b strings.Builder
		for i, p := range sm.TopPorts {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%d(%d)", p.Port, p.Count)
		}
		fmt.Fprintf(w, "  ports    %s\n", b.String())
	}
	if len(sm.Protocols) > 0 {
		fmt.Fprintf(w, "  proto    %s\n", labelList(sm.Protocols))
	}
	fmt.Fprintf(w, "  web      %d srv · tls %d (%d expired, %d weak) · crawl %d sensitive\n",
		sm.WebServers, sm.TLSPorts, sm.TLSExpired, sm.TLSWeak, sm.SensitivePaths)
	if len(sm.Countries) > 0 {
		fmt.Fprintf(w, "  geo      %s\n", labelList(sm.Countries))
	}

	// 5. Anomalies + observed enrichment errors
	an := anomalies(hosts, failedItems)
	fmt.Fprintf(w, "\n## anomalies (%d)\n", len(an))
	for _, a := range an {
		fmt.Fprintf(w, "  ! %s\n", a)
	}
	if errs := observedErrors(hosts); len(errs) > 0 {
		fmt.Fprintf(w, "\n## observed enrichment errors (%d, data — not necessarily bugs)\n", len(errs))
		for i, e := range errs {
			if i >= 30 {
				fmt.Fprintf(w, "  … +%d more\n", len(errs)-30)
				break
			}
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

// anomalies flags genuine tool/logic issues (not host-side data errors).
func anomalies(hosts []*model.HostRecord, failed []store.WorkItem) []string {
	var out []string
	for _, it := range failed {
		out = append(out, fmt.Sprintf("failed work item: %s stage=%s attempts=%d", it.IP, it.Stage, it.Attempts))
	}
	empty := 0
	for _, h := range hosts {
		if len(h.OpenPorts) == 0 {
			empty++
			continue
		}
		// Open ports with no classification (detect never produced data for them).
		for _, p := range h.OpenPorts {
			if h.Ports == nil || h.Ports[p] == nil {
				out = append(out, fmt.Sprintf("unclassified open port %s:%d (in open_ports but no detect data)", h.IP, p))
			}
		}
		// Stage gaps: only meaningful once detect ran for the host.
		if !statusHas(h, model.StageDetect) {
			out = append(out, fmt.Sprintf("host with ports but detect not done: %s", h.IP))
			continue
		}
		hasWeb, hasTLS := false, false
		for _, pi := range h.Ports {
			if pi == nil {
				continue
			}
			if pi.Protocol == model.ProtoHTTP || pi.Protocol == model.ProtoHTTPS {
				hasWeb = true
			}
			if pi.Protocol == model.ProtoHTTPS || pi.TLS != nil || pi.TLSDeep != nil {
				hasTLS = true
			}
		}
		if hasWeb && !statusHas(h, model.StageWebinfo) {
			out = append(out, fmt.Sprintf("gap: %s has a web port but webinfo not done", h.IP))
		}
		if hasTLS && !statusHas(h, model.StageTLSDeep) {
			out = append(out, fmt.Sprintf("gap: %s has TLS but tls-deep not done", h.IP))
		}
	}
	if empty > 0 {
		out = append(out, fmt.Sprintf("%d ping-only host(s) with no open ports (expected if serviceless or pending deep scan)", empty))
	}
	return out
}

// observedErrors lists host-side enrichment errors (web/tls) — informational.
func observedErrors(hosts []*model.HostRecord) []string {
	var out []string
	for _, h := range hosts {
		ports := make([]uint16, 0, len(h.Ports))
		for p := range h.Ports {
			ports = append(ports, p)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		for _, p := range ports {
			pi := h.Ports[p]
			if pi.HTTP != nil && pi.HTTP.Error != "" {
				out = append(out, fmt.Sprintf("%s:%d http: %s", h.IP, p, pi.HTTP.Error))
			}
			if pi.TLS != nil && pi.TLS.Error != "" {
				out = append(out, fmt.Sprintf("%s:%d tls: %s", h.IP, p, pi.TLS.Error))
			}
			if pi.TLSDeep != nil && pi.TLSDeep.Error != "" {
				out = append(out, fmt.Sprintf("%s:%d tls-deep: %s", h.IP, p, pi.TLSDeep.Error))
			}
		}
	}
	return out
}

// printDiff compares db (open st) against another scan db, listing host/port
// differences — the false-negative check (e.g. SYN vs connect).
func printDiff(ctx context.Context, st *store.SQLite, dbA, dbBPath string) {
	stB, err := store.Open(dbBPath)
	if err != nil {
		reportFatal("open %s: %v", dbBPath, err)
	}
	defer stB.Close()

	a, err := st.AllHosts(ctx)
	if err != nil {
		reportFatal("hosts A: %v", err)
	}
	b, err := stB.AllHosts(ctx)
	if err != nil {
		reportFatal("hosts B: %v", err)
	}
	pa, pb := portMap(a), portMap(b)

	w := os.Stdout
	fmt.Fprintf(w, "===== netscan diff · A=%s · B=%s =====\n", dbA, dbBPath)
	fmt.Fprintf(w, "A: %d hosts · B: %d hosts\n\n", len(pa), len(pb))

	onlyA, onlyB := diffKeys(pa, pb)
	fmt.Fprintf(w, "## hosts only in A (%d)\n", len(onlyA))
	for _, ip := range onlyA {
		fmt.Fprintf(w, "  A-only %s ports=%s\n", ip, portsList(pa[ip]))
	}
	fmt.Fprintf(w, "\n## hosts only in B (%d)\n", len(onlyB))
	for _, ip := range onlyB {
		fmt.Fprintf(w, "  B-only %s ports=%s\n", ip, portsList(pb[ip]))
	}

	// Per-host port differences among common hosts.
	fmt.Fprintln(w, "\n## port differences (common hosts)")
	common := commonKeys(pa, pb)
	diffs := 0
	for _, ip := range common {
		extraA := portsMinus(pa[ip], pb[ip])
		extraB := portsMinus(pb[ip], pa[ip])
		if len(extraA) == 0 && len(extraB) == 0 {
			continue
		}
		diffs++
		fmt.Fprintf(w, "  %s  A-only=%s  B-only=%s\n", ip, portsList(extraA), portsList(extraB))
	}
	if diffs == 0 {
		fmt.Fprintln(w, "  (none — common hosts have identical ports)")
	}
}

// ---- helpers ----------------------------------------------------------------

func splitHosts(hosts []*model.HostRecord) (withPorts, pingOnly []*model.HostRecord) {
	for _, h := range hosts {
		if len(h.OpenPorts) > 0 {
			withPorts = append(withPorts, h)
		} else {
			pingOnly = append(pingOnly, h)
		}
	}
	return
}

func statusHas(h *model.HostRecord, stage string) bool {
	_, ok := h.Status[stage]
	return ok
}

func hostProtos(h *model.HostRecord) string {
	var ps []string
	for _, p := range h.OpenPorts {
		if pi := h.Ports[p]; pi != nil && pi.Protocol != "" {
			ps = append(ps, pi.Protocol)
		}
	}
	if len(ps) == 0 {
		return "-"
	}
	return strings.Join(ps, ",")
}

func hostServices(h *model.HostRecord) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range h.OpenPorts {
		pi := h.Ports[p]
		if pi == nil {
			continue
		}
		for _, s := range pi.Services {
			id := s.Product
			if s.Version != "" {
				id += "/" + s.Version
			}
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

func hostStages(h *model.HostRecord) string {
	if len(h.Status) == 0 {
		return "-"
	}
	ks := make([]string, 0, len(h.Status))
	for k := range h.Status {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func ptrGeo(h *model.HostRecord) string {
	var extra []string
	if len(h.PTR) > 0 {
		extra = append(extra, h.PTR[0])
	}
	if h.Geo != nil && h.Geo.Country != "" {
		g := h.Geo.Country
		if h.Geo.ASN != 0 {
			g += fmt.Sprintf("/AS%d", h.Geo.ASN)
		}
		extra = append(extra, g)
	}
	if len(extra) == 0 {
		return ""
	}
	return " " + strings.Join(extra, " ")
}

func labelList(ls []store.LabelCount) string {
	parts := make([]string, len(ls))
	for i, l := range ls {
		parts[i] = fmt.Sprintf("%s %d", l.Label, l.Count)
	}
	return strings.Join(parts, " · ")
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func ipSample(hosts []*model.HostRecord, n int) string {
	var out []string
	for i, h := range hosts {
		if i >= n {
			out = append(out, fmt.Sprintf("… +%d", len(hosts)-n))
			break
		}
		out = append(out, h.IP.String())
	}
	return strings.Join(out, " ")
}

func portMap(hosts []*model.HostRecord) map[string][]uint16 {
	m := make(map[string][]uint16, len(hosts))
	for _, h := range hosts {
		m[h.IP.String()] = h.OpenPorts
	}
	return m
}

func diffKeys(a, b map[string][]uint16) (onlyA, onlyB []string) {
	for k := range a {
		if _, ok := b[k]; !ok {
			onlyA = append(onlyA, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return
}

func commonKeys(a, b map[string][]uint16) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// portsMinus returns ports in x not in y.
func portsMinus(x, y []uint16) []uint16 {
	yset := make(map[uint16]bool, len(y))
	for _, p := range y {
		yset[p] = true
	}
	var out []uint16
	for _, p := range x {
		if !yset[p] {
			out = append(out, p)
		}
	}
	return out
}

func reportFatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ns-status: "+format+"\n", args...)
	os.Exit(1)
}

// (kept for symmetry with the numeric formatting used elsewhere)
var _ = strconv.Itoa
