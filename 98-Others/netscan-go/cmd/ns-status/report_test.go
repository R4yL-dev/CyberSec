package main

import (
	"net/netip"
	"strings"
	"testing"

	"netscan/internal/model"
	"netscan/internal/store"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestAnomalies(t *testing.T) {
	hosts := []*model.HostRecord{
		// OK host: web port, all stages done → no anomaly.
		{
			IP:        mustAddr("1.1.1.1"),
			OpenPorts: []uint16{80},
			Ports:     map[uint16]*model.PortInfo{80: {Port: 80, Protocol: model.ProtoHTTP, HTTP: &model.HTTPInfo{}}},
			Status:    map[string]string{"detect": "ok", "webinfo": "ok", "crawl": "ok", "ptr": "ok"},
		},
		// Gap: web port, detect done, but webinfo NOT done.
		{
			IP:        mustAddr("2.2.2.2"),
			OpenPorts: []uint16{80},
			Ports:     map[uint16]*model.PortInfo{80: {Port: 80, Protocol: model.ProtoHTTP}},
			Status:    map[string]string{"detect": "ok"},
		},
		// Unclassified: open port not present in Ports.
		{
			IP:        mustAddr("3.3.3.3"),
			OpenPorts: []uint16{22},
			Ports:     map[uint16]*model.PortInfo{},
			Status:    map[string]string{"detect": "ok"},
		},
		// Ping-only: no ports.
		{IP: mustAddr("4.4.4.4"), OpenPorts: nil},
	}
	failed := []store.WorkItem{{IP: mustAddr("2.2.2.2"), Stage: "tls-deep", State: store.StateFailed, Attempts: 5}}

	got := strings.Join(anomalies(hosts, failed), "\n")

	wantContains := []string{
		"failed work item: 2.2.2.2 stage=tls-deep",
		"gap: 2.2.2.2 has a web port but webinfo not done",
		"unclassified open port 3.3.3.3:22",
		"1 ping-only host(s)",
	}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Errorf("anomalies missing %q\n--- got ---\n%s", w, got)
		}
	}
	// The healthy host must NOT appear.
	if strings.Contains(got, "1.1.1.1") {
		t.Errorf("healthy host flagged as anomaly:\n%s", got)
	}
}

func TestPortsMinusAndDiffKeys(t *testing.T) {
	if got := portsMinus([]uint16{80, 443, 9999}, []uint16{80, 443}); len(got) != 1 || got[0] != 9999 {
		t.Fatalf("portsMinus = %v, want [9999]", got)
	}
	a := map[string][]uint16{"1.1.1.1": {80}, "2.2.2.2": {443}}
	b := map[string][]uint16{"2.2.2.2": {443}, "3.3.3.3": {22}}
	onlyA, onlyB := diffKeys(a, b)
	if len(onlyA) != 1 || onlyA[0] != "1.1.1.1" {
		t.Fatalf("onlyA = %v, want [1.1.1.1]", onlyA)
	}
	if len(onlyB) != 1 || onlyB[0] != "3.3.3.3" {
		t.Fatalf("onlyB = %v, want [3.3.3.3]", onlyB)
	}
	if common := commonKeys(a, b); len(common) != 1 || common[0] != "2.2.2.2" {
		t.Fatalf("commonKeys = %v, want [2.2.2.2]", common)
	}
}
