package model

import (
	"net/netip"
	"testing"
)

// TestMergeNoClobber checks the property that makes concurrent paliers safe:
// merging per-stage updates in either order preserves every field.
func TestMergeNoClobber(t *testing.T) {
	base := func() *HostRecord {
		return &HostRecord{
			IP: netip.MustParseAddr("1.1.1.1"),
			Ports: map[uint16]*PortInfo{
				443: {Port: 443, HTTP: &HTTPInfo{Status: 200}, TLS: &TLSInfo{Version: "TLS 1.3"}},
			},
			Status: map[string]string{"light": "ok"},
		}
	}
	web := base()
	web.Ports[443].Web = &WebInfo{Technologies: []string{"Cloudflare"}}
	web.Status["webinfo"] = "ok"

	deep := base()
	deep.Ports[443].TLSDeep = &TLSDeepInfo{JARM: "abc123"}
	deep.Status["tls-deep"] = "ok"

	crawl := base()
	crawl.Ports[443].Crawl = &CrawlInfo{Paths: []FoundPath{{Path: "/robots.txt", Status: 200}}}
	crawl.Status["crawl"] = "ok"

	ptr := base()
	ptr.PTR = []string{"one.one.one.one"}
	ptr.Status["ptr"] = "ok"

	check := func(t *testing.T, cur *HostRecord) {
		if cur.Ports[443].Web == nil || cur.Ports[443].Web.Technologies[0] != "Cloudflare" {
			t.Fatal("webinfo lost")
		}
		if cur.Ports[443].TLSDeep == nil || cur.Ports[443].TLSDeep.JARM != "abc123" {
			t.Fatal("tls-deep lost")
		}
		if cur.Ports[443].Crawl == nil || len(cur.Ports[443].Crawl.Paths) != 1 {
			t.Fatal("crawl lost")
		}
		if cur.Ports[443].HTTP == nil || cur.Ports[443].TLS == nil {
			t.Fatal("light HTTP/TLS lost")
		}
		if len(cur.PTR) != 1 || cur.PTR[0] != "one.one.one.one" {
			t.Fatal("ptr lost")
		}
		for _, s := range []string{"light", "webinfo", "tls-deep", "ptr"} {
			if cur.Status[s] != "ok" {
				t.Fatalf("status %q lost: %v", s, cur.Status)
			}
		}
	}

	forward := base()
	forward.Merge(web)
	forward.Merge(deep)
	forward.Merge(crawl)
	forward.Merge(ptr)
	check(t, forward)

	reverse := base()
	reverse.Merge(ptr)
	reverse.Merge(crawl)
	reverse.Merge(deep)
	reverse.Merge(web)
	check(t, reverse)
}
