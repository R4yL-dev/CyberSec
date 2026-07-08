package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"netscan/internal/model"
)

// TestCrawlBlanketResponseFiltered: a server that answers every path with the
// same 403 (like Cloudflare) must yield no "found" paths — the baseline catches it.
func TestCrawlBlanketResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("error 1020"))
	}))
	defer srv.Close()

	ap, _ := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	host := &model.HostRecord{
		IP:        ap.Addr(),
		OpenPorts: []uint16{ap.Port()},
		Ports:     map[uint16]*model.PortInfo{ap.Port(): {Port: ap.Port(), Protocol: model.ProtoHTTP, HTTP: &model.HTTPInfo{Status: 403}}},
	}
	if err := NewCrawl(2*time.Second).Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	if cr := host.Ports[ap.Port()].Crawl; cr != nil && len(cr.Paths) != 0 {
		t.Fatalf("blanket-403 server should yield no found paths, got %+v", cr.Paths)
	}
}

func TestIsHTTPSMisdirect(t *testing.T) {
	yes := &model.HTTPInfo{Status: 400, Title: "400 The plain HTTP request was sent to HTTPS port"}
	no1 := &model.HTTPInfo{Status: 400, Title: "400 Bad Request"}
	no2 := &model.HTTPInfo{Status: 200, Title: "sent to HTTPS port"}
	if !isHTTPSMisdirect(yes) {
		t.Fatal("should detect the HTTPS-misdirect 400")
	}
	if isHTTPSMisdirect(no1) || isHTTPSMisdirect(no2) {
		t.Fatal("false positive on HTTPS-misdirect detection")
	}
}

func TestCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ref: refs/heads/main\n")) // matches the "ref:" signature
	})
	// A catch-all that returns 200 for everything else — the signature guard must
	// stop these soft-hits (e.g. /.env, /server-status) from being reported.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("generic page, nothing to see"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ap, _ := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	host := &model.HostRecord{
		IP:        ap.Addr(),
		OpenPorts: []uint16{ap.Port()},
		Ports: map[uint16]*model.PortInfo{
			ap.Port(): {Port: ap.Port(), Protocol: model.ProtoHTTP, HTTP: &model.HTTPInfo{Status: 200}},
		},
	}

	if err := NewCrawl(2*time.Second).Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	cr := host.Ports[ap.Port()].Crawl
	if cr == nil {
		t.Fatal("no crawl result")
	}

	found := map[string]string{} // path -> category
	for _, p := range cr.Paths {
		found[p.Path] = p.Category
	}
	if found["/robots.txt"] != "well-known" {
		t.Fatalf("robots.txt not found as well-known: %+v", cr.Paths)
	}
	if found["/.git/HEAD"] != "sensitive" {
		t.Fatalf("/.git/HEAD (signature ref:) not found: %+v", cr.Paths)
	}
	// The signature guard must reject the catch-all 200 on /.env (no "=" ... it
	// returns "generic page", which has no '='), /server-status, phpinfo, etc.
	if _, bad := found["/server-status"]; bad {
		t.Fatal("server-status soft-hit should have been rejected by signature guard")
	}
	if len(cr.Methods) == 0 || cr.Methods[0] != "GET" {
		t.Fatalf("OPTIONS methods = %v", cr.Methods)
	}
}
