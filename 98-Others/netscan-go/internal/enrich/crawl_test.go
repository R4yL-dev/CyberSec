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
