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

// TestLightThenWebinfo drives both paliers against a real local HTTP server,
// covering the network fetch + analysis paths end to end.
func TestLightThenWebinfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Hello</title></head><body>wp-content here</body></html>`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("some-favicon-bytes"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ap, err := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	host := &model.HostRecord{
		IP:        ap.Addr(),
		OpenPorts: []uint16{ap.Port()},
		Ports:     map[uint16]*model.PortInfo{},
	}

	// light
	if err := NewLight(2*time.Second).Enrich(ctx, host); err != nil {
		t.Fatal(err)
	}
	pi := host.Ports[ap.Port()]
	if pi == nil || pi.HTTP == nil || pi.HTTP.Status != 200 {
		t.Fatalf("light HTTP = %+v", pi)
	}
	if pi.HTTP.Server != "nginx/1.25" || pi.HTTP.Title != "Hello" {
		t.Fatalf("light server=%q title=%q", pi.HTTP.Server, pi.HTTP.Title)
	}

	// webinfo (gated in the pipeline by RespondedHTTP, which light now satisfies)
	if err := NewWebinfo(2*time.Second).Enrich(ctx, host); err != nil {
		t.Fatal(err)
	}
	web := host.Ports[ap.Port()].Web
	if web == nil {
		t.Fatal("no webinfo")
	}
	if web.SecurityHeaders["X-Frame-Options"] != "DENY" || web.SecurityHeaders["Strict-Transport-Security"] == "" {
		t.Fatalf("security headers = %v", web.SecurityHeaders)
	}
	techs := map[string]bool{}
	for _, x := range web.Technologies {
		techs[x] = true
	}
	if !techs["nginx"] || !techs["PHP"] || !techs["WordPress"] {
		t.Fatalf("technologies = %v", web.Technologies)
	}
	if web.FaviconHash == "" {
		t.Fatal("favicon hash empty")
	}
	if len(web.Headers) == 0 || len(web.Cookies) == 0 {
		t.Fatalf("headers=%d cookies=%d", len(web.Headers), len(web.Cookies))
	}
}
