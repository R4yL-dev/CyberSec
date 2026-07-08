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

func TestTLSDeep(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ap, err := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	// tls-deep runs on ports where light already saw TLS.
	host := &model.HostRecord{
		IP:        ap.Addr(),
		OpenPorts: []uint16{ap.Port()},
		Ports: map[uint16]*model.PortInfo{
			ap.Port(): {Port: ap.Port(), TLS: &model.TLSInfo{Version: "TLS 1.3"}},
		},
	}

	if err := NewTLSDeep(3*time.Second).Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	d := host.Ports[ap.Port()].TLSDeep
	if d == nil {
		t.Fatal("no tls-deep result")
	}
	if len(d.Versions) == 0 || len(d.Ciphers) == 0 {
		t.Fatalf("versions/ciphers empty: %+v", d)
	}
	if len(d.Chain) == 0 {
		t.Fatal("no certificate chain")
	}
	// httptest uses a self-signed cert, so a warning must fire.
	var selfSigned bool
	for _, w := range d.Warnings {
		if strings.Contains(w, "self-signed") {
			selfSigned = true
		}
	}
	if !selfSigned {
		t.Fatalf("expected self-signed warning, got %v (chain[0]=%+v)", d.Warnings, d.Chain[0])
	}
	if host.Status[model.StageTLSDeep] != "ok" {
		t.Fatalf("status = %v", host.Status)
	}
}
