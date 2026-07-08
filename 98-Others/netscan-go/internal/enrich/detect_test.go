package enrich

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"netscan/internal/model"
)

func detectPort(t *testing.T, addr string) *model.PortInfo {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	host := &model.HostRecord{IP: ap.Addr(), OpenPorts: []uint16{ap.Port()}}
	if err := NewDetect(3*time.Second).Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	return host.Ports[ap.Port()]
}

func TestDetectHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		_, _ = w.Write([]byte("<title>hi</title>"))
	}))
	defer srv.Close()

	pi := detectPort(t, strings.TrimPrefix(srv.URL, "http://"))
	if pi.Protocol != model.ProtoHTTP || pi.HTTP == nil || pi.HTTP.Status != 200 {
		t.Fatalf("detect http = %+v", pi)
	}
}

// TestDetectHTTPSNonStandardPort is the key regression: HTTPS on a non-443 port
// must be classified https with the cert captured (the old 443-hardcoded triage
// missed this).
func TestDetectHTTPSNonStandardPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pi := detectPort(t, strings.TrimPrefix(srv.URL, "https://"))
	if pi.Protocol != model.ProtoHTTPS {
		t.Fatalf("protocol = %q, want https (port %d)", pi.Protocol, pi.Port)
	}
	if pi.HTTP == nil || pi.HTTP.Status != 200 {
		t.Fatalf("https HTTP = %+v", pi.HTTP)
	}
	if pi.TLS == nil || pi.TLS.Version == "" {
		t.Fatalf("TLS not captured: %+v", pi.TLS)
	}
}

func TestDetectSpeakFirstSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n"))
		c.Close()
	}()

	pi := detectPort(t, ln.Addr().String())
	if pi.Protocol != model.ProtoSSH {
		t.Fatalf("protocol = %q, want ssh", pi.Protocol)
	}
	if pi.Banner == "" {
		t.Fatal("no raw banner")
	}
	if len(pi.Services) != 1 || pi.Services[0].Product != "openssh" || pi.Services[0].Version != "9.6p1" {
		t.Fatalf("services = %+v", pi.Services)
	}
}
