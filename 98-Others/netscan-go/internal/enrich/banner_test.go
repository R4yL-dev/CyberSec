package enrich

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"netscan/internal/model"
)

func TestParseBanner(t *testing.T) {
	cases := []struct {
		raw, product, version, cpe string
	}{
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "openssh", "8.2p1", "cpe:2.3:a:openbsd:openssh:8.2p1"},
		{"220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3", "cpe:2.3:a:vsftpd:vsftpd:3.0.3"},
		{"220 mail.example.com ESMTP Postfix (Ubuntu)", "postfix", "", "cpe:2.3:a:postfix:postfix:*"},
		{"+OK Dovecot ready.", "dovecot", "", "cpe:2.3:a:dovecot:dovecot:*"},
		{"5.7.42-log MySQL Community Server", "mysql", "5.7.42", "cpe:2.3:a:oracle:mysql:5.7.42"},
	}
	for _, c := range cases {
		svc := parseBanner(c.raw)
		if svc == nil {
			t.Errorf("parseBanner(%q) = nil", c.raw)
			continue
		}
		if svc.Product != c.product || svc.Version != c.version || svc.CPE != c.cpe {
			t.Errorf("parseBanner(%q) = %+v, want product=%q version=%q cpe=%q",
				c.raw, *svc, c.product, c.version, c.cpe)
		}
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("SSH-2.0-OpenSSH_9.6\r\nextra line"))
	if got != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("sanitize = %q", got)
	}
}

// TestBannerGrab exercises the connect+read path against a local TCP server that
// speaks first (like SSH/FTP/SMTP).
func TestBannerGrab(t *testing.T) {
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

	ap := netip.MustParseAddrPort(ln.Addr().String())
	host := &model.HostRecord{
		IP:        ap.Addr(),
		OpenPorts: []uint16{ap.Port()},
		Ports: map[uint16]*model.PortInfo{
			// light saw no HTTP here (status 0) → banner palier handles it.
			ap.Port(): {Port: ap.Port(), HTTP: &model.HTTPInfo{Status: 0}},
		},
	}
	if err := NewBanner(2*time.Second).Enrich(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	pi := host.Ports[ap.Port()]
	if pi.Banner == "" {
		t.Fatal("no raw banner captured")
	}
	if len(pi.Services) != 1 || pi.Services[0].Product != "openssh" || pi.Services[0].Source != "banner" {
		t.Fatalf("services = %+v", pi.Services)
	}
	if pi.Services[0].Version != "9.6p1" {
		t.Fatalf("version = %q", pi.Services[0].Version)
	}
}
