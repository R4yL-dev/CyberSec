package enrich

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"netscan/internal/model"
)

// Banner is a non-web service palier: it grabs the banner that server-speaks-
// first services (SSH, FTP, SMTP, POP3, IMAP, MySQL…) send on connect, stores it
// raw (truncated), and parses a product+version Service from it. It runs after
// light on ports that produced no HTTP response (the non-web ports).
type Banner struct {
	Timeout time.Duration
	MaxRead int
}

func NewBanner(timeout time.Duration) *Banner {
	return &Banner{Timeout: timeout, MaxRead: 1024}
}

func (b *Banner) Stage() string { return model.StageBanner }

func (b *Banner) Enrich(ctx context.Context, host *model.HostRecord) error {
	for _, port := range host.OpenPorts {
		if ctx.Err() != nil {
			break
		}
		pi := host.Ports[port]
		if pi != nil && pi.HTTP != nil && pi.HTTP.Status != 0 {
			continue // this is a web port; light already handled it
		}
		if pi == nil {
			pi = &model.PortInfo{Port: port}
			host.Ports[port] = pi
		}
		raw := b.grab(ctx, host.IP, port)
		if raw == "" {
			continue
		}
		pi.Banner = raw
		if svc := parseBanner(raw); svc != nil {
			svc.Source = "banner"
			pi.Services = append(pi.Services, *svc)
		}
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageBanner] = "ok"
	return nil
}

// grab connects and reads whatever the service sends first, within the timeout.
func (b *Banner) grab(ctx context.Context, ip netip.Addr, port uint16) string {
	d := net.Dialer{Timeout: b.Timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(b.Timeout))
	buf := make([]byte, b.MaxRead)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

// sanitizeBanner keeps the banner readable: first line, printable runes only,
// trimmed and length-capped.
func sanitizeBanner(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// bannerNeedle maps a case-insensitive substring in a banner to a product name
// (which the CPE map may then recognize).
type bannerNeedle struct{ needle, product string }

var bannerNeedles = []bannerNeedle{
	{"openssh", "openssh"},
	{"vsftpd", "vsftpd"},
	{"proftpd", "proftpd"},
	{"pure-ftpd", "pure-ftpd"},
	{"filezilla", "filezilla"},
	{"postfix", "postfix"},
	{"exim", "exim"},
	{"sendmail", "sendmail"},
	{"dovecot", "dovecot"},
	{"mariadb", "mariadb"},
	{"mysql", "mysql"},
	{"redis", "redis"},
}

// sshRe pulls the software token out of an SSH identification string,
// e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4" -> "OpenSSH_8.2p1".
var sshRe = regexp.MustCompile(`^SSH-\d+\.\d+-(\S+)`)

// parseBanner derives a Service (product+version+CPE) from a raw banner, or nil.
func parseBanner(raw string) *model.Service {
	lower := strings.ToLower(raw)

	// SSH: reliable, has its own identification format.
	if m := sshRe.FindStringSubmatch(raw); m != nil {
		token := m[1] // e.g. OpenSSH_8.2p1
		product := "openssh"
		if !strings.Contains(strings.ToLower(token), "openssh") {
			// some other SSH impl; use the token's leading name
			product = strings.ToLower(strings.FieldsFunc(token, func(r rune) bool { return r == '_' || r == '-' })[0])
		}
		version := versionRe.FindString(token)
		return &model.Service{Product: product, Version: version, CPE: makeCPE(product, version)}
	}

	// Other server-speaks-first services: match a known product needle.
	for _, bn := range bannerNeedles {
		if strings.Contains(lower, bn.needle) {
			version := versionRe.FindString(raw)
			return &model.Service{Product: bn.product, Version: version, CPE: makeCPE(bn.product, version)}
		}
	}

	// Unknown service: if the banner carries a version-looking token, keep it as
	// a bare (product-less) marker; otherwise nothing structured.
	if v := versionRe.FindString(raw); v != "" {
		return &model.Service{Product: "unknown", Version: v}
	}
	return nil
}
