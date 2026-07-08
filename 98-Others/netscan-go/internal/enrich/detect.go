package enrich

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"netscan/internal/model"
)

// detectTimeoutCap bounds the triage probe: detect is the cheap entry palier, so
// it must not burn the full (deep-palier) timeout on a silent port. 5s covers
// virtually any responsive service.
const detectTimeoutCap = 5 * time.Second

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	wsRE    = regexp.MustCompile(`\s+`)
)

// Detect is the entry palier: for each open port it makes a protocol-aware first
// contact and classifies the port into {Protocol, TLS, HTTP, Banner, Services}.
// It replaces the old HTTP-only "light" and folds in the banner grab. The port
// number only hints the probe order; classification is by what actually answers,
// so HTTPS on 8443 or SSH on 2222 are detected correctly via fallback.
type Detect struct {
	Timeout      time.Duration
	MaxBody      int64
	MaxRedirects int
}

func NewDetect(timeout time.Duration) *Detect {
	if timeout > detectTimeoutCap {
		timeout = detectTimeoutCap
	}
	return &Detect{Timeout: timeout, MaxBody: 64 << 10, MaxRedirects: 10}
}

func (d *Detect) Stage() string { return model.StageDetect }

func (d *Detect) Enrich(ctx context.Context, host *model.HostRecord) error {
	if host.Ports == nil {
		host.Ports = make(map[uint16]*model.PortInfo, len(host.OpenPorts))
	}
	for _, port := range host.OpenPorts {
		pi := &model.PortInfo{Port: port}
		d.detect(ctx, host.IP, port, pi)
		host.Ports[port] = pi
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageDetect] = "ok"
	return nil
}

// portHint returns the likely family of a port, used only to order the probes.
func portHint(port uint16) string {
	switch port {
	case 80, 8080, 8000, 8888, 8081, 3000, 5000:
		return "web"
	case 443, 8443, 9443, 993, 995, 465, 990:
		return "tls"
	case 22, 21, 25, 587, 110, 143, 3306, 5432, 6379, 23:
		return "speakfirst"
	default:
		return "unknown"
	}
}

func (d *Detect) detect(ctx context.Context, ip netip.Addr, port uint16, pi *model.PortInfo) {
	hint := portHint(port)

	// Peek for a server-speaks-first banner (SSH/FTP/SMTP…). Skip on web-likely
	// ports (HTTP never speaks first) to avoid the peek latency there.
	if hint != "web" {
		if banner := d.peek(ctx, ip, port); banner != "" {
			d.fromBanner(pi, banner)
			return
		}
	}

	tlsFirst := hint == "tls"
	if tlsFirst {
		if d.tryTLS(ctx, ip, port, pi) || d.tryHTTP(ctx, ip, port, false, pi) {
			return
		}
	} else {
		if d.tryHTTP(ctx, ip, port, false, pi) || d.tryTLS(ctx, ip, port, pi) {
			return
		}
	}
	pi.Protocol = model.ProtoUnknown
}

// peek connects and reads whatever the server sends first, within a short window.
func (d *Detect) peek(ctx context.Context, ip netip.Addr, port uint16) string {
	dialer := net.Dialer{Timeout: d.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return ""
	}
	defer conn.Close()
	peekWindow := d.Timeout
	if peekWindow > time.Second {
		peekWindow = time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(peekWindow))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

func (d *Detect) fromBanner(pi *model.PortInfo, banner string) {
	pi.Banner = banner
	pi.Protocol = classifyBanner(banner)
	if svc := parseBanner(banner); svc != nil {
		svc.Source = "banner"
		pi.Services = append(pi.Services, *svc)
	}
}

func classifyBanner(banner string) string {
	low := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return model.ProtoSSH
	case strings.Contains(low, "smtp") || strings.Contains(low, "postfix") ||
		strings.Contains(low, "exim") || strings.Contains(low, "sendmail"):
		return model.ProtoSMTP
	case strings.Contains(low, "ftp"):
		return model.ProtoFTP
	default:
		return model.ProtoBanner
	}
}

// tryTLS reports whether the port speaks TLS; if so it records the cert summary
// and whether HTTPS is served on top.
func (d *Detect) tryTLS(ctx context.Context, ip netip.Addr, port uint16, pi *model.PortInfo) bool {
	if info, tlsInfo := d.httpProbe(ctx, ip, port, true); info != nil {
		pi.Protocol = model.ProtoHTTPS
		pi.HTTP = info
		pi.TLS = tlsInfo
		return true
	}
	// GET over TLS failed — maybe TLS but not HTTP. Confirm with a bare handshake.
	if tlsInfo := d.tlsHandshake(ip, port); tlsInfo != nil {
		pi.Protocol = model.ProtoTLS
		pi.TLS = tlsInfo
		return true
	}
	return false
}

func (d *Detect) tryHTTP(ctx context.Context, ip netip.Addr, port uint16, https bool, pi *model.PortInfo) bool {
	info, _ := d.httpProbe(ctx, ip, port, https)
	if info == nil {
		return false
	}
	pi.Protocol = model.ProtoHTTP
	pi.HTTP = info
	return true
}

// httpProbe does one GET (scheme per https) and returns the HTTP summary, plus a
// TLS cert summary from the connection when https. Returns nil when the port
// produced no HTTP response.
func (d *Detect) httpProbe(ctx context.Context, ip netip.Addr, port uint16, https bool) (*model.HTTPInfo, *model.TLSInfo) {
	scheme := "http"
	if https {
		scheme = "https"
	}
	url := scheme + "://" + netip.AddrPortFrom(ip, port).String() + "/"
	info := &model.HTTPInfo{URL: url}

	var redirects []model.Redirect
	client := &http.Client{
		Timeout: d.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= d.MaxRedirects {
				return http.ErrUseLastResponse
			}
			if resp := req.Response; resp != nil {
				redirects = append(redirects, model.Redirect{Status: resp.StatusCode, Location: req.URL.String()})
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // no HTTP response
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, d.MaxBody))
	info.Status = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.Title = extractTitle(body)
	info.Redirects = redirects

	var tlsInfo *model.TLSInfo
	if https && resp.TLS != nil {
		tlsInfo = summarizeCert(resp.TLS)
	}
	return info, tlsInfo
}

// tlsHandshake does a bare TLS handshake and returns a cert summary, or nil.
func (d *Detect) tlsHandshake(ip netip.Addr, port uint16) *model.TLSInfo {
	dialer := &net.Dialer{Timeout: d.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", netip.AddrPortFrom(ip, port).String(),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	return summarizeCert(&cs)
}

// summarizeCert extracts the light TLS summary from a connection state.
func summarizeCert(cs *tls.ConnectionState) *model.TLSInfo {
	info := &model.TLSInfo{Version: tls.VersionName(cs.Version)}
	if len(cs.PeerCertificates) == 0 {
		info.Error = "no certificate presented"
		return info
	}
	cert := cs.PeerCertificates[0]
	info.SubjectCN = cert.Subject.CommonName
	info.Issuer = cert.Issuer.CommonName
	info.SAN = cert.DNSNames
	info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	return info
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(wsRE.ReplaceAllString(string(m[1]), " "))
}
