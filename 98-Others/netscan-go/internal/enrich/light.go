package enrich

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"netscan/internal/model"
)

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	wsRE    = regexp.MustCompile(`\s+`)
)

// tlsPorts are treated as HTTPS and get a certificate summary.
var tlsPorts = map[uint16]bool{443: true}

// Light is palier 1: a cheap HTTP probe (status, Server, redirect chain, and a
// title extracted from a size-capped body) plus a TLS certificate summary on
// TLS ports. It is a Go port of probe_http/get_tls_cert from netscan.py.
type Light struct {
	Timeout      time.Duration
	MaxBody      int64 // bytes read from the response body
	MaxRedirects int
}

// lightTimeoutCap bounds the triage probe: light is the cheap entry palier, so
// it should not burn the full (deep-palier) timeout on a silent/non-web port.
// 5s covers virtually any responsive web server; the rare web server slower than
// this to first byte won't be classified as web (acceptable triage tradeoff).
const lightTimeoutCap = 5 * time.Second

// NewLight returns a Light enricher with sensible defaults (64 KiB body cap).
func NewLight(timeout time.Duration) *Light {
	if timeout > lightTimeoutCap {
		timeout = lightTimeoutCap
	}
	return &Light{Timeout: timeout, MaxBody: 64 << 10, MaxRedirects: 10}
}

func (l *Light) Stage() string { return model.StageLight }

func (l *Light) Enrich(ctx context.Context, host *model.HostRecord) error {
	if host.Ports == nil {
		host.Ports = make(map[uint16]*model.PortInfo, len(host.OpenPorts))
	}
	for _, port := range host.OpenPorts {
		pi := &model.PortInfo{Port: port}
		// probeHTTP returns nil when the port produced no HTTP response at all
		// (connection error / timeout / non-HTTP) — leaving HTTP nil keeps the
		// record clean and routes the port to the banner palier via HasNonHTTP.
		pi.HTTP = l.probeHTTP(ctx, host.IP, port)
		if tlsPorts[port] {
			pi.TLS = l.probeTLS(host.IP, port)
		}
		host.Ports[port] = pi
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageLight] = "ok"
	return nil
}

func (l *Light) probeHTTP(ctx context.Context, ip netip.Addr, port uint16) *model.HTTPInfo {
	scheme := "http"
	if tlsPorts[port] {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, netip.AddrPortFrom(ip, port))
	info := &model.HTTPInfo{URL: url}

	var redirects []model.Redirect
	client := &http.Client{
		Timeout: l.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= l.MaxRedirects {
				return http.ErrUseLastResponse
			}
			if resp := req.Response; resp != nil {
				redirects = append(redirects, model.Redirect{
					Status:   resp.StatusCode,
					Location: req.URL.String(),
				})
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil // malformed request; nothing usable
	}
	resp, err := client.Do(req)
	if err != nil {
		// No HTTP response (timeout / connection reset / non-HTTP service like
		// SSH). Don't record a misleading http block; let banner handle the port.
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, l.MaxBody))
	info.Status = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.Title = extractTitle(body)
	info.Redirects = redirects
	return info
}

func extractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(wsRE.ReplaceAllString(string(m[1]), " "))
}

func (l *Light) probeTLS(ip netip.Addr, port uint16) *model.TLSInfo {
	info := &model.TLSInfo{}
	dialer := &net.Dialer{Timeout: l.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", netip.AddrPortFrom(ip, port).String(),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	info.Version = tls.VersionName(cs.Version)
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
