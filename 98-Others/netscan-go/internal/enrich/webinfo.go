package enrich

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"netscan/internal/model"
)

// Webinfo is a fetch palier: for each web port it does one richer HTTP fetch
// (full headers, cookies, body) and runs the composable analyzers over it in
// memory, persisting only small derived results. It runs after light, on hosts
// the selector let through — the "spend more on interesting hosts" tier.
type Webinfo struct {
	Timeout time.Duration
	MaxBody int64 // in-memory analysis cap (never persisted)
}

func NewWebinfo(timeout time.Duration) *Webinfo {
	return &Webinfo{Timeout: timeout, MaxBody: 256 << 10}
}

func (w *Webinfo) Stage() string { return model.StageWebinfo }

func (w *Webinfo) Enrich(ctx context.Context, host *model.HostRecord) error {
	for _, port := range host.OpenPorts {
		pi := host.Ports[port]
		if pi == nil || pi.HTTP == nil || pi.HTTP.Status == 0 {
			continue // light saw no HTTP response on this port
		}
		pi.Web = w.analyze(ctx, host.IP, port)
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageWebinfo] = "ok"
	return nil
}

func (w *Webinfo) client() *http.Client {
	return &http.Client{
		Timeout: w.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
}

func (w *Webinfo) analyze(ctx context.Context, ip netip.Addr, port uint16) *model.WebInfo {
	scheme := "http"
	if tlsPorts[port] {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, netip.AddrPortFrom(ip, port))
	info := &model.WebInfo{}

	client := w.client()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	resp, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, w.MaxBody))
	cookies := resp.Cookies()
	resp.Body.Close()

	info.Headers = flattenHeaders(resp.Header)
	info.Cookies = cookieNames(cookies)
	info.SecurityHeaders = securityHeaders(info.Headers)
	info.Technologies = detectTech(info.Headers, info.Cookies, body)
	info.FaviconHash = w.favicon(ctx, client, base)
	return info
}

// favicon fetches /favicon.ico (a separate URL, so its own request) and returns
// its Shodan-style hash; empty if there is no usable favicon.
func (w *Webinfo) favicon(ctx context.Context, client *http.Client, base string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/favicon.ico", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) == 0 {
		return ""
	}
	return faviconHash(body)
}
