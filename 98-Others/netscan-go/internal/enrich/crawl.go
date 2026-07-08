package enrich

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"netscan/internal/model"
)

// probe is one path the crawl palier checks, plus an optional signature that
// must appear in the body to count it as a genuine hit (guards against catch-all
// 200s and soft-404s).
type probe struct {
	path     string
	category string
	sig      string // case-insensitive; "" means any non-404 counts
}

// crawlProbes is a small curated list, in three families. Kept short on purpose
// — this palier is gated and should stay a handful of extra requests per host.
var crawlProbes = []probe{
	// well-known / polite discovery
	{"/robots.txt", "well-known", ""},
	{"/sitemap.xml", "well-known", ""},
	{"/.well-known/security.txt", "well-known", ""},
	{"/.well-known/openid-configuration", "well-known", ""},
	// sensitive / common exposures (signature-guarded where a marker exists)
	{"/.git/HEAD", "sensitive", "ref:"},
	{"/.git/config", "sensitive", "[core]"},
	{"/.env", "sensitive", "="},
	{"/.svn/entries", "sensitive", ""},
	{"/.DS_Store", "sensitive", ""},
	{"/server-status", "sensitive", "Apache Server Status"},
	{"/config.php.bak", "sensitive", ""},
	{"/.aws/credentials", "sensitive", ""},
	{"/wp-config.php.bak", "sensitive", ""},
	{"/phpinfo.php", "sensitive", "phpinfo()"},
}

// Crawl is a discovery palier: it probes a curated set of well-known and
// sensitive paths and lists the server's HTTP methods. Gated after light on
// hosts that answered HTTP — the most request-heavy palier, hence gated.
type Crawl struct {
	Timeout time.Duration
	MaxBody int64
}

func NewCrawl(timeout time.Duration) *Crawl {
	return &Crawl{Timeout: timeout, MaxBody: 16 << 10}
}

func (c *Crawl) Stage() string { return model.StageCrawl }

func (c *Crawl) Enrich(ctx context.Context, host *model.HostRecord) error {
	for _, port := range host.OpenPorts {
		if ctx.Err() != nil {
			break
		}
		pi := host.Ports[port]
		if pi == nil || pi.HTTP == nil || pi.HTTP.Status == 0 {
			continue // light saw no HTTP response here
		}
		pi.Crawl = c.crawl(ctx, host.IP, port)
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageCrawl] = "ok"
	return nil
}

func (c *Crawl) client() *http.Client {
	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		// Don't follow redirects: a 301/302 on a sensitive path is not a hit.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Crawl) crawl(ctx context.Context, ip netip.Addr, port uint16) *model.CrawlInfo {
	scheme := "http"
	if tlsPorts[port] {
		scheme = "https"
	}
	base := scheme + "://" + netip.AddrPortFrom(ip, port).String()
	client := c.client()
	info := &model.CrawlInfo{}

	for _, p := range crawlProbes {
		if ctx.Err() != nil {
			break
		}
		if fp := c.probePath(ctx, client, base, p); fp != nil {
			info.Paths = append(info.Paths, *fp)
		}
	}
	info.Methods = c.options(ctx, client, base)
	if len(info.Paths) == 0 && len(info.Methods) == 0 {
		return nil
	}
	return info
}

func (c *Crawl) probePath(ctx context.Context, client *http.Client, base string, p probe) *model.FoundPath {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p.path, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody))

	// A signature-guarded probe only counts on a 2xx whose body contains the marker.
	if p.sig != "" {
		if resp.StatusCode >= 300 || !strings.Contains(strings.ToLower(string(body)), strings.ToLower(p.sig)) {
			return nil
		}
	}
	return &model.FoundPath{
		Path:      p.path,
		Status:    resp.StatusCode,
		Size:      int64(len(body)),
		Category:  p.category,
		Signature: p.sig,
	}
}

func (c *Crawl) options(ctx context.Context, client *http.Client, base string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, base+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	allow := resp.Header.Get("Allow")
	if allow == "" {
		return nil
	}
	var methods []string
	for _, m := range strings.Split(allow, ",") {
		if m = strings.TrimSpace(m); m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}
