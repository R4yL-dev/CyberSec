package enrich

import (
	"encoding/base64"
	"encoding/binary"
	"math/bits"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// analyzers.go: small, composable, network-free functions run over an already
// fetched HTTP artifact. Add more here to enrich the webinfo palier.

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func cookieNames(cookies []*http.Cookie) []string {
	if len(cookies) == 0 {
		return nil
	}
	out := make([]string, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, c.Name)
	}
	return out
}

// securityHeaders returns the security-relevant response headers that are present.
func securityHeaders(headers map[string]string) map[string]string {
	want := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	out := map[string]string{}
	for _, name := range want {
		if v := headerGet(headers, name); v != "" {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// techRule matches a technology from headers, cookies or body.
type techRule struct {
	name   string
	header string // header name to inspect (optional)
	substr string // case-insensitive substring to find in header value or body
	cookie string // cookie name prefix (optional)
	body   string // case-insensitive substring in body (optional)
}

var techRules = []techRule{
	{name: "nginx", header: "Server", substr: "nginx"},
	{name: "Apache", header: "Server", substr: "apache"},
	{name: "Microsoft-IIS", header: "Server", substr: "iis"},
	{name: "Cloudflare", header: "Server", substr: "cloudflare"},
	{name: "OpenResty", header: "Server", substr: "openresty"},
	{name: "PHP", header: "X-Powered-By", substr: "php"},
	{name: "PHP", cookie: "PHPSESSID"},
	{name: "ASP.NET", header: "X-Powered-By", substr: "asp.net"},
	{name: "Express", header: "X-Powered-By", substr: "express"},
	{name: "Java", cookie: "JSESSIONID"},
	{name: "Laravel", cookie: "laravel_session"},
	{name: "WordPress", body: "wp-content"},
	{name: "Drupal", body: "drupal"},
}

// detectTech runs the ruleset over the fetched artifact and returns the matched
// technologies (deduplicated). It also picks up a <meta name="generator">.
func detectTech(headers map[string]string, cookies []string, body []byte) []string {
	found := map[string]struct{}{}
	lowerBody := strings.ToLower(string(body))

	for _, r := range techRules {
		switch {
		case r.header != "" && r.substr != "":
			if strings.Contains(strings.ToLower(headerGet(headers, r.header)), r.substr) {
				found[r.name] = struct{}{}
			}
		case r.cookie != "":
			for _, c := range cookies {
				if strings.HasPrefix(c, r.cookie) {
					found[r.name] = struct{}{}
				}
			}
		case r.body != "":
			if strings.Contains(lowerBody, r.body) {
				found[r.name] = struct{}{}
			}
		}
	}
	if gen := metaGenerator(string(body)); gen != "" {
		found[gen] = struct{}{}
	}

	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

var generatorRe = regexp.MustCompile(`(?is)<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+)["']`)

func metaGenerator(body string) string {
	m := generatorRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func headerGet(headers map[string]string, name string) string {
	// headers keys are canonical (http.Header), match case-insensitively anyway.
	if v, ok := headers[http.CanonicalHeaderKey(name)]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// faviconHash mimics the Shodan/Censys favicon hash: base64 (with 76-char lines,
// like Python's base64.encodebytes) then a signed 32-bit MurmurHash3.
func faviconHash(body []byte) string {
	b64 := base64.StdEncoding.EncodeToString(body)
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return strconv.FormatInt(int64(int32(murmur3_32([]byte(sb.String()), 0))), 10)
}

// murmur3_32 is the x86 32-bit MurmurHash3.
func murmur3_32(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
