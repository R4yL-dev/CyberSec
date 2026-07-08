package enrich

import (
	"regexp"
	"strings"

	"netscan/internal/model"
)

// services.go: extract normalized product+version (CVE-ready) from the web data
// webinfo already fetched — no extra requests. Sources: Server header,
// X-Powered-By header, and the <meta generator> tag.

// versionRe matches a version like 1.18.0, 2.4.29, 8.2p1. The tail keeps word
// chars (so OpenSSH's "8.2p1" stays intact) but stops at a dash, so build
// suffixes like MySQL's "5.7.42-log" don't leak into the version.
var versionRe = regexp.MustCompile(`\d+(?:\.\d+)+\w*`)

// cpeVendorProduct maps a lowercased product name to its CPE "vendor:product".
// Small and curated; extend as needed. Unknown products get no CPE.
var cpeVendorProduct = map[string]string{
	"nginx":         "nginx:nginx",
	"apache":        "apache:http_server",
	"httpd":         "apache:http_server",
	"iis":           "microsoft:iis",
	"microsoft-iis": "microsoft:iis",
	"openresty":     "openresty:openresty",
	"php":           "php:php",
	"asp.net":       "microsoft:asp.net",
	"express":       "expressjs:express",
	"openssh":       "openbsd:openssh",
	"wordpress":     "wordpress:wordpress",
	"drupal":        "drupal:drupal",
	"joomla":        "joomla:joomla",
	"tomcat":        "apache:tomcat",
	"jetty":         "eclipse:jetty",
	"lighttpd":      "lighttpd:lighttpd",
	"python":        "python:python",
	"node.js":       "nodejs:node.js",
	// non-web services (banner grab)
	"postfix":  "postfix:postfix",
	"exim":     "exim:exim",
	"sendmail": "proofpoint:sendmail",
	"mysql":    "oracle:mysql",
	"mariadb":  "mariadb:mariadb",
	"redis":    "redis:redis",
	"proftpd":  "proftpd:proftpd",
	"vsftpd":   "vsftpd:vsftpd",
	"dovecot":  "dovecot:dovecot",
}

// parseVersionToken splits a token like "nginx/1.18.0 (Ubuntu)" or "PHP/8.2.1"
// or "Python/3.11.4" into product + version. Version is "" when none is present
// (e.g. "cloudflare"). Product is normalized (lowercased, trimmed).
func parseVersionToken(tok string) (product, version string) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", ""
	}
	// Product is everything up to the first '/' or space.
	name := tok
	if i := strings.IndexAny(tok, "/ "); i >= 0 {
		name = tok[:i]
	}
	product = strings.ToLower(strings.TrimSpace(name))
	if v := versionRe.FindString(tok); v != "" {
		version = v
	}
	return product, version
}

// makeCPE composes cpe:2.3:a:vendor:product:version when the product is known.
func makeCPE(product, version string) string {
	vp, ok := cpeVendorProduct[product]
	if !ok {
		return ""
	}
	ver := version
	if ver == "" {
		ver = "*"
	}
	return "cpe:2.3:a:" + vp + ":" + ver
}

// extractServices derives Services from web headers and body. Deduplicated by
// product+version.
func extractServices(headers map[string]string, body []byte) []model.Service {
	var out []model.Service
	seen := map[string]bool{}
	add := func(product, version, source string) {
		if product == "" {
			return
		}
		key := product + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, model.Service{
			Product: product,
			Version: version,
			CPE:     makeCPE(product, version),
			Source:  source,
		})
	}

	if s := headerGet(headers, "Server"); s != "" {
		// A Server header can list several tokens ("Apache/2.4 (Unix) PHP/8.1").
		for _, tok := range strings.Fields(s) {
			p, v := parseVersionToken(tok)
			if p != "" {
				add(p, v, "http-server")
			}
		}
	}
	if x := headerGet(headers, "X-Powered-By"); x != "" {
		p, v := parseVersionToken(x)
		add(p, v, "x-powered-by")
	}
	if gen := metaGenerator(string(body)); gen != "" {
		// generator is "Product X.Y" (space-separated), not "name/x.y".
		p := strings.ToLower(strings.Fields(gen)[0])
		v := versionRe.FindString(gen)
		add(p, v, "generator")
	}
	return out
}
