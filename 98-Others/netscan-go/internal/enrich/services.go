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
// Curated best-effort — the strings should be validated against the official NVD
// CPE dictionary before they drive CVE matching (the deferred CVE step); a wrong
// mapping just fails to match, it never invents a vuln. Unknown products get no CPE.
var cpeVendorProduct = map[string]string{
	// web servers / proxies
	"nginx":         "nginx:nginx",
	"apache":        "apache:http_server",
	"httpd":         "apache:http_server",
	"iis":           "microsoft:iis",
	"microsoft-iis": "microsoft:iis",
	"openresty":     "openresty:openresty",
	"lighttpd":      "lighttpd:lighttpd",
	"caddy":         "caddyserver:caddy",
	"traefik":       "traefik:traefik",
	"haproxy":       "haproxy:haproxy",
	"litespeed":     "litespeedtech:litespeed_web_server",
	"cherokee":      "cherokee-project:cherokee",
	// app servers / runtimes / frameworks
	"php":       "php:php",
	"asp.net":   "microsoft:asp.net",
	"express":   "expressjs:express",
	"python":    "python:python",
	"node.js":   "nodejs:node.js",
	"tomcat":    "apache:tomcat",
	"jetty":     "eclipse:jetty",
	"gunicorn":  "gunicorn:gunicorn",
	"tornado":   "tornadoweb:tornado",
	"werkzeug":  "palletsprojects:werkzeug",
	"coldfusion": "adobe:coldfusion",
	"weblogic":  "oracle:weblogic_server",
	"websphere": "ibm:websphere_application_server",
	"wildfly":   "redhat:wildfly",
	"glassfish": "oracle:glassfish_server",
	// apps / CMS / tooling (Server / generator / signatures)
	"wordpress":     "wordpress:wordpress",
	"drupal":        "drupal:drupal",
	"joomla":        "joomla:joomla",
	"gitlab":        "gitlab:gitlab",
	"jenkins":       "jenkins:jenkins",
	"grafana":       "grafana:grafana",
	"kibana":        "elastic:kibana",
	"elasticsearch": "elastic:elasticsearch",
	"minio":         "minio:minio",
	// databases / caches / queues
	"mysql":     "oracle:mysql",
	"mariadb":   "mariadb:mariadb",
	"redis":     "redis:redis",
	"mongodb":   "mongodb:mongodb",
	"postgresql": "postgresql:postgresql",
	"memcached": "memcached:memcached",
	// mail / ftp (banner grab)
	"openssh":  "openbsd:openssh",
	"postfix":  "postfix:postfix",
	"exim":     "exim:exim",
	"sendmail": "proofpoint:sendmail",
	"proftpd":  "proftpd:proftpd",
	"vsftpd":   "vsftpd:vsftpd",
	"pure-ftpd": "pureftpd:pure-ftpd",
	"dovecot":  "dovecot:dovecot",
	"courier":  "courier-mta:courier",
	// apps (header signatures)
	"confluence": "atlassian:confluence",
	// network gear / appliances / IoT
	"routeros": "mikrotik:routeros",
	"mikrotik": "mikrotik:routeros",
	"fortios":  "fortinet:fortios",
	// remote access
	"tigervnc": "tigervnc:tigervnc",
	"realvnc":  "realvnc:vnc",
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
	// Product-revealing headers that don't use Server/X-Powered-By. Presence alone
	// (needle == "") is the signal; the header value often carries the version.
	for _, sig := range httpHeaderSigs {
		val := headerGet(headers, sig.header)
		if val == "" {
			continue
		}
		if sig.needle != "" && !strings.Contains(strings.ToLower(val), sig.needle) {
			continue
		}
		add(sig.product, versionRe.FindString(val), "http-header:"+sig.header)
	}
	return out
}

// httpHeaderSigs are high-signal product markers in headers other than Server /
// X-Powered-By / generator. needle "" means "presence of the header is enough".
var httpHeaderSigs = []struct{ header, needle, product string }{
	{"X-Jenkins", "", "jenkins"},                 // value = Jenkins version
	{"X-Drupal-Cache", "", "drupal"},
	{"X-Drupal-Dynamic-Cache", "", "drupal"},
	{"X-Generator", "drupal", "drupal"},
	{"X-Kibana-Version", "", "kibana"},           // value = Kibana version
	{"kbn-name", "", "kibana"},
	{"X-Confluence-Request-Time", "", "confluence"},
	{"WWW-Authenticate", "tomcat", "tomcat"},
	{"WWW-Authenticate", "jenkins", "jenkins"},
	{"WWW-Authenticate", "gitlab", "gitlab"},
}
