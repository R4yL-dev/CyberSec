package enrich

import (
	"regexp"
	"strings"
	"unicode"

	"netscan/internal/model"
)

// banner.go: parsers for server-speaks-first banners. The grab itself is done by
// the detect palier (detect.go); these turn a raw banner into a Service.

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
	{"courier", "courier"},
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

	// VNC greets with "RFB 003.008" — that's the RFB *protocol* version, not a
	// software version, and the banner names no product. classifyBanner already
	// tagged it vnc; don't emit a misleading unknown@003.008 service.
	if strings.HasPrefix(raw, "RFB ") {
		return nil
	}

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
