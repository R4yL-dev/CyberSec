package enrich

import "testing"

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

func TestClassifyBanner(t *testing.T) {
	cases := []struct{ raw, proto string }{
		{"SSH-2.0-OpenSSH_9.6", "ssh"},
		{"RFB 003.008", "vnc"},
		{"+OK Dovecot ready.", "pop3"},
		{"* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap"},
		{"* PREAUTH IMAP4rev1 server logged in", "imap"},
		{"220 mail.example.com ESMTP Postfix", "smtp"},
		{"220 (vsFTPd 3.0.3)", "ftp"},
		{"whatever else", "banner"},
	}
	for _, c := range cases {
		if got := classifyBanner(c.raw); got != c.proto {
			t.Errorf("classifyBanner(%q) = %q, want %q", c.raw, got, c.proto)
		}
	}
}

// RFB's "003.008" is the protocol version, not a software version — parseBanner
// must not emit a bogus unknown@003.008 service (classifyBanner tags it vnc).
func TestParseBannerRFBNil(t *testing.T) {
	if svc := parseBanner("RFB 003.008"); svc != nil {
		t.Errorf("parseBanner(RFB) = %+v, want nil", *svc)
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("SSH-2.0-OpenSSH_9.6\r\nextra line"))
	if got != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("sanitize = %q", got)
	}
}
