package enrich

import "testing"

func TestParseVersionToken(t *testing.T) {
	cases := []struct {
		in, product, version string
	}{
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"nginx/1.18.0 (Ubuntu)", "nginx", "1.18.0"},
		{"Apache/2.4.29", "apache", "2.4.29"},
		{"PHP/8.2.1", "php", "8.2.1"},
		{"Python/3.11.4", "python", "3.11.4"},
		{"cloudflare", "cloudflare", ""},
		{"OpenSSH_8.2p1", "openssh_8.2p1", "8.2p1"}, // no separator: whole token is name, version still found
	}
	for _, c := range cases {
		p, v := parseVersionToken(c.in)
		if p != c.product || v != c.version {
			t.Errorf("parseVersionToken(%q) = (%q,%q), want (%q,%q)", c.in, p, v, c.product, c.version)
		}
	}
}

func TestMakeCPE(t *testing.T) {
	if got := makeCPE("nginx", "1.18.0"); got != "cpe:2.3:a:nginx:nginx:1.18.0" {
		t.Errorf("nginx CPE = %q", got)
	}
	if got := makeCPE("apache", "2.4.29"); got != "cpe:2.3:a:apache:http_server:2.4.29" {
		t.Errorf("apache CPE = %q", got)
	}
	if got := makeCPE("nginx", ""); got != "cpe:2.3:a:nginx:nginx:*" {
		t.Errorf("versionless CPE = %q", got)
	}
	if got := makeCPE("totally-unknown", "1.0"); got != "" {
		t.Errorf("unknown vendor should have empty CPE, got %q", got)
	}
}

func TestExtractServices(t *testing.T) {
	headers := map[string]string{
		"Server":       "Apache/2.4.29 (Ubuntu)",
		"X-Powered-By": "PHP/8.2.1",
	}
	body := []byte(`<meta name="generator" content="WordPress 6.4">`)

	svcs := extractServices(headers, body)
	got := map[string]string{} // product -> cpe
	for _, s := range svcs {
		got[s.Product] = s.CPE
	}
	if got["apache"] != "cpe:2.3:a:apache:http_server:2.4.29" {
		t.Errorf("apache service = %v", got)
	}
	if got["php"] != "cpe:2.3:a:php:php:8.2.1" {
		t.Errorf("php service = %v", got)
	}
	if got["wordpress"] != "cpe:2.3:a:wordpress:wordpress:6.4" {
		t.Errorf("wordpress service = %v", got)
	}
}
