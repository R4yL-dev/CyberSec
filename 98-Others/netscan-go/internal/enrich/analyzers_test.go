package enrich

import "testing"

func TestDetectTech(t *testing.T) {
	headers := map[string]string{"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"}
	cookies := []string{"PHPSESSID"}
	body := []byte(`<html><meta name="generator" content="WordPress 6.4"> wp-content </html>`)

	got := detectTech(headers, cookies, body)
	want := map[string]bool{"nginx": true, "PHP": true, "WordPress": true, "WordPress 6.4": true}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Fatalf("detectTech=%v, missing %v", got, want)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := map[string]string{
		"Strict-Transport-Security": "max-age=63072000",
		"X-Frame-Options":           "DENY",
		"Server":                    "nginx",
	}
	got := securityHeaders(h)
	if got["Strict-Transport-Security"] == "" || got["X-Frame-Options"] != "DENY" {
		t.Fatalf("securityHeaders=%v", got)
	}
	if _, ok := got["Server"]; ok {
		t.Fatal("Server must not be treated as a security header")
	}
}

func TestMurmur3AndFavicon(t *testing.T) {
	if h := murmur3_32(nil, 0); h != 0 {
		t.Fatalf("murmur3(empty, 0) = %d, want 0", h)
	}
	if murmur3_32([]byte("hello"), 0) == murmur3_32([]byte("world"), 0) {
		t.Fatal("murmur3 collision on hello/world")
	}
	a := faviconHash([]byte("some icon bytes"))
	b := faviconHash([]byte("some icon bytes"))
	if a == "" || a != b {
		t.Fatalf("faviconHash not deterministic: %q vs %q", a, b)
	}
}
