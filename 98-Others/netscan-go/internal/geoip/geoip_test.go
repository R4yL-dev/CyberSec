package geoip

import (
	"net/netip"
	"testing"
)

// TestOptionalGraceful verifies geo is safe when disabled or given bad paths —
// the feature must never be fatal.
func TestOptionalGraceful(t *testing.T) {
	// No paths: disabled.
	l := Open("", "")
	if l.Enabled() {
		t.Fatal("empty paths should not enable")
	}
	if l.Annotate(netip.MustParseAddr("1.1.1.1")) != nil {
		t.Fatal("disabled lookup must return nil")
	}
	l.Close() // must not panic

	// Non-existent files: skipped, still disabled.
	l = Open("/no/such/country.mmdb", "/no/such/asn.mmdb")
	if l.Enabled() {
		t.Fatal("missing files should not enable")
	}

	// A nil *Lookup must be safe.
	var nilL *Lookup
	if nilL.Enabled() || nilL.Annotate(netip.MustParseAddr("8.8.8.8")) != nil {
		t.Fatal("nil Lookup must be safe")
	}
	nilL.Close()
}
