package stream

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"netscan/internal/model"
)

func TestNDJSONRoundTrip(t *testing.T) {
	recs := []model.WireRecord{
		{IP: netip.MustParseAddr("1.1.1.1"), OpenPorts: []uint16{80, 443}, DiscoveredAt: time.Now().UTC().Round(time.Second)},
		{IP: netip.MustParseAddr("8.8.8.8"), OpenPorts: []uint16{53}, DiscoveredAt: time.Now().UTC().Round(time.Second)},
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Flush(); err != nil {
		t.Fatal(err)
	}

	var got []model.WireRecord
	if err := Decode(&buf, func(r model.WireRecord) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(got) != len(recs) {
		t.Fatalf("decoded %d records, want %d", len(got), len(recs))
	}
	for i := range recs {
		if got[i].IP != recs[i].IP || len(got[i].OpenPorts) != len(recs[i].OpenPorts) {
			t.Fatalf("record %d mismatch: %+v vs %+v", i, got[i], recs[i])
		}
	}
}
