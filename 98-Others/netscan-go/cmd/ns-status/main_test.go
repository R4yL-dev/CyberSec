package main

import (
	"testing"

	"netscan/internal/store"
)

func TestPhaseOf(t *testing.T) {
	cases := []struct {
		name        string
		ingestState string
		pending     int64
		leased      int64
		want        phase
	}{
		{"ingesting, queue building", store.IngestRunning, 10, 2, phaseDiscovering},
		{"no ingest state yet", "", 0, 0, phaseDiscovering},
		{"ingest done, work remaining", store.IngestDone, 5, 0, phaseEnriching},
		{"ingest done, only leased left", store.IngestDone, 0, 3, phaseEnriching},
		{"ingest done, queue empty", store.IngestDone, 0, 0, phaseComplete},
	}
	for _, c := range cases {
		if got := phaseOf(c.ingestState, c.pending, c.leased); got != c.want {
			t.Errorf("%s: phaseOf(%q,%d,%d)=%d, want %d", c.name, c.ingestState, c.pending, c.leased, got, c.want)
		}
	}
}
