package fmtx

import (
	"testing"
	"time"
)

func TestCount(t *testing.T) {
	cases := map[uint64]string{
		254:        "254",
		1500:       "1.5k",
		16777216:   "16.8M",
		4300000000: "4.3B",
	}
	for n, want := range cases {
		if got := Count(n); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDuration(t *testing.T) {
	cases := map[time.Duration]string{
		45 * time.Second:                "45s",
		17*time.Minute + 36*time.Second: "17m36s",
		14 * time.Hour:                  "14h00m",
		time.Hour + 12*time.Minute:      "1h12m",
	}
	for d, want := range cases {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%v) = %q, want %q", d, got, want)
		}
	}
}
