package main

import "testing"

func TestParsePortSpec(t *testing.T) {
	// empty → the common set (non-empty)
	if got, err := parsePortSpec(""); err != nil || len(got) == 0 {
		t.Fatalf("empty spec: %d ports, err=%v", len(got), err)
	}
	// all → full range
	if got, err := parsePortSpec("all"); err != nil || len(got) != 65535 {
		t.Fatalf("all: %d ports, err=%v", len(got), err)
	}
	// explicit ranges + list, deduplicated
	got, err := parsePortSpec("1-10,80,80,8000-8002")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 14 { // 1..10 (10) + 80 (1) + 8000..8002 (3)
		t.Fatalf("got %d ports, want 14: %v", len(got), got)
	}
	// invalid
	for _, bad := range []string{"0", "70000", "abc", "10-1", "5-"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Errorf("spec %q should error", bad)
		}
	}
}
