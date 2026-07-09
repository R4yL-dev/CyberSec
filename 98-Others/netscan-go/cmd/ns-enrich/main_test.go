package main

import "testing"

func TestResolveAllPorts(t *testing.T) {
	// empty → disabled (nil)
	if got, err := resolveAllPorts(""); err != nil || got != nil {
		t.Fatalf("empty: got %v, err=%v (want nil,nil)", got, err)
	}
	// "common" → the curated set (non-empty)
	if got, err := resolveAllPorts("common"); err != nil || len(got) == 0 {
		t.Fatalf("common: %d ports, err=%v", len(got), err)
	}
	// "all" → full range
	if got, err := resolveAllPorts("all"); err != nil || len(got) != 65535 {
		t.Fatalf("all: %d ports, err=%v", len(got), err)
	}
	// explicit spec, deduplicated
	if got, err := resolveAllPorts("1-10,80,80,8000-8002"); err != nil || len(got) != 14 {
		t.Fatalf("spec: %d ports, err=%v (want 14)", len(got), err)
	}
	// invalid
	if _, err := resolveAllPorts("70000"); err == nil {
		t.Fatal("invalid spec should error")
	}
}
