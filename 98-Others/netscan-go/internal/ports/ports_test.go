package ports

import "testing"

func TestParse(t *testing.T) {
	if got, err := Parse("all"); err != nil || len(got) != 65535 {
		t.Fatalf("all: %d ports, err=%v", len(got), err)
	}
	// list + ranges, deduplicated and sorted
	got, err := Parse("8000-8002,80,80,1-3")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{1, 2, 3, 80, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted+deduped)", got, want)
		}
	}
	for _, bad := range []string{"", "0", "70000", "abc", "10-1", "5-", "80,x"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should error", bad)
		}
	}
}

func TestCommonNonEmpty(t *testing.T) {
	if c := Common(); len(c) == 0 || c[0] != 80 {
		t.Fatalf("Common() = %v (want non-empty, top=80)", c)
	}
}
