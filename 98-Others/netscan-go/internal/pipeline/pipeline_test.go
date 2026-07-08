package pipeline

import (
	"testing"
	"time"

	"netscan/internal/model"
)

func TestDefaultGraph(t *testing.T) {
	pl := Default(time.Second)

	if len(pl.Stages()) != 3 {
		t.Fatalf("stages = %v, want 3", pl.Stages())
	}

	light, ok := pl[model.StageLight]
	if !ok {
		t.Fatal("no light stage")
	}
	targets := map[string]bool{}
	for _, e := range light.Next {
		if e.When == nil {
			t.Fatalf("edge light->%s has a nil selector", e.To)
		}
		targets[e.To] = true
	}
	if !targets[model.StageWebinfo] || !targets[model.StagePTR] {
		t.Fatalf("light edges = %v, want webinfo + ptr", targets)
	}

	if len(pl[model.StageWebinfo].Next) != 0 || len(pl[model.StagePTR].Next) != 0 {
		t.Fatal("webinfo/ptr should be terminal stages")
	}

	for name, st := range pl {
		if st.Enricher.Stage() != name {
			t.Fatalf("stage %q enricher reports %q", name, st.Enricher.Stage())
		}
	}
}
