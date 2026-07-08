package pipeline

import (
	"testing"
	"time"

	"netscan/internal/model"
)

func TestDefaultGraph(t *testing.T) {
	pl := Default(time.Second)

	if len(pl.Stages()) != 5 {
		t.Fatalf("stages = %v, want 5", pl.Stages())
	}

	detect, ok := pl[model.StageDetect]
	if !ok {
		t.Fatal("no detect stage")
	}
	targets := map[string]bool{}
	for _, e := range detect.Next {
		if e.When == nil {
			t.Fatalf("edge detect->%s has a nil selector", e.To)
		}
		targets[e.To] = true
	}
	for _, want := range []string{model.StageWebinfo, model.StageTLSDeep, model.StageCrawl, model.StagePTR} {
		if !targets[want] {
			t.Fatalf("detect edges = %v, missing %s", targets, want)
		}
	}

	for _, s := range []string{model.StageWebinfo, model.StageTLSDeep, model.StageCrawl, model.StagePTR} {
		if len(pl[s].Next) != 0 {
			t.Fatalf("%s should be a terminal stage", s)
		}
	}

	for name, st := range pl {
		if st.Enricher.Stage() != name {
			t.Fatalf("stage %q enricher reports %q", name, st.Enricher.Stage())
		}
	}
}
