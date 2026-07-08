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

func TestLoadWebOnlyProfile(t *testing.T) {
	yaml := `
stages:
  detect:
    next:
      - {to: webinfo, when: is_web}
      - {to: crawl,   when: is_web}
  webinfo: {}
  crawl: {}
`
	pl, err := Load([]byte(yaml), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Stages()) != 3 {
		t.Fatalf("stages = %v, want detect/webinfo/crawl", pl.Stages())
	}
	if _, ok := pl[model.StageTLSDeep]; ok {
		t.Fatal("web-only profile should not include tls-deep")
	}
	if len(pl[model.StageDetect].Next) != 2 {
		t.Fatalf("detect should have 2 edges, got %d", len(pl[model.StageDetect].Next))
	}
}

func TestLoadEmptyWhenIsAlways(t *testing.T) {
	pl, err := Load([]byte("stages:\n  detect:\n    next:\n      - {to: ptr}\n  ptr: {}\n"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if e := pl[model.StageDetect].Next[0]; e.When == nil || !e.When(nil) {
		t.Fatal("empty when should resolve to always")
	}
}

func TestLoadInvalid(t *testing.T) {
	cases := map[string]string{
		"missing detect":    "stages:\n  ptr: {}\n",
		"unknown enricher":  "stages:\n  detect: {}\n  bogus: {}\n",
		"unknown selector":  "stages:\n  detect:\n    next:\n      - {to: ptr, when: nope}\n  ptr: {}\n",
		"edge to undefined": "stages:\n  detect:\n    next:\n      - {to: ghost, when: always}\n",
		"no stages":         "stages: {}\n",
	}
	for name, yaml := range cases {
		if _, err := Load([]byte(yaml), time.Second); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
