// Package pipeline wires the enrichment paliers into a graph: each stage runs an
// Enricher, and each outgoing edge carries a Selector deciding whether a host
// advances to the next stage after the current one completes. The graph is
// described in YAML (see default.yaml) and resolved against name registries; the
// embedded default doubles as the built-in graph and the editable template.
package pipeline

import (
	_ "embed"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"netscan/internal/enrich"
	"netscan/internal/model"
)

// Edge is a gated transition to another stage.
type Edge struct {
	To   string
	When enrich.Selector // nil means always
}

// Stage is one palier plus its outgoing edges.
type Stage struct {
	Enricher enrich.Enricher
	Next     []Edge
}

// Pipeline maps a stage name to its definition.
type Pipeline map[string]Stage

// Stages returns all stage names in the pipeline.
func (p Pipeline) Stages() []string {
	out := make([]string, 0, len(p))
	for name := range p {
		out = append(out, name)
	}
	return out
}

// Options carries per-build configuration passed to enricher constructors
// (kept out of the YAML: typed and supplied via CLI flags).
type Options struct {
	Timeout   time.Duration
	DeepPorts []uint16 // for the portscan palier
}

// enrichers maps a stage/enricher name to its constructor. The map key is both
// the work-queue stage name and the enricher type.
var enrichers = map[string]func(Options) enrich.Enricher{
	model.StageDetect:   func(o Options) enrich.Enricher { return enrich.NewDetect(o.Timeout) },
	model.StageWebinfo:  func(o Options) enrich.Enricher { return enrich.NewWebinfo(o.Timeout) },
	model.StageCrawl:    func(o Options) enrich.Enricher { return enrich.NewCrawl(o.Timeout) },
	model.StageTLSDeep:  func(o Options) enrich.Enricher { return enrich.NewTLSDeep(o.Timeout) },
	model.StagePTR:      func(Options) enrich.Enricher { return enrich.NewPTR() },
	model.StagePortscan: func(o Options) enrich.Enricher { return enrich.NewPortscan(o.DeepPorts, o.Timeout) },
}

// selectors maps a config `when:` name to its predicate. Empty/absent = always.
var selectors = map[string]enrich.Selector{
	"always":         enrich.Always,
	"is_web":         enrich.IsWeb,
	"has_tls":        enrich.HasTLS,
	"needs_portscan": enrich.NeedsPortscan,
}

// Config is the YAML shape of a pipeline.
type Config struct {
	Stages map[string]StageConfig `yaml:"stages"`
}

type StageConfig struct {
	Next []EdgeConfig `yaml:"next"`
}

type EdgeConfig struct {
	To   string `yaml:"to"`
	When string `yaml:"when"`
}

//go:embed default.yaml
var defaultYAML []byte

// Default is the built-in pipeline (parsed from the embedded default.yaml).
func Default(opts Options) Pipeline {
	pl, err := Load(defaultYAML, opts)
	if err != nil {
		panic("pipeline: embedded default.yaml is invalid: " + err.Error()) // build-time guarantee
	}
	return pl
}

// DefaultYAML returns the embedded default config (template for `--print-pipeline`).
func DefaultYAML() []byte { return defaultYAML }

// LoadFile reads and builds a pipeline from a YAML file.
func LoadFile(path string, opts Options) (Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data, opts)
}

// Load parses a YAML config, resolves enricher/selector names via the registries,
// and validates the graph.
func Load(data []byte, opts Options) (Pipeline, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse pipeline: %w", err)
	}
	if len(cfg.Stages) == 0 {
		return nil, fmt.Errorf("pipeline: no stages defined")
	}
	if _, ok := cfg.Stages[model.StageDetect]; !ok {
		return nil, fmt.Errorf("pipeline: entry stage %q must be defined", model.StageDetect)
	}

	pl := make(Pipeline, len(cfg.Stages))
	for name, sc := range cfg.Stages {
		ctor, ok := enrichers[name]
		if !ok {
			return nil, fmt.Errorf("pipeline: unknown stage/enricher %q", name)
		}
		st := Stage{Enricher: ctor(timeout)}
		for _, e := range sc.Next {
			when := e.When
			if when == "" {
				when = "always"
			}
			sel, ok := selectors[when]
			if !ok {
				return nil, fmt.Errorf("pipeline: unknown selector %q in stage %q", e.When, name)
			}
			st.Next = append(st.Next, Edge{To: e.To, When: sel})
		}
		pl[name] = st
	}

	// Every edge target must be a defined stage.
	for name, st := range pl {
		for _, e := range st.Next {
			if _, ok := pl[e.To]; !ok {
				return nil, fmt.Errorf("pipeline: stage %q has an edge to undefined stage %q", name, e.To)
			}
		}
	}
	return pl, nil
}
