// Package pipeline wires the enrichment paliers into a graph: each stage runs an
// Enricher, and each outgoing edge carries a Selector deciding whether a host
// advances to the next stage after the current one completes. The graph is
// defined in Go for now (a config-file form is a later evolution).
package pipeline

import (
	"time"

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

// Default is the built-in graph:
//
//	light ──RespondedHTTP──▶ webinfo
//	      ──Always─────────▶ ptr
func Default(timeout time.Duration) Pipeline {
	return Pipeline{
		model.StageLight: {
			Enricher: enrich.NewLight(timeout),
			Next: []Edge{
				{To: model.StageWebinfo, When: enrich.RespondedHTTP},
				{To: model.StagePTR, When: enrich.Always},
			},
		},
		model.StageWebinfo: {Enricher: enrich.NewWebinfo(timeout)},
		model.StagePTR:     {Enricher: enrich.NewPTR()},
	}
}

// Stages returns all stage names in the pipeline.
func (p Pipeline) Stages() []string {
	out := make([]string, 0, len(p))
	for name := range p {
		out = append(out, name)
	}
	return out
}
