// Package enrich holds the domain-B enrichment modules. An Enricher augments a
// host record in place; each is one palier (a work-queue stage). Paliers are
// composed into a graph by internal/pipeline and gated by Selectors.
package enrich

import (
	"context"

	"netscan/internal/model"
)

// Enricher is one enrichment palier.
type Enricher interface {
	// Stage is the work-queue stage this enricher drains.
	Stage() string
	// Enrich augments host in place. It records per-target errors inside the
	// record rather than failing the whole item; it returns an error only when
	// the item genuinely could not be processed (and should be retried).
	Enrich(ctx context.Context, host *model.HostRecord) error
}

// Selector decides whether a host advances along a pipeline edge to the next
// palier (e.g. only hosts that answered HTTP advance to webinfo). Built-in
// predicates live in selectors.go.
type Selector func(*model.HostRecord) bool
