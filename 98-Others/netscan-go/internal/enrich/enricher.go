// Package enrich holds the domain-B paliers. An Enricher augments a host record
// in place; v1 ships only Light. Heavier paliers (and a targeted "recheck")
// implement the same interface and are chosen by stage name.
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

// Selector decides whether a host advances to a given palier. v1 has a single
// palier and gates nothing; multi-palier setups will attach a Selector per
// stage (e.g. only 200-OK hosts advance to the heavy palier).
type Selector func(*model.HostRecord) bool
