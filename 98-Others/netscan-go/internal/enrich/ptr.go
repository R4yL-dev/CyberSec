package enrich

import (
	"context"
	"net"
	"strings"

	"netscan/internal/model"
)

// PTR is a context palier: reverse-DNS the host. Cheap, non-web, independent of
// the HTTP paliers — the minimal example of a module that isn't web-shaped.
type PTR struct {
	resolver *net.Resolver
}

func NewPTR() *PTR { return &PTR{resolver: net.DefaultResolver} }

func (p *PTR) Stage() string { return model.StagePTR }

func (p *PTR) Enrich(ctx context.Context, host *model.HostRecord) error {
	names, err := p.resolver.LookupAddr(ctx, host.IP.String())
	if err == nil && len(names) > 0 { // no PTR is normal, not an error
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		host.PTR = names
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StagePTR] = "ok"
	return nil
}
