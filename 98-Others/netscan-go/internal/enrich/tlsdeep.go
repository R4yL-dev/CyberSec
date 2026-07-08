package enrich

import (
	"context"
	"net/netip"
	"time"

	"netscan/internal/model"
)

// TLSDeep is a fingerprinting palier: for each TLS port it enumerates supported
// versions/ciphers, captures the cert chain, computes a JARM fingerprint, and
// flags weak crypto. It runs after light on hosts the HasTLS selector let
// through (roughly one handshake per version + JARM's ten — hence gated).
type TLSDeep struct {
	Timeout time.Duration
}

func NewTLSDeep(timeout time.Duration) *TLSDeep { return &TLSDeep{Timeout: timeout} }

func (t *TLSDeep) Stage() string { return model.StageTLSDeep }

func (t *TLSDeep) Enrich(ctx context.Context, host *model.HostRecord) error {
	for _, port := range host.OpenPorts {
		if ctx.Err() != nil {
			break
		}
		pi := host.Ports[port]
		if pi == nil || pi.TLS == nil || pi.TLS.Version == "" {
			continue // light saw no TLS on this port
		}
		addr := netip.AddrPortFrom(host.IP, port).String()
		info := probeTLSVersions(addr, t.Timeout)
		info.JARM = jarmFingerprint(host.IP.String(), int(port), t.Timeout)
		pi.TLSDeep = info
	}
	if host.Status == nil {
		host.Status = make(map[string]string, 1)
	}
	host.Status[model.StageTLSDeep] = "ok"
	return nil
}
