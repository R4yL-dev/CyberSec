package enrich

import "netscan/internal/model"

// Selectors gate pipeline edges on the protocol detected by the detect palier.
// Each is an enrich.Selector (func(*model.HostRecord) bool) on a pipeline edge.

// Always advances every host.
func Always(*model.HostRecord) bool { return true }

// IsWeb passes if any port speaks HTTP or HTTPS.
func IsWeb(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p != nil && (p.Protocol == model.ProtoHTTP || p.Protocol == model.ProtoHTTPS) {
			return true
		}
	}
	return false
}

// NeedsPortscan passes if the deep port scan hasn't run yet (loop guard for the
// portscan → detect re-entry: portscan runs at most once per host).
func NeedsPortscan(h *model.HostRecord) bool {
	_, done := h.Status[model.StagePortscan]
	return !done
}

// HasTLS passes if any port completed a TLS handshake (on any port, not just
// 443) — detect records a cert summary whenever TLS is present.
func HasTLS(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p != nil && p.TLS != nil && p.TLS.Version != "" {
			return true
		}
	}
	return false
}
