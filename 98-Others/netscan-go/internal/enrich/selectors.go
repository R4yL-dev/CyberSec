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

// HasNewPorts passes if an open port has no detect result yet — i.e. portscan
// found a port beyond what detect already classified. Gates the portscan →
// detect re-entry so it only fires (and re-enriches) when there is something new.
func HasNewPorts(h *model.HostRecord) bool {
	for _, p := range h.OpenPorts {
		if h.Ports == nil || h.Ports[p] == nil {
			return true
		}
	}
	return false
}

// HasTLS passes if any port speaks TLS: classified as https/tls by detect, OR
// with a cert already grabbed. Gating on the protocol (not only a successful
// cert grab) means tls-deep still runs when detect's quick cert fetch hiccuped
// (e.g. an SNI mismatch) — tls-deep does its own handshakes and can recover.
func HasTLS(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p == nil {
			continue
		}
		if p.Protocol == model.ProtoHTTPS || p.Protocol == model.ProtoTLS {
			return true
		}
		if p.TLS != nil && p.TLS.Version != "" {
			return true
		}
	}
	return false
}
