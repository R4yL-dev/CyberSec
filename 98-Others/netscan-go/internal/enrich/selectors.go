package enrich

import "netscan/internal/model"

// Selectors used to gate transitions between paliers. Each is an enrich.Selector
// (func(*model.HostRecord) bool) attached to a pipeline edge.

// Always advances every host.
func Always(*model.HostRecord) bool { return true }

// RespondedHTTP passes if any open port returned an HTTP status.
func RespondedHTTP(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p.HTTP != nil && p.HTTP.Status != 0 {
			return true
		}
	}
	return false
}

// HasTLS passes if any port presented a TLS certificate.
func HasTLS(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p.TLS != nil && p.TLS.Version != "" {
			return true
		}
	}
	return false
}

// HasNonHTTP passes if any open port produced no HTTP response — a candidate
// for non-web banner grabbing (light probes HTTP on every port, so a port with
// no HTTP status is one that didn't speak HTTP).
func HasNonHTTP(h *model.HostRecord) bool {
	for _, port := range h.OpenPorts {
		p := h.Ports[port]
		if p == nil || p.HTTP == nil || p.HTTP.Status == 0 {
			return true
		}
	}
	return false
}

// StatusOK passes if any port returned HTTP 200.
func StatusOK(h *model.HostRecord) bool {
	for _, p := range h.Ports {
		if p.HTTP != nil && p.HTTP.Status == 200 {
			return true
		}
	}
	return false
}
