// Package model holds the types exchanged between the scanner's stages: the
// NDJSON record emitted by discovery (WireRecord) and the durable per-host
// state that accumulates through enrichment paliers (HostRecord).
package model

import (
	"net/netip"
	"time"
)

// Stage names for the domain-B work queue — one per enrichment palier. New
// paliers add a constant here and an entry in internal/pipeline.
const (
	StageLight   = "light"    // cheap HTTP probe + TLS summary (entry palier)
	StageWebinfo = "webinfo"  // richer HTTP fetch + analyzers (tech, headers, favicon)
	StagePTR     = "ptr"      // reverse DNS
	StageTLSDeep = "tls-deep" // deep TLS: chain, versions/ciphers, JARM
)

// WireRecord is one line of NDJSON: what ns-discover emits for a responding
// host and what ns-ingest reads into the store.
type WireRecord struct {
	IP           netip.Addr `json:"ip"`
	OpenPorts    []uint16   `json:"open_ports"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// HostRecord is the durable per-host state in the store. Enrichment paliers
// accumulate into Ports; the bookkeeping fields drive re-entrance (retries,
// per-stage status, freshness).
type HostRecord struct {
	IP        netip.Addr           `json:"ip"`
	OpenPorts []uint16             `json:"open_ports"`
	Ports     map[uint16]*PortInfo `json:"ports,omitempty"`

	PTR       []string          `json:"ptr,omitempty"`    // reverse DNS names
	Geo       *GeoInfo          `json:"geo,omitempty"`    // country/ASN, set once at ingest
	Status    map[string]string `json:"status,omitempty"` // per-stage status
	Attempts  int               `json:"attempts"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// GeoInfo is IP-level context resolved locally at ingest (not a palier):
// country/city from a GeoIP DB and ASN/organisation from an ASN DB.
type GeoInfo struct {
	Country string `json:"country,omitempty"` // ISO country code
	City    string `json:"city,omitempty"`
	ASN     uint   `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
}

// Merge folds another record's enrichment into h, field by field, so the store
// can combine updates from paliers that ran concurrently on the same host
// without one clobbering the other. Only non-empty incoming fields win.
func (h *HostRecord) Merge(in *HostRecord) {
	if h.Ports == nil {
		h.Ports = make(map[uint16]*PortInfo, len(in.Ports))
	}
	for port, pin := range in.Ports {
		pe := h.Ports[port]
		if pe == nil {
			pe = &PortInfo{Port: port}
			h.Ports[port] = pe
		}
		if pin.HTTP != nil {
			pe.HTTP = pin.HTTP
		}
		if pin.TLS != nil {
			pe.TLS = pin.TLS
		}
		if pin.Web != nil {
			pe.Web = pin.Web
		}
		if pin.TLSDeep != nil {
			pe.TLSDeep = pin.TLSDeep
		}
	}
	if len(in.Status) > 0 {
		if h.Status == nil {
			h.Status = make(map[string]string, len(in.Status))
		}
		for k, v := range in.Status {
			h.Status[k] = v
		}
	}
	if len(in.PTR) > 0 {
		h.PTR = in.PTR
	}
	if in.Attempts > h.Attempts {
		h.Attempts = in.Attempts
	}
}

// PortInfo accumulates what each palier learns about a single open port.
type PortInfo struct {
	Port    uint16       `json:"port"`
	HTTP    *HTTPInfo    `json:"http,omitempty"`
	TLS     *TLSInfo     `json:"tls,omitempty"`
	Web     *WebInfo     `json:"web,omitempty"`
	TLSDeep *TLSDeepInfo `json:"tls_deep,omitempty"`
}

// TLSDeepInfo holds the derived results of the tls-deep palier: supported
// versions, negotiated cipher per version, the full cert chain, a JARM
// fingerprint, and weak-crypto warnings.
type TLSDeepInfo struct {
	Versions []string          `json:"versions,omitempty"`
	Ciphers  map[string]string `json:"ciphers,omitempty"` // version -> negotiated cipher
	Chain    []CertSummary     `json:"chain,omitempty"`
	JARM     string            `json:"jarm,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// CertSummary is one certificate in the chain.
type CertSummary struct {
	SubjectCN  string `json:"subject_cn,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
}

// WebInfo holds the derived results of the webinfo palier (a richer HTTP fetch
// than light): only small, extracted data — never the raw body.
type WebInfo struct {
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         []string          `json:"cookies,omitempty"`
	Technologies    []string          `json:"technologies,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	FaviconHash     string            `json:"favicon_hash,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// HTTPInfo mirrors the light HTTP probe (port of probe_http in netscan.py).
type HTTPInfo struct {
	URL       string     `json:"url"`
	Status    int        `json:"status,omitempty"`
	Server    string     `json:"server,omitempty"`
	Title     string     `json:"title,omitempty"`
	Redirects []Redirect `json:"redirects,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Redirect is one hop in an HTTP redirect chain.
type Redirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
}

// TLSInfo mirrors the certificate summary (port of get_tls_cert in netscan.py).
type TLSInfo struct {
	Version   string   `json:"tls_version,omitempty"`
	SubjectCN string   `json:"subject_cn,omitempty"`
	SAN       []string `json:"san,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Error     string   `json:"error,omitempty"`
}
