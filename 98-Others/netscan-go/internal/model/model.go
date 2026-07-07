// Package model holds the types exchanged between the scanner's stages: the
// NDJSON record emitted by discovery (WireRecord) and the durable per-host
// state that accumulates through enrichment paliers (HostRecord).
package model

import (
	"net/netip"
	"time"
)

// Stage names for the domain-B work queue. v1 ships only the light palier;
// heavier paliers (and a targeted "recheck") plug in later without changing
// the queue or the store.
const (
	StageLight = "light"
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

	Status    map[string]string `json:"status,omitempty"` // per-stage status
	Attempts  int               `json:"attempts"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// PortInfo accumulates what each palier learns about a single open port.
type PortInfo struct {
	Port uint16    `json:"port"`
	HTTP *HTTPInfo `json:"http,omitempty"`
	TLS  *TLSInfo  `json:"tls,omitempty"`
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
