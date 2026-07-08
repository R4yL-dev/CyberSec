// Package geoip annotates IP addresses with country/city and ASN/organisation
// from MaxMind-DB-format files (DB-IP lite or MaxMind GeoLite2). Lookups are
// purely local (no network); a nil *Lookup or a Lookup with no DBs is safe and
// simply returns nothing.
package geoip

import (
	"net"
	"net/netip"

	geoip2 "github.com/oschwald/geoip2-golang"

	"netscan/internal/model"
)

// Lookup holds the optional geo (country/city) and ASN readers.
type Lookup struct {
	geo *geoip2.Reader
	asn *geoip2.Reader
}

// Open opens the given .mmdb files. A non-empty path that fails to open is
// skipped (geo is optional, never fatal). The returned Lookup may be a no-op.
func Open(geoPath, asnPath string) *Lookup {
	l := &Lookup{}
	if geoPath != "" {
		if r, err := geoip2.Open(geoPath); err == nil {
			l.geo = r
		}
	}
	if asnPath != "" {
		if r, err := geoip2.Open(asnPath); err == nil {
			l.asn = r
		}
	}
	return l
}

// Enabled reports whether at least one database loaded.
func (l *Lookup) Enabled() bool {
	return l != nil && (l.geo != nil || l.asn != nil)
}

// Annotate returns the geo/ASN info for ip, or nil if nothing is known.
func (l *Lookup) Annotate(ip netip.Addr) *model.GeoInfo {
	if !l.Enabled() {
		return nil
	}
	netIP := net.IP(ip.AsSlice())
	g := &model.GeoInfo{}
	if l.geo != nil {
		// Try a city DB first (country + city); fall back to a country-only DB.
		if c, err := l.geo.City(netIP); err == nil {
			g.Country = c.Country.IsoCode
			g.City = c.City.Names["en"]
		} else if c, err := l.geo.Country(netIP); err == nil {
			g.Country = c.Country.IsoCode
		}
	}
	if l.asn != nil {
		if a, err := l.asn.ASN(netIP); err == nil {
			g.ASN = a.AutonomousSystemNumber
			g.Org = a.AutonomousSystemOrganization
		}
	}
	if g.Country == "" && g.City == "" && g.ASN == 0 && g.Org == "" {
		return nil
	}
	return g
}

// Close releases the open databases.
func (l *Lookup) Close() {
	if l == nil {
		return
	}
	if l.geo != nil {
		_ = l.geo.Close()
	}
	if l.asn != nil {
		_ = l.asn.Close()
	}
}
