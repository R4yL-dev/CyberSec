package enrich

import (
	"net/netip"
	"testing"

	"netscan/internal/model"
)

func hostWith(pi *model.PortInfo) *model.HostRecord {
	return &model.HostRecord{
		IP:    netip.MustParseAddr("1.1.1.1"),
		Ports: map[uint16]*model.PortInfo{pi.Port: pi},
	}
}

func TestSelectors(t *testing.T) {
	http := hostWith(&model.PortInfo{Port: 80, Protocol: model.ProtoHTTP})
	https := hostWith(&model.PortInfo{Port: 443, Protocol: model.ProtoHTTPS, TLS: &model.TLSInfo{Version: "TLS 1.3"}})
	tlsOnly := hostWith(&model.PortInfo{Port: 8443, Protocol: model.ProtoTLS, TLS: &model.TLSInfo{Version: "TLS 1.2"}})
	ssh := hostWith(&model.PortInfo{Port: 22, Protocol: model.ProtoSSH})

	if !Always(ssh) {
		t.Fatal("Always must always pass")
	}
	if !IsWeb(http) || !IsWeb(https) {
		t.Fatal("IsWeb must pass for http and https")
	}
	if IsWeb(ssh) || IsWeb(tlsOnly) {
		t.Fatal("IsWeb must fail for non-web protocols")
	}
	if !HasTLS(https) || !HasTLS(tlsOnly) {
		t.Fatal("HasTLS must pass whenever a cert summary is present (any port)")
	}
	if HasTLS(http) || HasTLS(ssh) {
		t.Fatal("HasTLS must fail without TLS")
	}
}
