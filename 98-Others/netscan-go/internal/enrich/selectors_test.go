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
	http200 := hostWith(&model.PortInfo{Port: 80, HTTP: &model.HTTPInfo{Status: 200}})
	http500 := hostWith(&model.PortInfo{Port: 80, HTTP: &model.HTTPInfo{Status: 500}})
	noResp := hostWith(&model.PortInfo{Port: 80, HTTP: &model.HTTPInfo{Status: 0}})
	tlsHost := hostWith(&model.PortInfo{Port: 443, TLS: &model.TLSInfo{Version: "TLS 1.3"}})

	if !Always(noResp) {
		t.Fatal("Always must always pass")
	}
	if !RespondedHTTP(http200) || !RespondedHTTP(http500) {
		t.Fatal("RespondedHTTP must pass for any non-zero status")
	}
	if RespondedHTTP(noResp) {
		t.Fatal("RespondedHTTP must fail for status 0")
	}
	if !StatusOK(http200) {
		t.Fatal("StatusOK must pass for 200")
	}
	if StatusOK(http500) {
		t.Fatal("StatusOK must fail for 500")
	}
	if !HasTLS(tlsHost) {
		t.Fatal("HasTLS must pass with a TLS version")
	}
	if HasTLS(http200) {
		t.Fatal("HasTLS must fail without TLS")
	}
}
