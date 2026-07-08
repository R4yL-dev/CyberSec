package enrich

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"

	jarm "github.com/hdm/jarm-go"

	"netscan/internal/model"
)

// tls_analyzers.go: the network-facing pieces of the tls-deep palier — version
// and cipher enumeration, chain capture, weak-crypto warnings, and the JARM
// active fingerprint.

var tlsVersions = []struct {
	name string
	ver  uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

// probeTLSVersions handshakes once per TLS version to learn which the server
// accepts and the cipher it negotiates for each, and captures the cert chain.
func probeTLSVersions(addr string, timeout time.Duration) *model.TLSDeepInfo {
	info := &model.TLSDeepInfo{Ciphers: map[string]string{}}
	captured := false
	for _, v := range tlsVersions {
		d := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.ver,
			MaxVersion:         v.ver,
		})
		if err != nil {
			continue
		}
		cs := conn.ConnectionState()
		info.Versions = append(info.Versions, v.name)
		info.Ciphers[v.name] = tls.CipherSuiteName(cs.CipherSuite)
		if !captured && len(cs.PeerCertificates) > 0 {
			info.Chain = certChain(cs.PeerCertificates)
			captured = true
		}
		conn.Close()
	}
	if len(info.Versions) == 0 {
		info.Error = "no TLS handshake succeeded"
		return info
	}
	info.Warnings = tlsWarnings(info)
	return info
}

func certChain(certs []*x509.Certificate) []model.CertSummary {
	now := time.Now()
	out := make([]model.CertSummary, 0, len(certs))
	for _, c := range certs {
		out = append(out, model.CertSummary{
			SubjectCN:  c.Subject.CommonName,
			Issuer:     c.Issuer.CommonName,
			NotBefore:  c.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
			SelfSigned: c.Subject.String() == c.Issuer.String(),
			Expired:    now.After(c.NotAfter) || now.Before(c.NotBefore),
		})
	}
	return out
}

func tlsWarnings(info *model.TLSDeepInfo) []string {
	var w []string
	for _, v := range info.Versions {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			w = append(w, "weak protocol: "+v)
		}
	}
	if len(info.Chain) > 0 {
		if leaf := info.Chain[0]; leaf.SelfSigned {
			w = append(w, "self-signed certificate")
		} else if info.Chain[0].Expired {
			w = append(w, "expired certificate")
		}
	}
	return w
}

// jarmZero is the JARM hash of a host that answered no probe (meaningless).
const jarmZero = "00000000000000000000000000000000000000000000000000000000000000"

// jarmFingerprint runs the 10 JARM probes and returns the fuzzy hash ("" if the
// target didn't respond to TLS).
func jarmFingerprint(host string, port int, timeout time.Duration) string {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	results := make([]string, 0, 10)
	for _, probe := range jarm.GetProbes(host, port) {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			results = append(results, "")
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write(jarm.BuildProbe(probe))
		buf := make([]byte, 1484)
		n, _ := conn.Read(buf)
		conn.Close()
		if n <= 0 {
			results = append(results, "")
			continue
		}
		ans, err := jarm.ParseServerHello(buf[:n], probe)
		if err != nil {
			ans = ""
		}
		results = append(results, ans)
	}
	h := jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	if h == jarmZero {
		return ""
	}
	return h
}
