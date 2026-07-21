package scan

// TLS certificate harvest model: the certificates themselves are the
// finding, so they are captured, never trust-validated.
//
//   - InsecureSkipVerify is deliberate. AD-internal PKI is self-signed by
//     default: LDAPS on a DC presents a cert issued by the domain's own
//     enterprise CA, RDP presents a self-signed per-host cert until an
//     admin deploys one, and WinRM HTTPS is commonly a self-signed
//     listener cert. Chain validation would fail against virtually every
//     AD target and report nothing; what a scan needs is the identity the
//     service *claims* (subject CN, SANs, issuer) and its validity
//     window — an enterprise-CA issuer name is itself an AD CS tell.
//   - Exactly one TLS handshake per port. All three services complete
//     TLS before any protocol bytes: LDAPS (636) is TLS from the first
//     octet, WinRM (5986) is plain HTTPS, and RDP (3389) opens with TLS
//     under the default Negotiate/TLS security layer. A server pinned to
//     the legacy RDP security layer answers with non-TLS bytes, the
//     handshake fails, and the port is simply skipped — that is the
//     per-port failure path working as designed, not a probe bug.
//   - ServerName is set to the scan target so a name-aware listener can
//     select the right cert via SNI; Go suppresses SNI for IP literals
//     (RFC 6066 forbids literal IPv4/IPv6 SNI), which is the correct
//     behavior either way.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"
)

// probeTLS harvests the leaf TLS certificate from each port in ports —
// the caller passes the open subset of the TLS-bearing AD services
// (636 LDAPS, 3389 RDP, 5986 WinRM HTTPS). Ports are probed sequentially:
// three quick handshakes do not justify goroutines, and sequential keeps
// the probe's traffic trivially attributable.
//
// Per-port failures (handshake error, a listener speaking no TLS, a
// server presenting no certificate) skip that port and are remembered;
// the first error becomes TLSInfo.Error only when EVERY port failed, so
// one good handshake — Probed=true plus its Certs entry — is never
// darkened by a sibling port's failure.
func probeTLS(target string, ports []int, timeout time.Duration) *TLSInfo {
	info := &TLSInfo{}
	var firstErr error
	firstPort := 0

	for _, port := range ports {
		leaf, err := harvestLeaf(target, port, timeout)
		if err != nil {
			if firstErr == nil {
				firstErr = err
				firstPort = port
			}
			continue
		}
		info.Certs = append(info.Certs, certInfoFromX509(leaf, port, time.Now()))
	}

	if len(info.Certs) > 0 {
		info.Probed = true
	} else if firstErr != nil {
		// Every port failed: report the first failure with its port for
		// context. With no ports at all there is nothing to report —
		// Probed stays false and Error stays empty.
		info.Error = fmt.Sprintf("port %d: %v", firstPort, firstErr)
	}
	return info
}

// harvestLeaf performs one TLS handshake against target:port and returns
// the leaf certificate the server presented. The handshake is the whole
// interaction: tls.DialWithDialer completes it before returning (the
// dialer's timeout covers connect and handshake together), and the
// connection is closed without a single application byte.
func harvestLeaf(target string, port int, timeout time.Duration) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp",
		net.JoinHostPort(target, strconv.Itoa(port)),
		&tls.Config{
			InsecureSkipVerify: true, // harvest, not validation — see file header
			ServerName:         target,
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		// InsecureSkipVerify does not stop the server from sending its
		// chain; an empty list means the handshake completed without one
		// (anonymous cipher, or a confused listener). Not a cert we can
		// report, so the port counts as failed.
		return nil, fmt.Errorf("server presented no certificate")
	}
	return peers[0], nil
}

// certInfoFromX509 reduces one parsed certificate to the identity and
// validity fields the profile reports. now is injected so the expiry
// verdict is testable. DaysLeft truncates toward zero: 36 hours to expiry
// reads 1, and 36 hours past expiry reads -1 — so Expired carries the
// definitive verdict and DaysLeft the magnitude. SANs are the DNS names
// only; IP SANs are not reported.
func certInfoFromX509(c *x509.Certificate, port int, now time.Time) TLSCertInfo {
	return TLSCertInfo{
		Port:      port,
		SubjectCN: c.Subject.CommonName,
		IssuerCN:  c.Issuer.CommonName,
		SANs:      c.DNSNames,
		NotAfter:  c.NotAfter,
		Expired:   now.After(c.NotAfter),
		DaysLeft:  int(c.NotAfter.Sub(now).Hours() / 24),
	}
}
