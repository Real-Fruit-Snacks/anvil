package scan

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCertInfoFromX509(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		c    *x509.Certificate
		port int
		want TLSCertInfo
	}{
		{
			// Typical LDAPS leaf on a DC: enterprise-CA issuer, DNS SANs
			// pass straight through to the profile.
			"sans and issuer pass through",
			&x509.Certificate{
				Subject:  pkix.Name{CommonName: "dc01.lab.local"},
				Issuer:   pkix.Name{CommonName: "LAB-DC01-CA"},
				DNSNames: []string{"dc01.lab.local", "lab.local"},
				NotAfter: now.Add(90 * 24 * time.Hour),
			},
			636,
			TLSCertInfo{
				Port: 636, SubjectCN: "dc01.lab.local", IssuerCN: "LAB-DC01-CA",
				SANs:     []string{"dc01.lab.local", "lab.local"},
				NotAfter: now.Add(90 * 24 * time.Hour), DaysLeft: 90,
			},
		},
		{
			// int(hours/24) truncates: 36 hours left is one day, not two.
			"partial day truncates down",
			&x509.Certificate{NotAfter: now.Add(36 * time.Hour)},
			3389,
			TLSCertInfo{Port: 3389, NotAfter: now.Add(36 * time.Hour), DaysLeft: 1},
		},
		{
			"under a day reads zero days left",
			&x509.Certificate{NotAfter: now.Add(23 * time.Hour)},
			5986,
			TLSCertInfo{Port: 5986, NotAfter: now.Add(23 * time.Hour), DaysLeft: 0},
		},
		{
			// Expired: Expired carries the verdict, DaysLeft the magnitude.
			"expired cert reports negative days",
			&x509.Certificate{
				Subject:  pkix.Name{CommonName: "old.lab.local"},
				NotAfter: now.Add(-10 * 24 * time.Hour),
			},
			636,
			TLSCertInfo{
				Port: 636, SubjectCN: "old.lab.local",
				NotAfter: now.Add(-10 * 24 * time.Hour), Expired: true, DaysLeft: -10,
			},
		},
		{
			// Truncation toward zero on the negative side: an hour past
			// expiry is Expired=true with DaysLeft=0, not -1.
			"expired within the last day reads zero",
			&x509.Certificate{NotAfter: now.Add(-time.Hour)},
			3389,
			TLSCertInfo{Port: 3389, NotAfter: now.Add(-time.Hour), Expired: true, DaysLeft: 0},
		},
		{
			// Self-signed RDP-style leaf: no SANs at all stays nil, and
			// subject == issuer shows in the identical CN fields.
			"no sans stays nil",
			&x509.Certificate{
				Subject:  pkix.Name{CommonName: "WIN-ABC123"},
				Issuer:   pkix.Name{CommonName: "WIN-ABC123"},
				NotAfter: now.Add(180 * 24 * time.Hour),
			},
			3389,
			TLSCertInfo{
				Port: 3389, SubjectCN: "WIN-ABC123", IssuerCN: "WIN-ABC123",
				NotAfter: now.Add(180 * 24 * time.Hour), DaysLeft: 180,
			},
		},
	}
	for _, c := range cases {
		if got := certInfoFromX509(c.c, c.port, now); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: certInfoFromX509 = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestProbeTLSAgainstLoopbackServer runs the whole harvest — dial,
// handshake, leaf conversion — against a loopback TLS server. Hermetic:
// loopback only, no external network.
func TestProbeTLSAgainstLoopbackServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil) // handler is never reached; handshake only
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	info := probeTLS("127.0.0.1", []int{port}, 5*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error != "" {
		t.Errorf("Error = %q, want empty", info.Error)
	}
	if len(info.Certs) != 1 {
		t.Fatalf("len(Certs) = %d, want 1", len(info.Certs))
	}
	// Cross-check against the server's own leaf rather than hardcoding
	// the httptest fixture's contents.
	want := srv.Certificate()
	got := info.Certs[0]
	if got.Port != port {
		t.Errorf("Port = %d, want %d", got.Port, port)
	}
	if got.SubjectCN != want.Subject.CommonName || got.IssuerCN != want.Issuer.CommonName {
		t.Errorf("Subject/Issuer = %q/%q, want %q/%q",
			got.SubjectCN, got.IssuerCN, want.Subject.CommonName, want.Issuer.CommonName)
	}
	if !reflect.DeepEqual(got.SANs, want.DNSNames) {
		t.Errorf("SANs = %v, want %v", got.SANs, want.DNSNames)
	}
	if !got.NotAfter.Equal(want.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, want.NotAfter)
	}
	if got.Expired || got.DaysLeft <= 0 {
		t.Errorf("Expired/DaysLeft = %v/%d, want false/positive for a live cert", got.Expired, got.DaysLeft)
	}
}

// TestProbeTLSPartialFailureKeepsCerts exercises the core rule: a sibling
// port's failure must not darken one good handshake.
func TestProbeTLSPartialFailureKeepsCerts(t *testing.T) {
	closed := closedLoopbackPort(t)
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	good := srv.Listener.Addr().(*net.TCPAddr).Port

	info := probeTLS("127.0.0.1", []int{closed, good}, 5*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error != "" {
		t.Errorf("Error = %q, want empty when any port succeeded", info.Error)
	}
	if len(info.Certs) != 1 || info.Certs[0].Port != good {
		t.Errorf("Certs = %+v, want one entry for port %d", info.Certs, good)
	}
}

// TestProbeTLSAllPortsFail covers the two failure shapes — a refused dial
// and a listener speaking no TLS — and the all-failed error rule.
func TestProbeTLSAllPortsFail(t *testing.T) {
	closed := closedLoopbackPort(t)
	plain := httptest.NewServer(nil) // plaintext HTTP: TLS handshake dies
	defer plain.Close()
	plainPort := plain.Listener.Addr().(*net.TCPAddr).Port

	info := probeTLS("127.0.0.1", []int{closed, plainPort}, 5*time.Second)
	if info.Probed {
		t.Error("Probed = true, want false when every port failed")
	}
	if len(info.Certs) != 0 {
		t.Errorf("Certs = %+v, want empty", info.Certs)
	}
	// The first port's failure is the one reported, with its port named.
	if !strings.Contains(info.Error, "port "+strconv.Itoa(closed)) {
		t.Errorf("Error = %q, want it to name first failed port %d", info.Error, closed)
	}
}

func TestProbeTLSNoPorts(t *testing.T) {
	// The caller passes only open TLS ports; an empty set is a quiet no-op,
	// not an error.
	info := probeTLS("127.0.0.1", nil, time.Second)
	if info.Probed || info.Error != "" || len(info.Certs) != 0 {
		t.Errorf("probeTLS with no ports = %+v, want zero value", info)
	}
}

// closedLoopbackPort returns a loopback TCP port that was open a moment
// ago and is now closed, so dialing it is refused.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
