package roast

import (
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/session"
)

// Kerberoast validates its inputs before opening any channel — these run
// without network by design.
func TestKerberoastRequiresDomain(t *testing.T) {
	_, _, err := Kerberoast("dc01.example.com", "EXAMPLE.COM", &session.Credentials{Username: "u", Password: "p"})
	if err == nil || !strings.Contains(err.Error(), "domain required") {
		t.Errorf("expected domain-required error, got %v", err)
	}
}

func TestHashShape(t *testing.T) {
	// The hashcat line contract: $krb5tgs$23$*user$realm$spn*$checksum$data.
	// (The line itself is produced by pkg/kerberos' formatTGSHash; Hash is
	// the thin wrapper we hand to the shell.)
	h := Hash{Username: "svc_archive", SPN: "HTTP/svc.lab.local", Line: "$krb5tgs$23$*svc_archive$LAB.LOCAL$HTTP/svc.lab.local*$0123456789abcdef0123456789abcdef$deadbeef"}
	if !strings.HasPrefix(h.Line, "$krb5tgs$23$*svc_archive$LAB.LOCAL$") {
		t.Errorf("unexpected hash line shape: %s", h.Line)
	}
}

// ASRep validates its inputs before opening any channel — these run
// without network by design.
func TestASRepRequiresDomain(t *testing.T) {
	_, _, err := ASRep("dc01.example.com", "EXAMPLE.COM", &session.Credentials{Username: "u", Password: "p"})
	if err == nil || !strings.Contains(err.Error(), "domain required") {
		t.Errorf("expected domain-required error, got %v", err)
	}
}

func TestASRepHashShape(t *testing.T) {
	// The hashcat line contract: $krb5asrep$23$user@REALM:checksum$data
	// (checksum is the first 16 bytes / 32 hex chars of the RC4 cipher).
	// The line itself is produced by pkg/kerberos' GetASREP; ASRepHash is
	// the thin wrapper we hand to the shell.
	h := ASRepHash{Username: "alice", Line: "$krb5asrep$23$alice@LAB.LOCAL:0123456789abcdef0123456789abcdef$deadbeef"}
	if !strings.HasPrefix(h.Line, "$krb5asrep$23$alice@LAB.LOCAL:") {
		t.Errorf("unexpected AS-REP hash line shape: %s", h.Line)
	}
}
