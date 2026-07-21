package scan

import (
	"strings"
	"testing"
)

func TestDCStringToDomain(t *testing.T) {
	cases := []struct {
		name string
		dn   string
		want string
	}{
		{"naming context", "DC=hackerblueprint,DC=local", "hackerblueprint.local"},
		{"lowercase prefix", "dc=lab,dc=local", "lab.local"},
		{"spaces tolerated", "DC=corp, DC=example, DC=com", "corp.example.com"},
		{"non-DC RDNs skipped", "CN=Users,DC=corp,DC=local", "corp.local"},
		{"no DC parts", "CN=Schema,CN=Configuration", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dcStringToDomain(c.dn); got != c.want {
				t.Errorf("dcStringToDomain(%q) = %q, want %q", c.dn, got, c.want)
			}
		})
	}
}

func TestShortIfaceName(t *testing.T) {
	cases := []struct {
		name string
		uuid string
		want string
	}{
		{"coercion interface", "12345678-1234-abcd-ef00-0123456789ab", "MS-RPRN"},
		{"plain interface", "12345778-1234-abcd-ef00-0123456789ac", "MS-SAMR"},
		{"uppercase normalized", "12345678-1234-ABCD-EF00-0123456789AB", "MS-RPRN"},
		{"no parenthetical falls back to annotation", "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "RPC Endpoint Mapper"},
		{"unknown uuid passes through", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shortIfaceName(c.uuid); got != c.want {
				t.Errorf("shortIfaceName(%q) = %q, want %q", c.uuid, got, c.want)
			}
		})
	}
}

func TestFormatSkew(t *testing.T) {
	cases := []struct {
		name string
		secs int64
		want string
	}{
		{"positive minutes", 372, "+6m12s"},
		{"negative", -45, "-45s"},
		{"zero", 0, "+0s"},
		{"sub-minute positive", 5, "+5s"},
		{"hours", 3661, "+1h1m1s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := formatSkew(c.secs); got != c.want {
				t.Errorf("formatSkew(%d) = %q, want %q", c.secs, got, c.want)
			}
		})
	}
}

func TestRealmHint(t *testing.T) {
	cases := []struct {
		name string
		p    *TargetProfile
		want string
	}{
		{"smb dns domain wins", &TargetProfile{
			SMB:  &SMBInfo{DNSDomain: "corp.local"},
			LDAP: &LDAPInfo{NamingContext: "DC=other,DC=local"},
		}, "corp.local"},
		{"ldap fallback", &TargetProfile{
			LDAP: &LDAPInfo{NamingContext: "DC=lab,DC=local"},
		}, "lab.local"},
		{"nothing known", &TargetProfile{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := realmHint(c.p); got != c.want {
				t.Errorf("realmHint() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildHintsNewSignals(t *testing.T) {
	skew := int64(400)
	p := &TargetProfile{
		SMB: &SMBInfo{SkewSeconds: &skew},
		RPC: &RPCInfo{Endpoints: []Endpoint{
			{UUID: "12345678-1234-abcd-ef00-0123456789ab"}, // MS-RPRN
			{UUID: "c681d488-d850-11d0-8c52-00c04fd90f7e"}, // MS-EFSR (lsarpc pipe)
			{UUID: "df1941c5-fe89-4e79-bf10-463657acf44d"}, // MS-EFSR (efsrpc pipe)
		}},
		LDAP:        &LDAPInfo{NamingContext: "DC=lab,DC=local", ForestRoot: "lab.local"},
		NullSession: &NullSessionInfo{Probed: true, SigningBlocked: true, Error: "null session accepted but blocked by client signing requirement"},
	}
	hints := buildHints(p, func(int) bool { return false })
	joined := ""
	for _, h := range hints {
		joined += h + "\n"
	}
	for _, want := range []string{
		"clock skew +6m40s breaks kerberos",
		"MS-RPRN exposed (PrinterBug coercion target)",
		"MS-EFSR exposed (PetitPotam coercion target)",
		"target is a forest-root DC",
		"null session accepted by target",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("hints missing %q — got:\n%s", want, joined)
		}
	}
	// The two MS-EFSR UUIDs must collapse into one hint.
	if n := strings.Count(joined, "PetitPotam"); n != 1 {
		t.Errorf("MS-EFSR dedupe failed — PetitPotam appears %d times", n)
	}
}
