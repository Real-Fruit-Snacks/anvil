package scan

import (
	"errors"
	"testing"
)

func TestChannelBindingStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil error", nil, "Never"},
		{"bad bindings", errors.New("data 80090346: SEC_E_BAD_BINDINGS"), "Always"},
		{"52e", errors.New("LDAP Result Code 49: data 52e"), "Never"},
		{"invalid creds text", errors.New("Invalid Credentials"), "Never"},
		{"strong auth", errors.New("Strong Auth Required"), "NTLM disabled on LDAPS"},
		{"strongerAuthRequired", errors.New("strongerAuthRequired"), "NTLM disabled on LDAPS"},
		// Unrecognized errors yield "" (unknown) — the UI suppresses the
		// field via omitempty rather than claiming a posture.
		{"other error", errors.New("connection reset"), ""},
	}
	for _, c := range cases {
		if got := channelBindingStatus(c.err); got != c.want {
			t.Errorf("%s: channelBindingStatus = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsStrongerAuthError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"LDAP Result Code 8 (strongerAuthRequired)", true},
		{"Strong Auth Required", true},
		{"server says STRONGER binds only", true},
		{"Invalid Credentials", false},
		{"connection refused", false},
	}
	for _, c := range cases {
		if got := isStrongerAuthError(errors.New(c.msg)); got != c.want {
			t.Errorf("isStrongerAuthError(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestFunctionalityLevel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// MS-ADTS DS_BEHAVIOR_* values 0–7 as returned by the root DSE.
		{"win2000", "0", "2000"},
		{"2003 interim", "1", "2003 interim"},
		{"2003", "2", "2003"},
		{"2008", "3", "2008"},
		{"2008 R2", "4", "2008 R2"},
		{"2012", "5", "2012"},
		{"2012 R2", "6", "2012 R2"},
		// Server 2016, 2019, and 2022 all report 7 — there is no 2019 or
		// 2022 functional level.
		{"2016/2019/2022", "7", "2016"},
		// Unmapped levels (8/9 never existed; 10 is Server 2025) render as
		// the raw number rather than a guessed name.
		{"unmapped 8", "8", "8"},
		{"server 2025", "10", "2025"},
		{"empty attribute", "", ""},
		{"surrounding whitespace", " 6 ", "2012 R2"},
		// A non-numeric value passes through verbatim — the UI shows what
		// the server said instead of dropping it.
		{"non-numeric", "abc", "abc"},
	}
	for _, c := range cases {
		if got := functionalityLevel(c.in); got != c.want {
			t.Errorf("%s: functionalityLevel(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestForestRootFromSchemaNC(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"typical AD DN", "CN=Schema,CN=Configuration,DC=hackerblueprint,DC=local", "hackerblueprint.local"},
		{"single-label root", "CN=Schema,CN=Configuration,DC=corp", "corp"},
		{"three-label root", "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com", "corp.example.com"},
		{"lowercase RDNs", "cn=schema,cn=configuration,dc=lab,dc=local", "lab.local"},
		{"mixed case preserved in labels", "CN=Schema,CN=Configuration,DC=Lab,DC=Local", "Lab.Local"},
		{"spaces after commas", "CN=Schema, CN=Configuration, DC=lab, DC=local", "lab.local"},
		{"empty input", "", ""},
		{"garbage input", "not a dn", ""},
		{"missing schema RDN", "CN=Configuration,DC=lab,DC=local", ""},
		{"missing configuration RDN", "CN=Schema,DC=lab,DC=local", ""},
		{"no DC RDNs after prefix", "CN=Schema,CN=Configuration", ""},
		{"non-DC RDN after prefix", "CN=Schema,CN=Configuration,OU=servers,DC=lab", ""},
		{"empty DC value", "CN=Schema,CN=Configuration,DC=", ""},
	}
	for _, c := range cases {
		if got := forestRootFromSchemaNC(c.in); got != c.want {
			t.Errorf("%s: forestRootFromSchemaNC(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
