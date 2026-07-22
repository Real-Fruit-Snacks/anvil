package scan

import (
	"strings"
	"testing"
)

func TestParseProbeList(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []Probe // expected set members (nil = expect error)
		wantErr string  // substring; "" = no error
	}{
		{"single", "smb", []Probe{ProbeSMB}, ""},
		{"several", "smb,ldap,krb", []Probe{ProbeSMB, ProbeLDAP, ProbeKerberos}, ""},
		{"case and space tolerant", " SMB , Rpc ", []Probe{ProbeSMB, ProbeRPC}, ""},
		{"all nine", "smb,rpc,ldap,krb,nullsession,tls,adcs,tds,rdp",
			[]Probe{ProbeSMB, ProbeRPC, ProbeLDAP, ProbeKerberos, ProbeNullSession, ProbeTLS, ProbeADCS, ProbeTDS, ProbeRDP}, ""},
		{"duplicates collapse", "smb,smb", []Probe{ProbeSMB}, ""},
		{"unknown name", "smb,wmi", nil, "unknown probe"},
		{"error names valid probes", "wmi", nil, "smb, rpc, ldap, krb, nullsession, tls, adcs, tds, rdp"},
		{"only commas", ",,,", nil, "no valid probes"},
		{"empty", "", nil, "no valid probes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := ParseProbeList(c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("ParseProbeList(%q) err = %v, want substring %q", c.in, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProbeList(%q): %v", c.in, err)
			}
			if len(set) != len(c.want) {
				t.Fatalf("ParseProbeList(%q) size = %d, want %d", c.in, len(set), len(c.want))
			}
			for _, p := range c.want {
				if !set[p] {
					t.Errorf("ParseProbeList(%q) missing %q", c.in, p)
				}
			}
		})
	}
}

func TestSelectProbes(t *testing.T) {
	t.Run("neither selects all (nil)", func(t *testing.T) {
		set, err := SelectProbes("", "")
		if err != nil || set != nil {
			t.Errorf("SelectProbes(\"\", \"\") = %v, %v — want nil, nil", set, err)
		}
	})
	t.Run("both is a usage error", func(t *testing.T) {
		if _, err := SelectProbes("smb", "krb"); err == nil ||
			!strings.Contains(err.Error(), "cannot be used together") {
			t.Errorf("SelectProbes(smb, krb) err = %v, want both-flags error", err)
		}
	})
	t.Run("only whitelists", func(t *testing.T) {
		set, err := SelectProbes("smb,ldap", "")
		if err != nil {
			t.Fatal(err)
		}
		if !set[ProbeSMB] || !set[ProbeLDAP] || set[ProbeKerberos] || set[ProbeRPC] || set[ProbeNullSession] {
			t.Errorf("only smb,ldap → %v", set)
		}
	})
	t.Run("skip blacklists", func(t *testing.T) {
		set, err := SelectProbes("", "nullsession,krb")
		if err != nil {
			t.Fatal(err)
		}
		if set[ProbeNullSession] || set[ProbeKerberos] || !set[ProbeSMB] || !set[ProbeRPC] || !set[ProbeLDAP] {
			t.Errorf("skip nullsession,krb → %v", set)
		}
	})
	t.Run("skip everything is a bare port sweep", func(t *testing.T) {
		set, err := SelectProbes("", "smb,rpc,ldap,krb,nullsession,tls,adcs,tds,rdp")
		if err != nil {
			t.Fatal(err)
		}
		if len(set) != 0 {
			t.Errorf("skip all → %v, want empty set", set)
		}
		for _, p := range AllProbes {
			if (Options{Probes: set}).enabled(p) {
				t.Errorf("enabled(%q) true under skip-all", p)
			}
		}
	})
	t.Run("nil options enable everything", func(t *testing.T) {
		for _, p := range AllProbes {
			if !(Options{}).enabled(p) {
				t.Errorf("enabled(%q) false under nil Probes", p)
			}
		}
	})
}
