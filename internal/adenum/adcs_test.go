package adenum

import (
	"reflect"
	"testing"
)

// TestTemplatesFilter pins the query — the whole contract with AD is
// matching pKICertificateTemplate objects under the Configuration NC.
func TestTemplatesFilter(t *testing.T) {
	want := "(objectClass=pKICertificateTemplate)"
	if got := templatesFilter(); got != want {
		t.Errorf("templatesFilter() = %q, want %q", got, want)
	}
}

func TestTemplatesAttributes(t *testing.T) {
	want := []string{"cn", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"}
	if got := templatesAttributes(); !reflect.DeepEqual(got, want) {
		t.Errorf("templatesAttributes() = %v, want %v", got, want)
	}
}

// TestTemplatesBaseDN pins the Configuration NC derivation: templates are
// forest-wide, so the search base must be built from the default NC, not
// searched under it.
func TestTemplatesBaseDN(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"two-label domain", "DC=corp,DC=com",
			"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com"},
		{"three-label domain", "DC=lab,DC=corp,DC=com",
			"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=corp,DC=com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := templatesBaseDN(tc.in); got != tc.want {
				t.Errorf("templatesBaseDN(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEKUName(t *testing.T) {
	cases := []struct{ name, oid, want string }{
		{"server authentication", "1.3.6.1.5.5.7.3.1", "Server Authentication"},
		{"client authentication", "1.3.6.1.5.5.7.3.2", "Client Authentication"},
		{"smart card logon is the Microsoft-private OID", "1.3.6.1.4.1.311.20.2.2", "Smart Card Logon"},
		{"any purpose", "2.5.29.37.0", "Any Purpose"},
		{"pkinit client authentication", "1.3.6.1.5.2.3.4", "PKINIT Client Authentication"},
		{"kdc authentication", "1.3.6.1.5.2.3.5", "KDC Authentication"},
		{"certificate request agent", "1.3.6.1.4.1.311.20.2.1", "Certificate Request Agent"},
		// 1.3.6.1.5.5.7.3.14 is id-kp-eapOverLAN (RFC 4334), NOT Smart
		// Card Logon — it must stay raw.
		{"id-kp .14 is eapOverLAN, kept raw", "1.3.6.1.5.5.7.3.14", "1.3.6.1.5.5.7.3.14"},
		{"custom application policy stays raw", "1.3.6.1.4.1.99999.1.2.3", "1.3.6.1.4.1.99999.1.2.3"},
		{"empty string stays raw", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ekuName(tc.oid); got != tc.want {
				t.Errorf("ekuName(%q) = %q, want %q", tc.oid, got, tc.want)
			}
		})
	}
}

func TestMapEKUs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil input yields nil (the SubCA no-EKU case)", nil, nil},
		{"empty input yields nil", []string{}, nil},
		{
			"known OIDs map in directory order",
			[]string{"1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2"},
			[]string{"Smart Card Logon", "Client Authentication"},
		},
		{
			"unknown OIDs stay raw alongside friendly names",
			[]string{"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.99999.7"},
			[]string{"Client Authentication", "1.3.6.1.4.1.99999.7"},
		},
		{"any purpose", []string{"2.5.29.37.0"}, []string{"Any Purpose"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapEKUs(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mapEKUs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestEnrolleeSuppliesSubject pins the ESC1 bit:
// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is 0x00000001 of
// msPKI-Certificate-Name-Flag (MS-CRTD 2.28).
func TestEnrolleeSuppliesSubject(t *testing.T) {
	cases := []struct {
		name      string
		nameFlags uint32
		want      bool
	}{
		{"flag unset", 0x00000000, false},
		{"flag set alone", 0x00000001, true},
		{"flag set among other bits", 0x90000001, true},
		{"other bits only", 0x90000000, false},
		{"alt-name bit is not the subject bit", 0x00010000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enrolleeSuppliesSubject(tc.nameFlags); got != tc.want {
				t.Errorf("enrolleeSuppliesSubject(0x%08x) = %v, want %v", tc.nameFlags, got, tc.want)
			}
		})
	}
}

// TestParseUint32Attr covers the LDAP INTEGER representations: AD stores
// these flags as signed 32-bit integers, so a set top bit can arrive as a
// negative decimal string.
func TestParseUint32Attr(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want uint32
	}{
		{"unset attribute", "", 0},
		{"zero", "0", 0},
		{"plain flag value", "1", 1},
		{"typical user template name flags", "2684354560", 0xa0000000},
		{"max uint32", "4294967295", 0xffffffff},
		{"negative signed representation of top bit", "-2147483648", 0x80000000},
		{"negative signed representation of all bits", "-1", 0xffffffff},
		{"surrounding whitespace", " 1 ", 1},
		{"garbage", "notanumber", 0},
		{"overflow clamps to zero", "99999999999999999999", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseUint32Attr(tc.in); got != tc.want {
				t.Errorf("parseUint32Attr(%q) = 0x%08x, want 0x%08x", tc.in, got, tc.want)
			}
		})
	}
}
