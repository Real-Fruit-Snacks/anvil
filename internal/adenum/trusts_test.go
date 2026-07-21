package adenum

import (
	"reflect"
	"testing"
)

// TestTrustsFilter pins the TDO query: trustedDomain objects live under
// CN=System in the domain NC, and a bare objectClass filter is how the
// reference tooling (netdom, PowerView's Get-DomainTrust) finds them.
func TestTrustsFilter(t *testing.T) {
	want := "(objectClass=trustedDomain)"
	if got := trustsFilter(); got != want {
		t.Errorf("trustsFilter() = %q, want %q", got, want)
	}
}

func TestTrustsAttributes(t *testing.T) {
	want := []string{"trustPartner", "trustDirection", "trustType", "trustAttributes"}
	if got := trustsAttributes(); !reflect.DeepEqual(got, want) {
		t.Errorf("trustsAttributes() = %v, want %v", got, want)
	}
}

// TestRenderTrustDirection covers every MS-ADTS trustDirection value plus
// the undefined range, which must fall through to the raw number.
func TestRenderTrustDirection(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"disabled", "0", "disabled"},
		{"inbound", "1", "inbound"},
		{"outbound", "2", "outbound"},
		{"bidirectional", "3", "bidirectional"},
		{"undefined value renders as the number", "4", "4"},
		{"large undefined value renders as the number", "17", "17"},
		{"non-numeric renders as-is", "garbage", "garbage"},
		{"empty renders as-is", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderTrustDirection(tc.in); got != tc.want {
				t.Errorf("renderTrustDirection(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRenderTrustType covers every MS-ADTS trustType value (1-5) plus the
// undefined range, which must fall through to the raw number.
func TestRenderTrustType(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"downlevel NT4 domain", "1", "downlevel"},
		{"uplevel AD domain", "2", "uplevel"},
		{"MIT kerberos realm", "3", "mit"},
		{"dce historical", "4", "dce"},
		{"azure ad", "5", "aad"},
		{"zero is undefined and renders as the number", "0", "0"},
		{"undefined value renders as the number", "6", "6"},
		{"non-numeric renders as-is", "garbage", "garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderTrustType(tc.in); got != tc.want {
				t.Errorf("renderTrustType(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRenderTrustAttributes exercises the flag-list rendering: no bits,
// single bits, real-world combos (forest trust, selective auth, external
// trust with SID filtering), and unnamed bits falling through to hex.
func TestRenderTrustAttributes(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"absent attribute renders none", "", "none"},
		{"zero renders none", "0", "none"},
		{"non-transitive alone", "1", "non-transitive"},
		{"external trust with SID filtering", "5", "non-transitive, quarantined"},
		{"forest trust", "8", "forest-transitive"},
		{"forest trust with selective authentication", "24", "forest-transitive, cross-org"},
		{"parent-child trust within forest", "32", "within-forest"},
		{"forest trust treated as external", "72", "forest-transitive, treat-as-external"},
		{"uplevel-only alone", "2", "uplevel-only"},
		{"unnamed RC4 bit renders as hex", "128", "0x00000080"},
		{"unnamed AES bit renders as hex", "256", "0x00000100"},
		{"named and unnamed bits both render", "136", "forest-transitive, 0x00000080"},
		{"non-numeric renders as-is", "garbage", "garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderTrustAttributes(tc.in); got != tc.want {
				t.Errorf("renderTrustAttributes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
