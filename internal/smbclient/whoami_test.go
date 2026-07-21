package smbclient

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc/lsarpc"
	"github.com/mandiant/gopacket/pkg/security"
)

// sidAttr marshals a string SID into the binary objectSid/tokenGroups LDAP
// attribute encoding (testSID lives in dacledit_test.go).
func sidAttr(t *testing.T, s string) []byte {
	t.Helper()
	return testSID(t, s).Marshal()
}

func TestParseTokenGroups(t *testing.T) {
	cases := []struct {
		name    string
		values  [][]byte
		want    []string
		wantErr string // substring of the expected error
	}{
		{
			name:   "single domain group",
			values: [][]byte{sidAttr(t, "S-1-5-21-1111-2222-3333-512")},
			want:   []string{"S-1-5-21-1111-2222-3333-512"},
		},
		{
			name: "multiple groups preserve attribute order",
			values: [][]byte{
				sidAttr(t, "S-1-5-21-1111-2222-3333-513"),
				sidAttr(t, "S-1-5-21-1111-2222-3333-512"),
				sidAttr(t, "S-1-5-21-1111-2222-3333-1104"),
			},
			want: []string{
				"S-1-5-21-1111-2222-3333-513",
				"S-1-5-21-1111-2222-3333-512",
				"S-1-5-21-1111-2222-3333-1104",
			},
		},
		{
			name:   "builtin group sid",
			values: [][]byte{sidAttr(t, "S-1-5-32-544")},
			want:   []string{"S-1-5-32-544"},
		},
		{
			name:   "zero sub-authorities",
			values: [][]byte{sidAttr(t, "S-1-5")},
			want:   []string{"S-1-5"},
		},
		{
			name:   "absent attribute",
			values: nil,
			want:   []string{},
		},
		{
			name:    "truncated value",
			values:  [][]byte{sidAttr(t, "S-1-5-21-1111-2222-3333-512")[:5]},
			wantErr: "value 0",
		},
		{
			name: "declared sub-authorities exceed buffer",
			values: [][]byte{{
				1, 3, 0, 0, 0, 0, 0, 5, // revision 1, 3 sub-auths claimed, authority 5
				0x15, 0, 0, 0, // only one sub-authority actually present
			}},
			wantErr: "value 0",
		},
		{
			name: "trailing garbage after sid",
			values: [][]byte{append(
				sidAttr(t, "S-1-5-21-1111-2222-3333-512"),
				0xde, 0xad, 0xbe, 0xef,
			)},
			wantErr: "trailing bytes",
		},
		{
			name: "corrupt second value reports its index",
			values: [][]byte{
				sidAttr(t, "S-1-5-21-1111-2222-3333-512"),
				sidAttr(t, "S-1-5-21-1111-2222-3333-513")[:4],
			},
			wantErr: "value 1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseTokenGroups(c.values)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("parseTokenGroups = %v, %v; want error containing %q", got, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTokenGroups: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseTokenGroups = %v, want %v", got, c.want)
			}
		})
	}
}

func TestQualifiedName(t *testing.T) {
	cases := []struct {
		name string
		res  lsarpc.LookupResult
		want string
	}{
		{"domain and name", lsarpc.LookupResult{Domain: "CORP", Name: "Domain Admins"}, "CORP\\Domain Admins"},
		{"user", lsarpc.LookupResult{Domain: "CORP", Name: "alice"}, "CORP\\alice"},
		{"empty domain", lsarpc.LookupResult{Name: "Administrators"}, "Administrators"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := qualifiedName(c.res); got != c.want {
				t.Errorf("qualifiedName(%+v) = %q, want %q", c.res, got, c.want)
			}
		})
	}
}

func TestSortResolvedGroups(t *testing.T) {
	cases := []struct {
		name  string
		input []ResolvedGroup
		want  []ResolvedGroup
	}{
		{
			name: "case-insensitive by name",
			input: []ResolvedGroup{
				{SID: "S-1-5-21-1-2-3-513", Name: "CORP\\domain users"},
				{SID: "S-1-5-21-1-2-3-512", Name: "CORP\\Domain Admins"},
				{SID: "S-1-5-21-1-2-3-519", Name: "CORP\\enterprise admins"},
			},
			want: []ResolvedGroup{
				{SID: "S-1-5-21-1-2-3-512", Name: "CORP\\Domain Admins"},
				{SID: "S-1-5-21-1-2-3-513", Name: "CORP\\domain users"},
				{SID: "S-1-5-21-1-2-3-519", Name: "CORP\\enterprise admins"},
			},
		},
		{
			name: "same name ties break by sid",
			input: []ResolvedGroup{
				{SID: "S-1-5-21-1-2-3-513", Name: "CORP\\Users"},
				{SID: "S-1-5-32-545", Name: "BUILTIN\\Users"},
			},
			want: []ResolvedGroup{
				{SID: "S-1-5-32-545", Name: "BUILTIN\\Users"},
				{SID: "S-1-5-21-1-2-3-513", Name: "CORP\\Users"},
			},
		},
		{
			name: "unresolved groups tie-break by sid",
			input: []ResolvedGroup{
				{SID: "S-1-5-21-9-9-9-2000", Name: ""},
				{SID: "S-1-5-21-9-9-9-1000", Name: ""},
			},
			want: []ResolvedGroup{
				{SID: "S-1-5-21-9-9-9-1000", Name: ""},
				{SID: "S-1-5-21-9-9-9-2000", Name: ""},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sortResolvedGroups(c.input)
			if !reflect.DeepEqual(c.input, c.want) {
				t.Errorf("sortResolvedGroups = %+v, want %+v", c.input, c.want)
			}
		})
	}
}

// TestParseSIDAttr exercises the single-value decoder parseTokenGroups wraps
// (objectSid is single-valued; tokenGroups multi-valued).
func TestParseSIDAttr(t *testing.T) {
	cases := []struct {
		name    string
		value   []byte
		want    string
		wantErr string
	}{
		{"domain user sid", sidAttr(t, "S-1-5-21-1111-2222-3333-1104"), "S-1-5-21-1111-2222-3333-1104", ""},
		{"well-known sid", sidAttr(t, "S-1-5-18"), "S-1-5-18", ""},
		{"empty attribute", nil, "", "empty"},
		{"too short for a header", []byte{1, 0, 0}, "", "too short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseSIDAttr(c.value)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("parseSIDAttr = %q, %v; want error containing %q", got, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSIDAttr: %v", err)
			}
			if got != c.want {
				t.Errorf("parseSIDAttr = %q, want %q", got, c.want)
			}
		})
	}
}

// Guard: the hand-built fixture in TestParseTokenGroups really is the wire
// encoding security.ParseSIDBytes expects for S-1-5-21 (authority 5, one
// sub-authority 21).
func TestSIDAttrEncodingSanity(t *testing.T) {
	raw := sidAttr(t, "S-1-5-21")
	want := []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}
	if !reflect.DeepEqual(raw, want) {
		t.Fatalf("sidAttr(S-1-5-21) = %v, want wire bytes %v", raw, want)
	}
	if _, _, err := security.ParseSIDBytes(raw); err != nil {
		t.Fatalf("ParseSIDBytes rejected its own Marshal output: %v", err)
	}
}
