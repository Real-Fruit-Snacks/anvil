package ticket

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/etypeID"
)

// testdata/golden.ccache was forged by `anvil ticket` itself (dummy,
// well-known key material: the empty-password NT hash, lab.local,
// S-1-5-21-1004336348-1177238915-682003330, user Administrator) and
// testdata/golden.kirbi is `anvil convert`'s output on it. Both carry one
// RC4-HMAC TGT for Administrator@LAB.LOCAL -> krbtgt/LAB.LOCAL with flags
// forwardable+proxiable+renewable+initial+pre_authent (0x50e00000).
const (
	fixtureCCache = "golden.ccache"
	fixtureKirbi  = "golden.kirbi"

	wantClient = "Administrator"
	wantRealm  = "LAB.LOCAL"
	wantServer = "krbtgt/LAB.LOCAL"
	wantFlags  = 0x50e00000
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestSniffFormat(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"ccache fixture", readFixture(t, fixtureCCache), FormatCCache},
		{"kirbi fixture", readFixture(t, fixtureKirbi), FormatKirbi},
		{"empty", nil, FormatUnknown},
		{"ccache magic only", []byte{0x05}, FormatCCache},
		{"kirbi magic only", []byte{0x76}, FormatKirbi},
		{"text", []byte("not a ticket"), FormatUnknown},
		{"zero byte", []byte{0x00}, FormatUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SniffFormat(tc.data); got != tc.want {
				t.Errorf("SniffFormat = %v, want %v", got, tc.want)
			}
		})
	}
}

// checkGoldenEntry asserts the fields both fixture formats must agree on.
func checkGoldenEntry(t *testing.T, e Entry) {
	t.Helper()
	if e.Client != wantClient || e.ClientRealm != wantRealm {
		t.Errorf("client = %s@%s, want %s@%s", e.Client, e.ClientRealm, wantClient, wantRealm)
	}
	if e.Server != wantServer || e.ServerRealm != wantRealm {
		t.Errorf("server = %s@%s, want %s@%s", e.Server, e.ServerRealm, wantServer, wantRealm)
	}
	if e.SessionEType != etypeID.RC4_HMAC {
		t.Errorf("session etype = %d, want %d (rc4_hmac)", e.SessionEType, etypeID.RC4_HMAC)
	}
	if !e.TicketOK {
		t.Error("ticket blob did not parse")
	}
	if e.TicketEType != etypeID.RC4_HMAC {
		t.Errorf("ticket etype = %d, want %d (rc4_hmac)", e.TicketEType, etypeID.RC4_HMAC)
	}
	if e.Flags != wantFlags {
		t.Errorf("flags = 0x%08x, want 0x%08x", e.Flags, wantFlags)
	}
	for _, name := range []string{"forwardable", "proxiable", "renewable", "initial", "pre_authent"} {
		found := false
		for _, got := range e.FlagNames {
			if got == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("flag names %v missing %q", e.FlagNames, name)
		}
	}
	if e.StartTime.IsZero() || e.EndTime.IsZero() {
		t.Error("start/end time must be set")
	}
	// The forge grants the impacket-default ~10 year lifetime.
	if d := e.EndTime.Sub(e.StartTime); d < 87599*time.Hour || d > 87600*time.Hour {
		t.Errorf("ticket lifetime = %v, want ~87600h", d)
	}
}

func TestDescribeCCacheFixture(t *testing.T) {
	d, err := Describe(readFixture(t, fixtureCCache))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if d.Format != FormatCCache {
		t.Errorf("format = %v, want ccache", d.Format)
	}
	if d.Client != wantClient+"@"+wantRealm {
		t.Errorf("default client = %q, want %s@%s", d.Client, wantClient, wantRealm)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(d.Entries))
	}
	checkGoldenEntry(t, d.Entries[0])
	if d.Entries[0].AuthTime.IsZero() {
		t.Error("ccache auth time must be set")
	}
}

func TestDescribeKirbiFixture(t *testing.T) {
	d, err := Describe(readFixture(t, fixtureKirbi))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if d.Format != FormatKirbi {
		t.Errorf("format = %v, want kirbi", d.Format)
	}
	if d.Client != wantClient+"@"+wantRealm {
		t.Errorf("client = %q, want %s@%s", d.Client, wantClient, wantRealm)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(d.Entries))
	}
	checkGoldenEntry(t, d.Entries[0])
	// The kirbi form anvil/impacket write omits AuthTime (tag 4).
	if !d.Entries[0].AuthTime.IsZero() {
		t.Errorf("kirbi auth time = %v, want zero (not carried)", d.Entries[0].AuthTime)
	}
}

// trunc returns the first n bytes of data as an exact-size slice. Subslice
// capacity must not leak through: the gokrb5 ccache parser slices without
// bounds checks, and b[len:] only panics when cap is exhausted too.
func trunc(data []byte, n int) []byte {
	s := make([]byte, n)
	copy(s, data[:n])
	return s
}

func TestDescribeErrors(t *testing.T) {
	ccache := readFixture(t, fixtureCCache)
	kirbi := readFixture(t, fixtureKirbi)
	cases := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "empty file"},
		{"unknown magic", []byte("MZ\x90\x00"), "not a ccache or kirbi file"},
		{"truncated ccache header", trunc(ccache, 8), "invalid ccache"},
		{"truncated ccache mid-credential", trunc(ccache, len(ccache)/2), "invalid ccache"},
		{"truncated kirbi", trunc(kirbi, len(kirbi)/2), "invalid kirbi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Describe(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Describe error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBitStringFlags(t *testing.T) {
	cases := []struct {
		name string
		bs   asn1.BitString
		want uint32
	}{
		{"forwardable+initial", asn1.BitString{Bytes: []byte{0x40, 0x40, 0, 0}, BitLength: 32}, 0x40400000},
		{"all zero", asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, 0},
		{"short bitstring", asn1.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}, 0xffff0000},
		// pyasn1 (impacket) writes named KerberosFlags as BitLength 31 with
		// the value one bit high; the same bytes at BitLength 32 stay put.
		{"pyasn1 named bits", asn1.BitString{Bytes: []byte{0xa0, 0x20, 0, 0}, BitLength: 31}, 0x50100000},
		{"same bytes, bitlength 32", asn1.BitString{Bytes: []byte{0xa0, 0x20, 0, 0}, BitLength: 32}, 0xa0200000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bitStringFlags(tc.bs); got != tc.want {
				t.Errorf("bitStringFlags = 0x%08x, want 0x%08x", got, tc.want)
			}
		})
	}
}

func TestFlagNames(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want []string
	}{
		{"none", 0, nil},
		{"forwardable", 0x40000000, []string{"forwardable"}},
		{"golden set", wantFlags, []string{"forwardable", "proxiable", "renewable", "initial", "pre_authent"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := flagNames(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("flagNames(0x%08x) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("flagNames(0x%08x) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestETypeName(t *testing.T) {
	cases := []struct {
		in   int32
		want string
	}{
		{etypeID.AES256_CTS_HMAC_SHA1_96, "aes256_cts_hmac_sha1_96"},
		{etypeID.AES128_CTS_HMAC_SHA1_96, "aes128_cts_hmac_sha1_96"},
		{etypeID.RC4_HMAC, "rc4_hmac"},
		{etypeID.DES_CBC_MD5, "des_cbc_md5"},
		{1337, "etype_1337"},
	}
	for _, tc := range cases {
		if got := ETypeName(tc.in); got != tc.want {
			t.Errorf("ETypeName(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
