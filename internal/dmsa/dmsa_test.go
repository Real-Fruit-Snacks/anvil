package dmsa

import (
	"bytes"
	"encoding/asn1"
	"os"
	"reflect"
	"testing"
	"time"
)

// Fixture values, duplicated from the generator (testdata/keypackage.der)
// on purpose: the fixture parse test is only meaningful if the expected
// data is stated independently of the marshaling code.
var (
	fixtCurrentRC4    = bytes.Repeat([]byte{0xA1}, 16)
	fixtCurrentAES256 = bytes.Repeat([]byte{0xB1}, 32)
	fixtCurrentAES128 = bytes.Repeat([]byte{0xC1}, 16)
	fixtPreviousRC4   = bytes.Repeat([]byte{0xD1}, 16)
	fixtExpiration    = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fixtFetch         = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
)

func fixturePackage() *KeyPackage {
	return &KeyPackage{
		CurrentKeys: []EncryptionKey{
			{Type: ETypeRC4, Value: fixtCurrentRC4},
			{Type: ETypeAES256, Value: fixtCurrentAES256},
			{Type: ETypeAES128, Value: fixtCurrentAES128},
		},
		PreviousKeys: []EncryptionKey{
			{Type: ETypeRC4, Value: fixtPreviousRC4},
		},
		ExpirationInterval: fixtExpiration,
		FetchInterval:      fixtFetch,
	}
}

// TestParseKeyPackageFixture parses the on-disk fixture (built by a
// generator from independent values) and checks every field.
func TestParseKeyPackageFixture(t *testing.T) {
	der, err := os.ReadFile("testdata/keypackage.der")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := ParseKeyPackage(der)
	if err != nil {
		t.Fatalf("ParseKeyPackage: %v", err)
	}

	if len(p.CurrentKeys) != 3 {
		t.Fatalf("current-keys: got %d, want 3", len(p.CurrentKeys))
	}
	wantCurrent := []EncryptionKey{
		{ETypeRC4, fixtCurrentRC4},
		{ETypeAES256, fixtCurrentAES256},
		{ETypeAES128, fixtCurrentAES128},
	}
	for i, w := range wantCurrent {
		if p.CurrentKeys[i].Type != w.Type || !bytes.Equal(p.CurrentKeys[i].Value, w.Value) {
			t.Errorf("current-keys[%d]: got (%d, %x), want (%d, %x)",
				i, p.CurrentKeys[i].Type, p.CurrentKeys[i].Value, w.Type, w.Value)
		}
	}

	if len(p.PreviousKeys) != 1 || p.PreviousKeys[0].Type != ETypeRC4 ||
		!bytes.Equal(p.PreviousKeys[0].Value, fixtPreviousRC4) {
		t.Errorf("previous-keys: got %+v, want one RC4 key %x", p.PreviousKeys, fixtPreviousRC4)
	}
	if !p.ExpirationInterval.Equal(fixtExpiration) {
		t.Errorf("expiration-interval: got %v, want %v", p.ExpirationInterval, fixtExpiration)
	}
	if !p.FetchInterval.Equal(fixtFetch) {
		t.Errorf("fetch-interval: got %v, want %v", p.FetchInterval, fixtFetch)
	}
}

// TestKeyPackageRoundTrip marshals and re-parses, checking the bytes are
// identical (DER is canonical for these structures).
func TestKeyPackageRoundTrip(t *testing.T) {
	p := fixturePackage()
	der := p.Marshal()
	p2, err := ParseKeyPackage(der)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !reflect.DeepEqual(p.CurrentKeys, p2.CurrentKeys) ||
		!reflect.DeepEqual(p.PreviousKeys, p2.PreviousKeys) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", p2, p)
	}
	if !p2.ExpirationInterval.Equal(p.ExpirationInterval) || !p2.FetchInterval.Equal(p.FetchInterval) {
		t.Errorf("round-trip times: got %v / %v", p2.ExpirationInterval, p2.FetchInterval)
	}
	if !bytes.Equal(p2.Marshal(), der) {
		t.Errorf("re-marshal not byte-identical")
	}
}

// TestKeyPackageTags pins the wire layout: context tags 0,1,2,4 must be
// present (4, not 3, for fetch-interval — MS-KILE 2.2.14) and each must
// wrap the right type.
func TestKeyPackageTags(t *testing.T) {
	der := fixturePackage().Marshal()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	seen := map[int]bool{}
	for body := seq.Bytes; len(body) > 0; {
		var f asn1.RawValue
		var err error
		body, err = asn1.Unmarshal(body, &f)
		if err != nil {
			t.Fatalf("field: %v", err)
		}
		if f.Class != asn1.ClassContextSpecific {
			t.Fatalf("non-context tag class %d", f.Class)
		}
		seen[f.Tag] = true
	}
	for _, tag := range []int{0, 1, 2, 4} {
		if !seen[tag] {
			t.Errorf("missing context tag %d", tag)
		}
	}
	if seen[3] {
		t.Errorf("tag 3 present — fetch-interval must use tag 4 per MS-KILE")
	}
}

// TestParseKeyPackageStandalone covers a dMSA that never superseded an
// account: previous-keys is absent (Rubeus PR #204 fixed a crash on this
// exact shape).
func TestParseKeyPackageStandalone(t *testing.T) {
	p := &KeyPackage{
		CurrentKeys:        []EncryptionKey{{Type: ETypeAES256, Value: fixtCurrentAES256}},
		ExpirationInterval: fixtExpiration,
		FetchInterval:      fixtFetch,
	}
	p2, err := ParseKeyPackage(p.Marshal())
	if err != nil {
		t.Fatalf("ParseKeyPackage: %v", err)
	}
	if len(p2.PreviousKeys) != 0 {
		t.Errorf("standalone package should have no previous-keys, got %+v", p2.PreviousKeys)
	}
	if len(p2.CurrentKeys) != 1 || p2.CurrentKeys[0].Type != ETypeAES256 {
		t.Errorf("current-keys: got %+v", p2.CurrentKeys)
	}
}

func TestParseKeyPackageErrors(t *testing.T) {
	good := fixturePackage().Marshal()
	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"truncated", good[:len(good)/2]},
		{"not a sequence", derOctetString([]byte{1, 2, 3})},
		{"trailing garbage", append(append([]byte{}, good...), 0x05, 0x00)},
		{"no current-keys", derSeq(derExplicit(2, derGeneralizedTime(fixtExpiration)))},
		{"bad key list", derSeq(derExplicit(0, derOctetString([]byte{9, 9, 9})))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeyPackage(tc.der); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestFindKey(t *testing.T) {
	p := fixturePackage()
	cases := []struct {
		name  string
		etype int32
		want  []byte
		found bool
	}{
		{"rc4 current", ETypeRC4, fixtCurrentRC4, true},
		{"aes256", ETypeAES256, fixtCurrentAES256, true},
		{"aes128", ETypeAES128, fixtCurrentAES128, true},
		{"missing", 1, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FindKey(p.CurrentKeys, tc.etype)
			if ok != tc.found || (ok && !bytes.Equal(got, tc.want)) {
				t.Errorf("FindKey(%d) = (%x, %v), want (%x, %v)", tc.etype, got, ok, tc.want, tc.found)
			}
		})
	}
	// previous-keys lookup (the BadSuccessor prize: the superseded NT hash)
	got, ok := FindKey(p.PreviousKeys, ETypeRC4)
	if !ok || !bytes.Equal(got, fixtPreviousRC4) {
		t.Errorf("previous RC4 = (%x, %v)", got, ok)
	}
}

func TestETypeName(t *testing.T) {
	cases := []struct {
		etype int32
		want  string
	}{
		{ETypeRC4, "rc4_hmac"},
		{ETypeAES128, "aes128_cts_hmac_sha1_96"},
		{ETypeAES256, "aes256_cts_hmac_sha1_96"},
		{1, "etype 1"},
	}
	for _, tc := range cases {
		if got := ETypeName(tc.etype); got != tc.want {
			t.Errorf("ETypeName(%d) = %q, want %q", tc.etype, got, tc.want)
		}
	}
}

func fixtureSuperseded() *SupersededByUser {
	return &SupersededByUser{Name: []string{"dmsa-backup$"}, Realm: "CORP.LOCAL"}
}

func TestParseSupersededByUserFixture(t *testing.T) {
	der, err := os.ReadFile("testdata/superseded.der")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	s, err := ParseSupersededByUser(der)
	if err != nil {
		t.Fatalf("ParseSupersededByUser: %v", err)
	}
	if !reflect.DeepEqual(s, fixtureSuperseded()) {
		t.Errorf("got %+v, want %+v", s, fixtureSuperseded())
	}
	if s.String() != `CORP.LOCAL\dmsa-backup$` {
		t.Errorf("String() = %q", s.String())
	}
}

func TestSupersededByUserRoundTrip(t *testing.T) {
	s := fixtureSuperseded()
	s2, err := ParseSupersededByUser(s.Marshal())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !reflect.DeepEqual(s, s2) {
		t.Errorf("round-trip: got %+v, want %+v", s2, s)
	}
}

// TestExtractSupersededByUser builds a KRB-ERROR e-data payload
// (METHOD-DATA: SEQUENCE OF PA-DATA) holding one unrelated PA-DATA plus a
// type-170 one, and checks the successor is found.
func TestExtractSupersededByUser(t *testing.T) {
	sup := fixtureSuperseded().Marshal()
	padata := func(typ int64, val []byte) []byte {
		return derSeq(
			append(derExplicit(1, derInt(typ)), derExplicit(2, derOctetString(val))...))
	}
	edata := derSeq(append(padata(1, []byte{0, 0, 0, 0}), padata(PADataTypeSupersededByUser, sup)...))

	got := ExtractSupersededByUser(edata)
	if got == nil {
		t.Fatalf("no successor extracted")
	}
	if got.String() != `CORP.LOCAL\dmsa-backup$` {
		t.Errorf("got %q", got.String())
	}

	for name, blob := range map[string][]byte{
		"nil":             nil,
		"not a sequence":  derOctetString([]byte{1}),
		"no type-170":     derSeq(padata(2, []byte{1, 2})),
		"garbage payload": derSeq(padata(PADataTypeSupersededByUser, []byte{0xff})),
	} {
		if ExtractSupersededByUser(blob) != nil {
			t.Errorf("%s: expected nil", name)
		}
	}
}

func TestDerInt(t *testing.T) {
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{23, []byte{0x02, 0x01, 0x17}},
		{127, []byte{0x02, 0x01, 0x7F}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{256, []byte{0x02, 0x02, 0x01, 0x00}},
		{65536, []byte{0x02, 0x03, 0x01, 0x00, 0x00}},
		{-1, []byte{0x02, 0x01, 0xFF}},
		{-128, []byte{0x02, 0x01, 0x80}},
		{-129, []byte{0x02, 0x02, 0xFF, 0x7F}},
		{-138, []byte{0x02, 0x02, 0xFF, 0x76}}, // HMAC-MD5 checksum type
	}
	for _, tc := range cases {
		if got := derInt(tc.v); !bytes.Equal(got, tc.want) {
			t.Errorf("derInt(%d) = %x, want %x", tc.v, got, tc.want)
		}
	}
}
