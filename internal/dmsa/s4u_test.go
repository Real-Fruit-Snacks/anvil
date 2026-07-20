package dmsa

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// s4uFields is the decoded PA-S4U-X509-USER under test.
type s4uFields struct {
	nonce     int64
	nameType  int64
	name      string
	realm     string
	options   []byte // BIT STRING content incl. the unused-bits byte
	cksumType int64
	cksum     []byte
	userIDDER []byte
}

// decodeS4U walks the hand-rolled DER with encoding/asn1 only — the parse
// path is independent of the marshal path it checks.
func decodeS4U(t *testing.T, der []byte) s4uFields {
	t.Helper()
	var out s4uFields
	next := func(body *[]byte) asn1.RawValue {
		var f asn1.RawValue
		rest, err := asn1.Unmarshal(*body, &f)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		*body = rest
		if f.Class != asn1.ClassContextSpecific {
			t.Fatalf("expected context tag, got class %d tag %d", f.Class, f.Tag)
		}
		return f
	}
	intOf := func(b []byte) int64 {
		var v int64
		if _, err := asn1.Unmarshal(b, &v); err != nil {
			t.Fatalf("int: %v", err)
		}
		return v
	}

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("top: %v", err)
	}
	body := seq.Bytes

	uid := next(&body)
	if uid.Tag != 0 {
		t.Fatalf("user-id tag = %d, want 0", uid.Tag)
	}
	out.userIDDER = uid.Bytes
	cks := next(&body)
	if cks.Tag != 1 {
		t.Fatalf("checksum tag = %d, want 1", cks.Tag)
	}

	// S4UUserID fields — uid.Bytes is the wrapped SEQUENCE's DER.
	var uidSeq asn1.RawValue
	if _, err := asn1.Unmarshal(uid.Bytes, &uidSeq); err != nil {
		t.Fatalf("user-id seq: %v", err)
	}
	ubody := uidSeq.Bytes
	f := next(&ubody)
	if f.Tag != 0 {
		t.Fatalf("nonce tag = %d", f.Tag)
	}
	out.nonce = intOf(f.Bytes)

	f = next(&ubody)
	if f.Tag != 1 {
		t.Fatalf("cname tag = %d", f.Tag)
	}
	var pname asn1.RawValue
	if _, err := asn1.Unmarshal(f.Bytes, &pname); err != nil {
		t.Fatalf("cname: %v", err)
	}
	pbody := pname.Bytes
	pf := next(&pbody)
	out.nameType = intOf(pf.Bytes)
	pf = next(&pbody)
	var names asn1.RawValue
	if _, err := asn1.Unmarshal(pf.Bytes, &names); err != nil {
		t.Fatalf("name-string: %v", err)
	}
	var str asn1.RawValue
	if _, err := asn1.Unmarshal(names.Bytes, &str); err != nil {
		t.Fatalf("name: %v", err)
	}
	out.name = string(str.Bytes)

	f = next(&ubody)
	if f.Tag != 2 {
		t.Fatalf("crealm tag = %d", f.Tag)
	}
	var realm asn1.RawValue
	if _, err := asn1.Unmarshal(f.Bytes, &realm); err != nil {
		t.Fatalf("crealm: %v", err)
	}
	out.realm = string(realm.Bytes)

	f = next(&ubody)
	if f.Tag != 4 {
		t.Fatalf("options tag = %d (must be 4)", f.Tag)
	}
	var bs asn1.RawValue
	if _, err := asn1.Unmarshal(f.Bytes, &bs); err != nil {
		t.Fatalf("options: %v", err)
	}
	out.options = bs.Bytes

	// Checksum fields — same one-level unwrap as the user-id.
	var ckSeq asn1.RawValue
	if _, err := asn1.Unmarshal(cks.Bytes, &ckSeq); err != nil {
		t.Fatalf("checksum seq: %v", err)
	}
	cbody := ckSeq.Bytes
	f = next(&cbody)
	out.cksumType = intOf(f.Bytes)
	f = next(&cbody)
	var oct asn1.RawValue
	if _, err := asn1.Unmarshal(f.Bytes, &oct); err != nil {
		t.Fatalf("cksum value: %v", err)
	}
	out.cksum = oct.Bytes
	return out
}

// TestBuildS4UX509UserAES256 checks the wire layout (nonce, NT_PRINCIPAL
// cname, realm, options bit string with SIGN_REPLY |
// UNCONDITIONAL_DELEGATION) and that the checksum is exactly
// HMAC-SHA1-96-AES256(userID DER) with key usage 26, recomputed through
// gopacket's crypto independently of the build path.
//
// NOTE: byte-compatibility with a real Server 2025 KDC is not covered
// here (the lab DC is 2022); this pins our construction to MS-SFU 2.2.2
// and to gopacket's proven checksum primitives.
func TestBuildS4UX509UserAES256(t *testing.T) {
	key := types.EncryptionKey{KeyType: ETypeAES256, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
	pa, err := BuildS4UX509User("dmsa-backup$", "CORP.LOCAL", 12345678, key)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if pa.PADataType != PADataTypeS4UX509User {
		t.Fatalf("padata type = %d, want %d", pa.PADataType, PADataTypeS4UX509User)
	}

	f := decodeS4U(t, pa.PADataValue)
	if f.nonce != 12345678 {
		t.Errorf("nonce = %d", f.nonce)
	}
	if f.nameType != 1 { // NT_PRINCIPAL — NT_ENTERPRISE breaks dMSA requests
		t.Errorf("name-type = %d, want 1 (NT_PRINCIPAL)", f.nameType)
	}
	if f.name != "dmsa-backup$" {
		t.Errorf("cname = %q", f.name)
	}
	if f.realm != "CORP.LOCAL" {
		t.Errorf("crealm = %q", f.realm)
	}
	wantOpts := []byte{0x00, 0x28, 0x00, 0x00, 0x00} // 0 unused bits | 0x28000000
	if !bytes.Equal(f.options, wantOpts) {
		t.Errorf("options = %x, want %x (SIGN_REPLY|UNCONDITIONAL_DELEGATION)", f.options, wantOpts)
	}

	et, err := crypto.GetEtype(ETypeAES256)
	if err != nil {
		t.Fatalf("etype: %v", err)
	}
	if int32(f.cksumType) != et.GetHashID() {
		t.Errorf("cksumtype = %d, want %d", f.cksumType, et.GetHashID())
	}
	want, err := et.GetChecksumHash(key.KeyValue, f.userIDDER, keyUsageS4UX509User)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !bytes.Equal(f.cksum, want) {
		t.Errorf("checksum mismatch over user-id DER (usage 26)")
	}
}

// TestBuildS4UX509UserRC4 checks the RC4 session-key variant: checksum
// type KERB_CHECKSUM_HMAC_MD5 (-138), 16-byte value.
func TestBuildS4UX509UserRC4(t *testing.T) {
	key := types.EncryptionKey{KeyType: ETypeRC4, KeyValue: bytes.Repeat([]byte{0x24}, 16)}
	pa, err := BuildS4UX509User("svc-dmsa$", "LAB.LOCAL", 7, key)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	f := decodeS4U(t, pa.PADataValue)
	if f.cksumType != -138 {
		t.Errorf("cksumtype = %d, want -138 (KERB_CHECKSUM_HMAC_MD5)", f.cksumType)
	}
	if len(f.cksum) != 16 {
		t.Errorf("checksum len = %d, want 16", len(f.cksum))
	}
	et, _ := crypto.GetEtype(ETypeRC4)
	want, err := et.GetChecksumHash(key.KeyValue, f.userIDDER, keyUsageS4UX509User)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !bytes.Equal(f.cksum, want) {
		t.Errorf("checksum mismatch over user-id DER (usage 26)")
	}
}

// TestParseS4UX509UserUserID exercises the test/debug helper: it must
// return the exact bytes the checksum covered.
func TestParseS4UX509UserUserID(t *testing.T) {
	key := types.EncryptionKey{KeyType: ETypeAES256, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
	pa, err := BuildS4UX509User("a$", "B.LOCAL", 99, key)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	uid, err := parseS4UX509UserUserID(pa.PADataValue)
	if err != nil {
		t.Fatalf("parseS4UX509UserUserID: %v", err)
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(uid, &seq); err != nil || seq.Tag != asn1.TagSequence {
		t.Fatalf("user-id is not a SEQUENCE: %v", err)
	}
}
