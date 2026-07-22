package dpapi

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// credSpec describes a decrypted CREDENTIAL_BLOB plaintext for the builder
// below. The layout follows impacket's CREDENTIAL_BLOB (impacket/dpapi.py)
// exactly: 48-byte header, then six length-prefixed fields (targetName,
// targetAlias, description, unknown, username — UTF-16LE NUL-terminated —
// and the raw credentialBlob secret).
type credSpec struct {
	typ         uint32 // wincred CREDENTIAL_TYPE (1 = CRED_TYPE_GENERIC)
	persist     uint32 // wincred CREDENTIAL_PERSIST (2 = local machine)
	target      string
	alias       string
	description string
	unknown     string
	user        string
	secret      []byte
	trailing    []byte // CREDENTIAL_ATTRIBUTE records would sit here
}

// machineCred is a synthetic machine-store credential as written by a
// service via CredWrite: unlike UI/cmdkey user creds it populates the
// targetAlias/description/unknown metadata fields — the exact shape that
// defeated the old one-field-plus-8-byte-skip parse on the live DC's
// systemprofile/ServiceProfiles blobs.
var machineCred = credSpec{
	typ:         1, // CRED_TYPE_GENERIC
	persist:     2, // CRED_PERSIST_LOCAL_MACHINE
	target:      "LegacyGeneric:target=svc-backup",
	alias:       "svc-backup",
	description: "Nightly backup service credential",
	unknown:     "machine-store metadata",
	user:        `CORP\svc-backup`,
	secret:      utf16raw("B@ckupS3cret!"),
}

// userCred mirrors a cmdkey-written user credential: every metadata field
// empty, only target/user/secret set (shape of testdata/cred-plain.bin).
var userCred = credSpec{
	typ:     1,
	persist: 2,
	target:  "LegacyGeneric:target=fileserver",
	user:    `CORP\jdoe`,
	secret:  utf16raw("UserP@ss1"),
}

// utf16raw encodes s as UTF-16LE without a terminator (secrets are raw
// byte blobs, not C strings).
func utf16raw(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// utf16z encodes s as UTF-16LE with the trailing NUL Windows writes into
// the CREDENTIAL string fields.
func utf16z(s string) []byte {
	if s == "" {
		return nil
	}
	return utf16raw(s + "\x00")
}

// buildCredPlaintext serializes s to a decrypted credential blob per
// impacket's CREDENTIAL_BLOB layout.
func buildCredPlaintext(s credSpec) []byte {
	buf := new(bytes.Buffer)
	u32 := func(v uint32) { binary.Write(buf, binary.LittleEndian, v) }
	field := func(raw []byte) { u32(uint32(len(raw))); buf.Write(raw) }

	u32(0)     // flags
	u32(0)     // total length (patched below)
	u32(0)     // unknown0
	u32(s.typ) // type
	u32(0)     // flags2
	binary.Write(buf, binary.LittleEndian,
		uint64(133497840000000000)) // lastWritten: FILETIME for 2024-01-15T12:00:00Z
	u32(0)         // unkFlagsOrSize
	u32(s.persist) // persistence
	u32(0)         // attributeCount (0 = no trailing attributes)
	u32(0)         // unknown3, low half (u64 in the real struct)
	u32(0)         // unknown3, high half
	field(utf16z(s.target))
	field(utf16z(s.alias))
	field(utf16z(s.description))
	field(utf16z(s.unknown))
	field(utf16z(s.user))
	field(s.secret)
	buf.Write(s.trailing)

	out := buf.Bytes()
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out))) // Size = struct size
	return out
}

func TestParseCredential(t *testing.T) {
	tests := []struct {
		name       string
		plain      []byte
		wantErr    bool
		wantTarget string
		wantUser   string
		wantSecret string // renderSecret(secret)
	}{
		{
			name:       "machine cred with all metadata fields populated",
			plain:      buildCredPlaintext(machineCred),
			wantTarget: "LegacyGeneric:target=svc-backup\x00",
			wantUser:   "CORP\\svc-backup\x00",
			wantSecret: "B@ckupS3cret!",
		},
		{
			name:       "user cred with empty metadata fields",
			plain:      buildCredPlaintext(userCred),
			wantTarget: "LegacyGeneric:target=fileserver\x00",
			wantUser:   "CORP\\jdoe\x00",
			wantSecret: "UserP@ss1",
		},
		{
			name: "machine cred with binary secret renders as hex",
			plain: buildCredPlaintext(credSpec{
				typ: 1, persist: 2,
				target:      "LegacyGeneric:target=cert-store",
				description: "service certificate credential",
				user:        `CORP\svc-certs`,
				secret:      []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82},
			}),
			wantTarget: "LegacyGeneric:target=cert-store\x00",
			wantUser:   "CORP\\svc-certs\x00",
			wantSecret: "0x3082010a0282",
		},
		{
			name: "trailing attribute records ignored",
			plain: buildCredPlaintext(credSpec{
				typ: 1, persist: 2,
				target:   "LegacyGeneric:target=with-attrs",
				user:     `CORP\jdoe`,
				secret:   utf16raw("P@ss"),
				trailing: []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4},
			}),
			wantTarget: "LegacyGeneric:target=with-attrs\x00",
			wantUser:   "CORP\\jdoe\x00",
			wantSecret: "P@ss",
		},
		{
			name: "empty credential record parses to empty fields",
			plain: buildCredPlaintext(credSpec{
				typ: 1, persist: 2,
			}),
			wantTarget: "",
			wantUser:   "",
			wantSecret: "",
		},
		{
			name:    "truncated header rejected",
			plain:   buildCredPlaintext(machineCred)[:60],
			wantErr: true,
		},
		{
			name: "field length overrun rejected (wrong-key garbage shape)",
			plain: func() []byte {
				// A decrypt under the wrong masterkey yields random bytes;
				// the first length prefix at +48 almost surely overruns the
				// buffer. That failure is what arbitrates keys in
				// DecryptBlob, so it must keep happening.
				b := bytes.Repeat([]byte{0x7f}, 128)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "truncated secret rejected",
			plain: func() []byte {
				b := buildCredPlaintext(userCred)
				return b[:len(b)-4] // declared secret length now exceeds the buffer
			}(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseCredential(tc.plain)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseCredential succeeded, want error (target=%q user=%q)", c.Target, c.User)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCredential: %v", err)
			}
			if c.Target != tc.wantTarget {
				t.Errorf("target = %q, want %q", c.Target, tc.wantTarget)
			}
			if c.User != tc.wantUser {
				t.Errorf("user = %q, want %q", c.User, tc.wantUser)
			}
			if got := renderSecret(c.Secret); got != tc.wantSecret {
				t.Errorf("secret = %q, want %q", got, tc.wantSecret)
			}
		})
	}
}

// TestParseMachineFixture parses the committed synthetic machine-store
// fixture (testdata/cred-machine-plain.bin) and pins it byte-for-byte to
// buildCredPlaintext(machineCred) so the fixture cannot drift from the
// documented impacket CREDENTIAL_BLOB layout it was generated from.
func TestParseMachineFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/cred-machine-plain.bin")
	if err != nil {
		t.Skip("no fixture")
	}
	if want := buildCredPlaintext(machineCred); !bytes.Equal(data, want) {
		t.Fatalf("fixture differs from builder output (%d vs %d bytes) — regenerate testdata/cred-machine-plain.bin", len(data), len(want))
	}
	c, err := parseCredential(data)
	if err != nil {
		t.Fatalf("parseCredential: %v", err)
	}
	if c.Target != "LegacyGeneric:target=svc-backup\x00" {
		t.Errorf("target = %q", c.Target)
	}
	if c.User != "CORP\\svc-backup\x00" {
		t.Errorf("user = %q", c.User)
	}
	if got := renderSecret(c.Secret); got != "B@ckupS3cret!" {
		t.Errorf("secret = %q", got)
	}
	if c.Type != 1 {
		t.Errorf("type = %d, want 1 (CRED_TYPE_GENERIC)", c.Type)
	}
}
