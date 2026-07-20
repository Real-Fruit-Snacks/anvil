package dpapi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildCredentialFile hand-crafts a credential file holding a syntactically
// valid DPAPI blob with garbage crypto content (decryption must fail).
func buildCredentialFile() []byte {
	blob := new(bytes.Buffer)
	binary.Write(blob, binary.LittleEndian, uint32(1))      // version
	blob.Write(make([]byte, 16))                            // provider GUID
	binary.Write(blob, binary.LittleEndian, uint32(1))      // mk version
	blob.Write(make([]byte, 16))                            // masterkey GUID
	binary.Write(blob, binary.LittleEndian, uint32(0))      // flags
	binary.Write(blob, binary.LittleEndian, uint32(0))      // descLen
	binary.Write(blob, binary.LittleEndian, uint32(0x3f1))  // algCrypt (CALG_3DES_112)
	binary.Write(blob, binary.LittleEndian, uint32(0))      // algCryptLen
	binary.Write(blob, binary.LittleEndian, uint32(16))     // saltLen
	blob.Write(make([]byte, 16))                            // salt
	binary.Write(blob, binary.LittleEndian, uint32(0))      // hmacKeyLen
	binary.Write(blob, binary.LittleEndian, uint32(0x800e)) // algHash (CALG_SHA_512)
	binary.Write(blob, binary.LittleEndian, uint32(0))      // algHashLen
	binary.Write(blob, binary.LittleEndian, uint32(64))     // hmacLen
	blob.Write(make([]byte, 64))                            // hmac
	binary.Write(blob, binary.LittleEndian, uint32(16))     // dataLen
	blob.Write(bytes.Repeat([]byte{0x42}, 16))              // data (garbage cipher)
	binary.Write(blob, binary.LittleEndian, uint32(20))     // signLen
	blob.Write(make([]byte, 20))                            // sign

	cf := new(bytes.Buffer)
	binary.Write(cf, binary.LittleEndian, uint32(1)) // version
	binary.Write(cf, binary.LittleEndian, uint32(0)) // size
	binary.Write(cf, binary.LittleEndian, uint32(0)) // unknown
	cf.Write(blob.Bytes())
	return cf.Bytes()
}

func TestDecryptBlobErrors(t *testing.T) {
	key := make([]byte, 24)

	if _, err := DecryptBlob(nil, [][]byte{key}); err == nil {
		t.Error("nil input: expected error")
	}
	if _, err := DecryptBlob([]byte("short"), [][]byte{key}); err == nil {
		t.Error("truncated input: expected error")
	}

	// Parses fine, but no key can decrypt garbage ciphertext.
	_, err := DecryptBlob(buildCredentialFile(), [][]byte{key})
	if err == nil {
		t.Error("garbage ciphertext with arbitrary key: expected decrypt error")
	}
}

func TestRenderSecret(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"utf16", []byte{'s', 0, '3', 0, 'c', 0, 'r', 0, '3', 0, 't', 0, 0, 0}, "s3cr3t"},
		{"ascii", []byte("plain-text"), "plain-text"},
		{"binary", []byte{0xde, 0xad, 0xbe, 0xef}, "0xdeadbeef"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := renderSecret(c.in); got != c.want {
				t.Errorf("renderSecret(%x) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
