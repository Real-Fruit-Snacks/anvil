package dpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// TestMD4Vectors runs the RFC 1320 MD4 test suite, plus the Windows NT-hash
// form: MD4(utf16le("Password123!")) must equal the published NT hash.
func TestMD4Vectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, c := range cases {
		sum := md4Sum([]byte(c.in))
		if got := hex.EncodeToString(sum[:]); got != c.want {
			t.Errorf("md4(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	// NT hash of Password123! (published value, also cross-checked against
	// impacket's deriveKeysFromUserkey output below).
	if sum := md4Sum(utf16le("Password123!")); hex.EncodeToString(sum[:]) != "2b576acbe6bcfda7294d6bd18041b8fe" {
		t.Errorf("nt hash = %s", hex.EncodeToString(sum[:]))
	}
}

// TestDeriveUserKeys checks derivation against values computed by impacket:
//
//	SHA1(utf16le('Password123!')) = e30d1c18c56c027667d35734660751dc80203354
//	MD4 (utf16le('Password123!')) = 2b576acbe6bcfda7294d6bd18041b8fe (NT hash)
func TestDeriveUserKeys(t *testing.T) {
	keys := DeriveUserKeys("Password123!", "")
	if len(keys) != 2 {
		t.Fatalf("password-only: got %d keys, want 2", len(keys))
	}
	if got := hex.EncodeToString(keys[0]); got != "e30d1c18c56c027667d35734660751dc80203354" {
		t.Errorf("sha1 key = %s", got)
	}
	if got := hex.EncodeToString(keys[1]); got != "2b576acbe6bcfda7294d6bd18041b8fe" {
		t.Errorf("md4 key = %s", got)
	}

	hk := DeriveUserKeys("", "2b576acbe6bcfda7294d6bd18041b8fe")
	if len(hk) != 1 || !bytes.Equal(hk[0], keys[1]) {
		t.Errorf("hash-only: got %x, want the md4 key", hk)
	}

	// Same secret twice: the duplicate MD4 form collapses.
	if both := DeriveUserKeys("Password123!", "2b576acbe6bcfda7294d6bd18041b8fe"); len(both) != 2 {
		t.Errorf("password+hash: got %d keys, want 2 (deduped)", len(both))
	}
	if got := DeriveUserKeys("", ""); got != nil {
		t.Errorf("empty inputs: got %x, want nil", got)
	}
	if got := DeriveUserKeys("", "not-hex"); got != nil {
		t.Errorf("bad hash hex: got %x, want nil", got)
	}
	if got := DeriveUserKeys("", "aabbcc"); got != nil {
		t.Errorf("wrong-length hash: got %x, want nil", got)
	}
}

// TestPBKDF2Variants pins the two PBKDF2 constructions apart: pbkdf2HMAC is
// the accumulator-chain variant impacket's MasterKey.deriveKey implements
// (verified against impacket's own output), pbkdf2Std is RFC 2898 (verified
// against the draft-josefsson-scrypt test vectors).
func TestPBKDF2Variants(t *testing.T) {
	key, _ := hex.DecodeString("2572c458dd7ca30a7b3e6628fcb0a4144f139f14")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	// impacket> hexlify(MasterKey().deriveKey(key, bytes(range(16)), 48, 4000, prf_hmac_sha1))
	const impacketDeriveKey = "29cf402478573fc6ad3da4c91f653d3c0730e986f4ac0a5adc99cb4ef32dcda2d0127731819ddc0d3d852ab6df634af5"
	if got := hex.EncodeToString(pbkdf2HMAC(key, salt, 48, 4000, sha1.New)); got != impacketDeriveKey {
		t.Errorf("pbkdf2HMAC != impacket deriveKey:\n got %s\nwant %s", got, impacketDeriveKey)
	}

	// draft-josefsson-scrypt PBKDF2-HMAC-SHA256 vectors.
	if got := hex.EncodeToString(pbkdf2Std([]byte("password"), []byte("salt"), 32, 1, sha256.New)); got != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" {
		t.Errorf("pbkdf2Std c=1 = %s", got)
	}
	if got := hex.EncodeToString(pbkdf2Std([]byte("password"), []byte("salt"), 32, 4096, sha256.New)); got != "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a" {
		t.Errorf("pbkdf2Std c=4096 = %s", got)
	}
}

// TestDecryptUserMasterKeyFile decrypts masterkey files produced from
// impacket's deriveKeysFromUser output (SID S-1-5-21-1-2-3-500, password
// Password123!, AES-256/HMAC-SHA1 file, iter 4000, embedded masterkey
// 0x20..0x5f). Each fixture was encrypted with one of impacket's three
// candidate keys:
//
//	mk-sha1.bin      — key1 = HMAC-SHA1(SHA1(utf16le(pw)), utf16le(sid+"\0"))
//	mk-md4.bin       — key2 = HMAC-SHA1(MD4(utf16le(pw)), utf16le(sid+"\0"))
//	mk-protected.bin — key3 (Protected-users PBKDF2-HMAC-SHA256 chain)
func TestDecryptUserMasterKeyFile(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-500"
	want := make([]byte, 64)
	for i := range want {
		want[i] = byte(0x20 + i)
	}

	cases := []struct {
		name     string
		file     string
		password string
		ntHash   string
		ok       bool
	}{
		{"sha1-by-password", "testdata/mk-sha1.bin", "Password123!", "", true},
		{"sha1-by-nthash-fails", "testdata/mk-sha1.bin", "", "2b576acbe6bcfda7294d6bd18041b8fe", false},
		{"md4-by-password", "testdata/mk-md4.bin", "Password123!", "", true},
		{"md4-by-nthash", "testdata/mk-md4.bin", "", "2b576acbe6bcfda7294d6bd18041b8fe", true},
		{"protected-by-password", "testdata/mk-protected.bin", "Password123!", "", true},
		{"protected-by-nthash", "testdata/mk-protected.bin", "", "2b576acbe6bcfda7294d6bd18041b8fe", true},
		{"wrong-password", "testdata/mk-md4.bin", "WrongPassword1", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := os.ReadFile(c.file)
			if err != nil {
				t.Skip("no fixture")
			}
			got, err := DecryptUserMasterKeyFile(data, sid, DeriveUserKeys(c.password, c.ntHash))
			if !c.ok {
				if err == nil {
					t.Fatalf("expected failure, got key %x", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecryptUserMasterKeyFile: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("masterkey = %x, want %x", got, want)
			}
		})
	}

	if _, err := DecryptUserMasterKeyFile([]byte{1, 2, 3}, sid, nil); err == nil {
		t.Error("no user keys: expected error")
	}
}

// TestDecryptUserMasterKeyFileDerivation pins the intermediate candidate keys
// (not just the fixture round trip) to impacket's published outputs:
//
//	impacket> deriveKeysFromUser('S-1-5-21-1-2-3-500', 'Password123!')
//	key1 = 7b22d5602d276dd43a78608fd15df094d5ab787c   (SHA1 path)
//	key2 = 2572c458dd7ca30a7b3e6628fcb0a4144f139f14   (MD4 path)
//	key3 = 7dc48d8c94ff2bd0097cc41a9819800692d7e07a   (Protected users)
//
// The SID-dependent expansion is internal, so observe it through decryption:
// synthesize one masterkey file per impacket-computed key and require each
// to open with the password-derived key set.
func TestDecryptUserMasterKeyFileDerivation(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-500"
	want := make([]byte, 64)
	for i := range want {
		want[i] = byte(0x20 + i)
	}
	candidates := []struct {
		name string
		hexK string // impacket-computed key the file is encrypted with
	}{
		{"key1-sha1", "7b22d5602d276dd43a78608fd15df094d5ab787c"},
		{"key2-md4", "2572c458dd7ca30a7b3e6628fcb0a4144f139f14"},
		{"key3-protected", "7dc48d8c94ff2bd0097cc41a9819800692d7e07a"},
	}
	for _, c := range candidates {
		t.Run(c.name, func(t *testing.T) {
			key, _ := hex.DecodeString(c.hexK)
			data := buildMasterKeyFile(t, key, want)
			got, err := DecryptUserMasterKeyFile(data, sid, DeriveUserKeys("Password123!", ""))
			if err != nil {
				t.Fatalf("DecryptUserMasterKeyFile: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("masterkey = %x, want %x", got, want)
			}
		})
	}
}

// buildMasterKeyFile synthesizes an AES-256/HMAC-SHA1 masterkey file
// protected by key, carrying master as the 64-byte profile masterkey — the
// mirror image of decryptMasterKeyFile (and of impacket's MasterKey.decrypt).
func buildMasterKeyFile(t *testing.T, key, master []byte) []byte {
	t.Helper()
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	hmacSalt := make([]byte, 16)
	for i := range hmacSalt {
		hmacSalt[i] = byte(16 + i)
	}
	derived := pbkdf2HMAC(key, salt, 48, 4000, sha1.New)

	h := hmac.New(sha1.New, key)
	h.Write(hmacSalt)
	hmacKey := h.Sum(nil)
	h2 := hmac.New(sha1.New, hmacKey)
	h2.Write(master)
	mac := h2.Sum(nil)

	clear := append(append(append([]byte{}, hmacSalt...), mac...), make([]byte, 28)...)
	clear = append(clear, master...)
	if len(clear) != 128 {
		t.Fatalf("cleartext layout: %d bytes", len(clear))
	}
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(clear))
	cipher.NewCBCEncrypter(block, derived[32:48]).CryptBlocks(ct, clear)

	mk := new(bytes.Buffer)
	binary.Write(mk, binary.LittleEndian, uint32(1))      // version
	mk.Write(salt)                                        // salt
	binary.Write(mk, binary.LittleEndian, uint32(4000))   // iter
	binary.Write(mk, binary.LittleEndian, uint32(0x8009)) // CALG_HMAC (SHA1)
	binary.Write(mk, binary.LittleEndian, uint32(0x6610)) // CALG_AES256
	mk.Write(ct)

	hdr := new(bytes.Buffer)
	binary.Write(hdr, binary.LittleEndian, uint32(1)) // version
	binary.Write(hdr, binary.LittleEndian, uint32(0)) // unk1
	binary.Write(hdr, binary.LittleEndian, uint32(0)) // unk2
	guid := utf16le("abcdef01-2345-6789-abcd-ef0123456789")
	if len(guid) != 72 {
		t.Fatalf("guid: %d bytes", len(guid))
	}
	hdr.Write(guid)                                   // guid
	binary.Write(hdr, binary.LittleEndian, uint32(0)) // unk
	binary.Write(hdr, binary.LittleEndian, uint32(0)) // policy
	binary.Write(hdr, binary.LittleEndian, uint32(0)) // flags
	binary.Write(hdr, binary.LittleEndian, uint64(mk.Len()))
	binary.Write(hdr, binary.LittleEndian, uint64(0))
	binary.Write(hdr, binary.LittleEndian, uint64(0))
	binary.Write(hdr, binary.LittleEndian, uint64(0))
	return append(hdr.Bytes(), mk.Bytes()...)
}
