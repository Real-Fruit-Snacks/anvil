// Package dpapi implements DPAPI Credential Manager decryption end to end:
// DPAPI_SYSTEM keys (from the LSA dump) → Protect masterkey files → blobs.
// gopacket's pkg/dpapi proved broken for this path (no SHA1 pre-hash in its
// blob derivation, an misparsing credential parser, and no masterkey-file
// support at all), so the crypto lives here, verified byte-for-byte against
// a live Server 2022 credential chain (algorithms per impacket's dpapi.py).
package dpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	godpapi "github.com/mandiant/gopacket/pkg/dpapi"
)

const (
	calgSHA1   = 0x8004
	calgHMAC   = 0x8009
	calgSHA512 = 0x800e
	calg3DES   = 0x6603
	calgAES256 = 0x6610
)

func hashFor(algo uint32) (func() hash.Hash, int, error) {
	switch algo {
	case calgSHA1, calgHMAC:
		return sha1.New, 20, nil
	case calgSHA512:
		return sha512.New, 16, nil
	}
	return nil, 0, fmt.Errorf("unsupported hash algorithm 0x%x", algo)
}

// pbkdf2HMAC derives key material with the PBKDF2-HMAC construction DPAPI
// masterkey files use (impacket's MasterKey.deriveKey). NB: it is NOT RFC
// 2898 PBKDF2 for iteration counts > 1 — the PRF chain feeds on the running
// XOR accumulator rather than the previous U value. That is how Windows and
// impacket derive these keys (verified byte-identical to impacket's
// deriveKey, and proven against a live Server 2022 chain), so do not "fix"
// it. The standard RFC 2898 variant (pbkdf2Std in userkey.go) is used only
// where impacket uses hashlib.pbkdf2_hmac — the Protected-users chain.
func pbkdf2HMAC(key, salt []byte, keylen, count int, hf func() hash.Hash) []byte {
	prf := func(p, s []byte) []byte { h := hmac.New(hf, p); h.Write(s); return h.Sum(nil) }
	var out []byte
	for i := int32(1); len(out) < keylen; i++ {
		u := append(append([]byte{}, salt...), byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		derived := prf(key, u)
		for r := 1; r < count; r++ {
			actual := prf(key, derived)
			for j := range derived {
				derived[j] ^= actual[j]
			}
		}
		out = append(out, derived...)
	}
	return out[:keylen]
}

func cbcDecrypt(key, iv, data []byte, algo uint32) ([]byte, error) {
	var block cipher.Block
	var err error
	switch algo {
	case calgAES256:
		block, err = aes.NewCipher(key[:32])
	case calg3DES:
		block, err = des.NewTripleDESCipher(key[:24])
	default:
		return nil, fmt.Errorf("unsupported crypt algorithm 0x%x", algo)
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func pkcs7unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n <= 0 || n > len(b) {
		return b
	}
	return b[:len(b)-n]
}

// DecryptMasterKeyFile decrypts a Protect masterkey file (as found under
// ...\Microsoft\Protect\...\) with DPAPI_SYSTEM keys. Every key is tried;
// the built-in HMAC verification decides which (if any) is correct.
func DecryptMasterKeyFile(data []byte, keys [][]byte) ([]byte, error) {
	mk, err := decryptMasterKeyFile(data, keys)
	if err != nil {
		return nil, fmt.Errorf("no DPAPI_SYSTEM key decrypts this masterkey file: %w", err)
	}
	return mk, nil
}

// decryptMasterKeyFile is the shared core of the SYSTEM and user masterkey
// paths: parse the file, then try each key (PBKDF2 → CBC → HMAC verify).
func decryptMasterKeyFile(data []byte, keys [][]byte) ([]byte, error) {
	// MasterKeyFile header: v,u1,u2(12) + guid(72) + unk,pol,flags(12) +
	// 4x uint64 section lengths (32) = 128. MasterKey structure follows:
	// version(4), salt(16), iter(4), hashAlgo(4), cryptAlgo(4), data.
	if len(data) < 128+32 {
		return nil, fmt.Errorf("masterkey file too short (%d bytes)", len(data))
	}
	mkLen := int(binary.LittleEndian.Uint64(data[96:104]))
	if mkLen < 32 || 128+mkLen > len(data) {
		return nil, fmt.Errorf("bad masterkey section length %d", mkLen)
	}
	mk := data[128 : 128+mkLen]
	salt := mk[4:20]
	iter := binary.LittleEndian.Uint32(mk[20:24])
	hashAlgo := binary.LittleEndian.Uint32(mk[24:28])
	cryptAlgo := binary.LittleEndian.Uint32(mk[28:32])
	enc := mk[32:]

	hf, hashLen, err := hashFor(hashAlgo)
	if err != nil {
		return nil, err
	}
	keyLen, ivLen := 0, 0
	switch cryptAlgo {
	case calgAES256:
		keyLen, ivLen = 32, 16
	case calg3DES:
		keyLen, ivLen = 24, 8
	default:
		return nil, fmt.Errorf("unsupported crypt algorithm 0x%x", cryptAlgo)
	}

	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		derived := pbkdf2HMAC(key, salt, keyLen+ivLen, int(iter), hf)
		clear, err := cbcDecrypt(derived[:keyLen], derived[keyLen:keyLen+ivLen], enc, cryptAlgo)
		if err != nil || len(clear) < 64+16+hashLen {
			continue
		}
		profileKey := clear[len(clear)-64:]
		hmacSalt := clear[:16]
		expect := clear[16 : 16+hashLen]

		h := hmac.New(hf, key)
		h.Write(hmacSalt)
		hmacKey := h.Sum(nil)
		h2 := hmac.New(hf, hmacKey)
		h2.Write(profileKey)
		if bytes.Equal(h2.Sum(nil)[:hashLen], expect) {
			return profileKey, nil
		}
	}
	return nil, fmt.Errorf("no key decrypts this masterkey file")
}

// decryptBlob decrypts a credential DPAPIBlob with a profile masterkey.
// Derivation per impacket's DPAPIBlob.decrypt: sessionKey =
// HMAC(SHA1(masterKey), salt, blob.HashAlgo); AES/3DES-CBC with zero IV.
func decryptBlob(blob *godpapi.DPAPIBlob, masterKey []byte) ([]byte, error) {
	hf, _, err := hashFor(blob.AlgHash)
	if err != nil {
		return nil, err
	}
	keyHash := sha1.Sum(masterKey)
	h := hmac.New(hf, keyHash[:])
	h.Write(blob.Salt)
	sessionKey := h.Sum(nil)
	// impacket: session keys longer than the hash block size are re-hashed.
	if bs := hf().BlockSize(); len(sessionKey) > bs {
		r := hf()
		r.Write(sessionKey)
		sessionKey = r.Sum(nil)
	}

	keyLen := 0
	switch blob.AlgCrypt {
	case calgAES256:
		keyLen = 32
	case calg3DES:
		keyLen = 24
	default:
		return nil, fmt.Errorf("unsupported crypt algorithm 0x%x", blob.AlgCrypt)
	}
	if len(sessionKey) < keyLen {
		sessionKey = extendKey(sessionKey, keyLen, hf)
	}
	iv := make([]byte, 16)
	if blob.AlgCrypt == calg3DES {
		iv = iv[:8]
	}
	plain, err := cbcDecrypt(sessionKey[:keyLen], iv, blob.Data, blob.AlgCrypt)
	if err != nil {
		return nil, err
	}
	return pkcs7unpad(plain), nil
}

// extendKey stretches a session key past the hash length, per impacket's
// DPAPIBlob.deriveKey: zero-pad to the block size, then hash the ipad and
// opad halves and concatenate (with DES parity fix for 3DES keys).
func extendKey(key []byte, keyLen int, hf func() hash.Hash) []byte {
	bs := hf().BlockSize()
	padded := make([]byte, bs)
	copy(padded, key)
	ipad := make([]byte, bs)
	opad := make([]byte, bs)
	for i := range padded {
		ipad[i] = padded[i] ^ 0x36
		opad[i] = padded[i] ^ 0x5c
	}
	h1 := hf()
	h1.Write(ipad)
	h2 := hf()
	h2.Write(opad)
	out := append(h1.Sum(nil), h2.Sum(nil)...)
	if keyLen == 24 { // 3DES: fix DES parity bits
		for i, b := range out {
			ones := 0
			for j := 0; j < 7; j++ {
				if b>>uint(j+1)&1 == 1 {
					ones++
				}
			}
			if ones%2 == 0 {
				out[i] |= 1
			} else {
				out[i] &^= 1
			}
		}
	}
	if len(out) < keyLen {
		out = extendKey(out, keyLen, hf)
	}
	return out[:keyLen]
}
