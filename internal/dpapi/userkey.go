// User-context DPAPI: regular users' Protect masterkey files (under
// ...\Microsoft\Protect\<SID>\) are encrypted not with DPAPI_SYSTEM but with
// keys derived from the user's own password or NT hash, mixed with their
// SID. Algorithms per impacket's dpapi.py deriveKeysFromUser (line 1200)
// and deriveKeysFromUserkey (line 1211).
package dpapi

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"unicode/utf16"
)

// DeriveUserKeys builds the SID-independent password pre-keys for decrypting
// a regular user's Protect masterkey file. Password input yields
// SHA1(utf16le(password)) and MD4(utf16le(password)) (the NT hash) — the two
// digests impacket feeds its HMAC-with-SID step; ntHashHex input contributes
// the decoded NT hash itself (16 bytes, or 20 for the rare SHA1 form).
// Returns nil when both inputs are empty; an undecodable hash is ignored.
// The SID-dependent expansion happens in DecryptUserMasterKeyFile, which owns
// the SID.
func DeriveUserKeys(password, ntHashHex string) [][]byte {
	var keys [][]byte
	if password != "" {
		u := utf16le(password)
		s1 := sha1.Sum(u)
		m4 := md4Sum(u)
		keys = append(keys, s1[:], m4[:])
	}
	if ntHashHex != "" {
		if h, err := hex.DecodeString(strings.TrimSpace(ntHashHex)); err == nil && (len(h) == 16 || len(h) == 20) {
			keys = append(keys, h)
		}
	}
	// Dedupe: a password and its own NT hash both yield the MD4 digest.
	out := keys[:0]
	seen := map[string]bool{}
	for _, k := range keys {
		if !seen[string(k)] {
			seen[string(k)] = true
			out = append(out, k)
		}
	}
	return out
}

// DecryptUserMasterKeyFile decrypts a regular user's Protect masterkey file
// with the pre-keys from DeriveUserKeys. sid is the user's SID string as
// taken from the Protect\<SID> directory name. Per user key it expands the
// candidate decryption keys exactly as impacket's deriveKeysFromUser /
// deriveKeysFromUserkey (dpapi.py:1200-1224):
//
//	key1 = HMAC-SHA1(userKey, utf16le(sid + "\0"))                       (every key)
//	key2 = HMAC-SHA1(tmp2, utf16le(sid + "\0"))[:20]                     (16-byte keys only)
//	  tmp1 = PBKDF2-HMAC-SHA256(userKey, utf16le(sid), 10000, 32)        ("Protected users" chain)
//	  tmp2 = PBKDF2-HMAC-SHA256(tmp1, utf16le(sid), 1, 32)[:16]
//
// Each candidate then runs through the standard masterkey-file decryption
// (PBKDF2 with the file's own salt, CBC, built-in HMAC verification), shared
// with the DPAPI_SYSTEM path.
func DecryptUserMasterKeyFile(data []byte, sid string, userKeys [][]byte) ([]byte, error) {
	if len(userKeys) == 0 {
		return nil, fmt.Errorf("no user keys provided")
	}
	msg := utf16le(sid + "\x00") // HMAC message: SID + NUL, utf-16le (impacket: (sid + '\0').encode('utf-16le'))
	sidSalt := utf16le(sid)      // PBKDF2 salt for the Protected-users chain: SID without NUL
	var candidates [][]byte
	for _, uk := range userKeys {
		if len(uk) == 0 {
			continue
		}
		h := hmac.New(sha1.New, uk)
		h.Write(msg)
		candidates = append(candidates, h.Sum(nil))
		if len(uk) != 16 {
			continue // impacket: only MD4-form hashes derive the Protected-users key
		}
		// Standard RFC 2898 PBKDF2 here, NOT the masterkey-file variant:
		// impacket calls hashlib.pbkdf2_hmac for this chain.
		tmp1 := pbkdf2Std(uk, sidSalt, 32, 10000, sha256.New)
		tmp2 := pbkdf2Std(tmp1, sidSalt, 16, 1, sha256.New) // PBKDF2 prefix == impacket's [:16]
		h2 := hmac.New(sha1.New, tmp2)
		h2.Write(msg)
		candidates = append(candidates, h2.Sum(nil))
	}
	mk, err := decryptMasterKeyFile(data, candidates)
	if err != nil {
		return nil, fmt.Errorf("no user key decrypts this masterkey file: %w", err)
	}
	return mk, nil
}

// pbkdf2Std is standard RFC 2898 PBKDF2-HMAC: the PRF chain feeds on the
// previous U value, with a separate XOR accumulator. Needed for the
// "Protected users" chain, which impacket derives with hashlib.pbkdf2_hmac —
// unlike masterkey-file decryption, where impacket (and Windows, and this
// package's pbkdf2HMAC) use the accumulator-chain variant.
func pbkdf2Std(key, salt []byte, keylen, count int, hf func() hash.Hash) []byte {
	prf := func(p, s []byte) []byte { h := hmac.New(hf, p); h.Write(s); return h.Sum(nil) }
	var out []byte
	for i := int32(1); len(out) < keylen; i++ {
		u := prf(key, append(append([]byte{}, salt...), byte(i>>24), byte(i>>16), byte(i>>8), byte(i)))
		t := append([]byte{}, u...)
		for r := 1; r < count; r++ {
			u = prf(key, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keylen]
}

// utf16le encodes s as UTF-16LE bytes (matching Python's utf-16le codec for
// the BMP and surrogate pairs alike).
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return b
}
