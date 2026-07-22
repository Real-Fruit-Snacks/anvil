package dpapi

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// credential is a decrypted Credential Manager entry. The decrypted blob is
// a serialized wincred CREDENTIAL struct; the layout below is impacket's
// CREDENTIAL_BLOB (impacket/dpapi.py — the same class dploot's
// triage_system_credentials uses for systemprofile/ServiceProfiles blobs),
// identical to SharpDPAPI's Dpapi.ParseDecCredBlob, and matches the live
// Server 2022 user credential in testdata/cred-plain.bin:
//
//	+0  flags (u32)          +4  total length (u32)    +8  unknown0 (u32)
//	+12 type (u32)           +16 flags2 (u32)          +20 lastWritten (u64, FILETIME)
//	+28 unkFlagsOrSize (u32) +32 persistence (u32)     +36 attributeCount (u32)
//	+40 unknown3 (u64)
//	+48 six length-prefixed fields (u32 byte length + data each):
//	    targetName, targetAlias, description, unknown (UTF-16LE, NUL-terminated),
//	    username (UTF-16LE), credentialBlob (raw bytes — the secret)
//	then attributeCount x CREDENTIAL_ATTRIBUTE records (unused here).
//
// Machine-store blobs (systemprofile / ServiceProfiles Credential trees,
// decrypted with DPAPI_SYSTEM-derived masterkeys) are NOT a different record
// type — every reference implementation parses them with this same layout.
// What differs in practice is authorship: UI/cmdkey user creds leave
// targetAlias/description/unknown empty, while machine creds are written
// programmatically (CredWrite from services and scheduled tasks) and
// routinely populate them. An earlier shortcut here read one "comment"
// field and skipped a fixed 8 bytes — only valid while description and
// unknown are empty — so on machine creds every later length prefix
// misaligned and the parse failed ("field length exceeds remaining") on
// blobs that had decrypted correctly.
type credential struct {
	Target string
	User   string
	Secret []byte
	Type   uint32
}

func readUTF16Field(data []byte, off *int) (string, error) {
	if *off+4 > len(data) {
		return "", fmt.Errorf("truncated length field at %d", *off)
	}
	n := int(binary.LittleEndian.Uint32(data[*off : *off+4]))
	*off += 4
	if n > len(data)-*off {
		return "", fmt.Errorf("field length %d exceeds remaining %d", n, len(data)-*off)
	}
	raw := data[*off : *off+n]
	*off += n
	if n%2 != 0 {
		n--
	}
	u16 := make([]uint16, n/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16)), nil
}

// parseCredential parses decrypted credential plaintext (see layout above).
// The six length-prefixed fields are walked strictly — the length checks are
// also the wrong-key arbiter: decryptBlob does not verify the blob's HMAC
// signature, so garbage plaintext from a wrong masterkey reaches this
// parser and must keep failing here (a random u32 length overruns the
// buffer with near-certainty).
func parseCredential(data []byte) (*credential, error) {
	if len(data) < 72 {
		return nil, fmt.Errorf("data too short for credential (%d bytes)", len(data))
	}
	c := &credential{Type: binary.LittleEndian.Uint32(data[12:16])}

	off := 48
	var err error
	if c.Target, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("target: %v", err)
	}
	// targetAlias, description, unknown: metadata between target and
	// username. Their contents are not rendered, but their lengths MUST be
	// honored or the user/secret offsets misalign — that was the live
	// failure on machine-store creds (they populate these; user creds
	// usually don't).
	if _, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("target alias: %v", err)
	}
	if _, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("description: %v", err)
	}
	if _, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("unknown field: %v", err)
	}
	if c.User, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("user: %v", err)
	}
	if off+4 > len(data) {
		return nil, fmt.Errorf("truncated secret length at %d", off)
	}
	n := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	if n > len(data)-off {
		return nil, fmt.Errorf("secret length %d exceeds remaining %d", n, len(data)-off)
	}
	c.Secret = data[off : off+n]
	// Trailing CREDENTIAL_ATTRIBUTE records (attributeCount of them) are
	// deliberately not parsed — rare, and never part of the secret.
	return c, nil
}
