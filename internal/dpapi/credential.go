package dpapi

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// credential is a decrypted Credential Manager entry. The on-disk decrypted
// layout (verified against a live Server 2022 credential):
//
//	+0  flags (u32)        +4  total length (u32)   +8  unknown (u32)
//	+12 type (u32)         +16 unknown (u32)        +20 lastWritten (u64)
//	+28 unknown (u32)      +32 persistence (u32)    +36 12 bytes unknown
//	+48 targetLen (u32, bytes) + target (UTF-16LE)
//	commentLen (u32) + comment (UTF-16LE, usually empty)
//	+8 bytes unknown (2x u32)
//	userLen (u32) + user (UTF-16LE)
//	secretLen (u32) + secret (bytes)
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
func parseCredential(data []byte) (*credential, error) {
	if len(data) < 56 {
		return nil, fmt.Errorf("data too short for credential (%d bytes)", len(data))
	}
	c := &credential{Type: binary.LittleEndian.Uint32(data[12:16])}

	off := 48
	var err error
	if c.Target, err = readUTF16Field(data, &off); err != nil {
		return nil, fmt.Errorf("target: %v", err)
	}
	// comment (usually empty length) then 8 unknown bytes
	comment, err := readUTF16Field(data, &off)
	_ = comment
	if err != nil {
		return nil, fmt.Errorf("comment: %v", err)
	}
	off += 8
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
	return c, nil
}
