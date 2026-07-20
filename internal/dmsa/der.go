package dmsa

import "time"

// Minimal DER builders for the Kerberos structures this package marshals
// (fixtures, round-trip tests, and the PA-S4U-X509-USER pre-auth data).
// gopacket's pkg/kerberos carries the same helpers unexported in
// keylist.go; these are the anvil copies, kept deliberately small.

// derWrap prepends a tag and DER length to content.
func derWrap(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// derSeq wraps the concatenated parts in a SEQUENCE.
func derSeq(parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return derWrap(0x30, content)
}

// derExplicit wraps inner (already-encoded DER) in context tag [tag]
// EXPLICIT.
func derExplicit(tag int, inner []byte) []byte {
	return derWrap(byte(0xA0+tag), inner)
}

// derLen encodes a DER length (short form below 128, long form above).
func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// derInt encodes a signed INTEGER (two's complement, minimal length).
// Negative values occur in Kerberos checksum types (HMAC-MD5 is -138).
func derInt(v int64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	// Trim leading bytes while the sign is preserved: drop 0x00 when the
	// next byte's high bit is clear (positive), 0xFF when it is set.
	i := 0
	for i < 7 {
		if b[i] == 0x00 && b[i+1]&0x80 == 0 || b[i] == 0xFF && b[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return derWrap(0x02, b[i:])
}

// derOctetString wraps b in an OCTET STRING.
func derOctetString(b []byte) []byte { return derWrap(0x04, b) }

// derGeneralizedTime encodes t as KerberosTime (YYYYMMDDHHMMSSZ).
func derGeneralizedTime(t time.Time) []byte {
	return derWrap(0x18, []byte(t.UTC().Format("20060102150405Z")))
}

// derGeneralString encodes s as a GeneralString (Realm in Kerberos
// structures — IA5 in practice, ASCII-safe).
func derGeneralString(s string) []byte { return derWrap(0x1B, []byte(s)) }

// derBitString encodes raw as a BIT STRING with zero unused bits. The
// S4U options field is a 32-bit big-endian bit string.
func derBitString(raw []byte) []byte {
	return derWrap(0x03, append([]byte{0x00}, raw...))
}
