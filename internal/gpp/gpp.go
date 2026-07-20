// Package gpp extracts and decrypts Group Policy Preferences (GPP)
// cpassword attributes. Pure: no I/O, no network.
package gpp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/utf16le"
)

// gppKey is Microsoft's published AES-256 key for GPP cpasswords
// (MS-GPPREF 2c15cbf0-f086-4c74-8b70-1f2fa45dd4be).
var gppKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// gppIV is the fixed all-zero IV Microsoft uses.
var gppIV = make([]byte, 16)

// Decrypt decrypts a base64 cpassword with the published key (AES-256-CBC,
// zero IV, PKCS7 padding) and returns the plaintext password.
func Decrypt(cpassword string) (string, error) {
	if cpassword == "" {
		return "", fmt.Errorf("empty cpassword")
	}

	// Base64 padding tolerance (mirrors tools/Get-GPPPassword).
	switch pad := len(cpassword) % 4; pad {
	case 1:
		cpassword = cpassword[:len(cpassword)-1]
	case 2, 3:
		cpassword += strings.Repeat("=", 4-pad)
	}

	encrypted, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %v", err)
	}
	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(gppKey)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, gppIV).CryptBlocks(decrypted, encrypted)

	decrypted = pkcs7Unpad(decrypted)
	if decrypted == nil {
		return "", fmt.Errorf("invalid padding")
	}
	return strings.TrimRight(utf16le.DecodeToString(decrypted), "\x00"), nil
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil
		}
	}
	return b[:len(b)-n]
}

// Match is one cpassword occurrence with its context attributes.
type Match struct {
	Cpassword string
	UserName  string
	Changed   string
}

// FindInXML finds all cpassword="..." (or cpassword='...') attribute values
// in XML text, line by line (mirrors tools/Get-GPPPassword's extraction:
// cpassword and its context attributes must share a line).
func FindInXML(content string) []Match {
	var out []Match
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "cpassword") {
			continue
		}
		cpass := extractAttribute(line, "cpassword")
		if cpass == "" {
			continue
		}
		out = append(out, Match{
			Cpassword: cpass,
			UserName:  extractAttribute(line, "userName"),
			Changed:   extractAttribute(line, "changed"),
		})
	}
	return out
}

// extractAttribute returns the value of attr="value" or attr='value' in a
// single line (mirrors tools/Get-GPPPassword's extractAttribute).
func extractAttribute(line, attr string) string {
	for _, prefix := range []string{attr + `="`, attr + `='`} {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		quote := line[idx+len(attr)+1]
		end := strings.Index(line[start:], string(quote))
		if end < 0 {
			continue
		}
		return line[start : start+end]
	}
	return ""
}
