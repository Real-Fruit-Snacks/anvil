// Package dpapi decrypts DPAPI Credential Manager blobs using masterkeys
// recovered from the LSA dump (DPAPI_SYSTEM keys) via the Protect masterkey
// files. Pure: no I/O, no network.
package dpapi

import (
	"fmt"
	"strings"
	"unicode/utf8"

	godpapi "github.com/mandiant/gopacket/pkg/dpapi"
)

// Entry is one decrypted Credential Manager entry.
type Entry struct {
	Target string
	User   string
	Secret string // plaintext, rendered (short text as-is, binary as capped hex)
	Type   uint32
}

// BlobMasterKeyGUID returns the GuidMasterKey string of a credential file
// (the filename of the Protect masterkey file that protects it).
func BlobMasterKeyGUID(fileBytes []byte) (string, error) {
	cf, err := godpapi.ParseCredentialFile(fileBytes)
	if err != nil {
		return "", err
	}
	if cf.DPAPIBlob == nil {
		return "", fmt.Errorf("no DPAPI blob in credential file")
	}
	return cf.DPAPIBlob.GUIDMasterKey, nil
}

// DecryptBlob decrypts one credential file (as stored under
// ...\Microsoft\Credentials) with the given PROFILE masterkeys (from
// DecryptMasterKeyFile), tried in order, and parses the credential
// structure out of the plaintext.
func DecryptBlob(fileBytes []byte, keys [][]byte) (*Entry, error) {
	cf, err := godpapi.ParseCredentialFile(fileBytes)
	if err != nil {
		return nil, err
	}
	if cf.DPAPIBlob == nil {
		return nil, fmt.Errorf("no DPAPI blob in credential file")
	}

	var plain []byte
	for _, k := range keys {
		if len(k) == 0 {
			continue
		}
		if p, err := decryptBlob(cf.DPAPIBlob, k); err == nil {
			if c, err2 := parseCredential(p); err2 == nil {
				return &Entry{
					Target: strings.TrimRight(c.Target, "\x00"),
					User:   strings.TrimRight(c.User, "\x00"),
					Secret: renderSecret(c.Secret),
					Type:   c.Type,
				}, nil
			} else {
				_ = err2
			}
			plain = p
		}
	}
	if plain == nil {
		return nil, fmt.Errorf("no masterkey decrypts this blob")
	}
	return nil, fmt.Errorf("decrypted but credential unparseable")
}

// renderSecret renders a credential secret for display. Real Credential
// Manager passwords are short printable text (UTF-16 or UTF-8); anything
// else (cert blobs, large binary) is capped hex.
func renderSecret(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if s, ok := asShortText(b); ok {
		return s
	}
	const max = 64
	if len(b) > max {
		return fmt.Sprintf("0x%x… (%d bytes)", b[:max], len(b))
	}
	return fmt.Sprintf("0x%x", b)
}

// asShortText accepts the buffer as display text only when it decodes to
// at most 64 chars of strictly printable ASCII — UTF-16LE if the high
// bytes are NUL, otherwise UTF-8.
func asShortText(b []byte) (string, bool) {
	printable := func(s string) bool {
		if len(s) == 0 || len(s) > 64 {
			return false
		}
		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		return true
	}

	if len(b) >= 4 && len(b)%2 == 0 {
		nul := 0
		for i := 1; i < len(b); i += 2 {
			if b[i] == 0 {
				nul++
			}
		}
		if nul*20 >= len(b)/2*19 { // ≥95% NUL high bytes
			u16 := make([]uint16, len(b)/2)
			for i := range u16 {
				u16[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
			}
			s := strings.TrimRight(u16ToString(u16), "\x00")
			if printable(s) {
				return s, true
			}
		}
	}
	if utf8.Valid(b) {
		if s := strings.TrimRight(string(b), "\x00"); printable(s) {
			return s, true
		}
	}
	return "", false
}

func u16ToString(u []uint16) string {
	r := make([]rune, len(u))
	for i, c := range u {
		r[i] = rune(c)
	}
	return string(r)
}
