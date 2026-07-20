package gpp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"
)

// encryptForTest encrypts a plaintext password with the same key/IV/padding
// the real GPP uses, so Decrypt can be verified round-trip.
func encryptForTest(t *testing.T, utf16leBytes []byte) string {
	t.Helper()
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		t.Fatal(err)
	}
	n := aes.BlockSize - len(utf16leBytes)%aes.BlockSize
	for i := 0; i < n; i++ {
		utf16leBytes = append(utf16leBytes, byte(n))
	}
	out := make([]byte, len(utf16leBytes))
	cipher.NewCBCEncrypter(block, gppIV).CryptBlocks(out, utf16leBytes)
	return base64.StdEncoding.EncodeToString(out)
}

func utf16(s string) []byte {
	b := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		b[2*i] = s[i]
	}
	return b
}

func TestDecryptRoundTrip(t *testing.T) {
	for _, pw := range []string{"P@ssw0rd!", "Lab!GPP#2026", "a", "longer password with spaces 123"} {
		cpass := encryptForTest(t, utf16(pw))
		got, err := Decrypt(cpass)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", pw, err)
		}
		if got != pw {
			t.Errorf("Decrypt = %q, want %q", got, pw)
		}
	}
}

func TestDecryptKnownAnswer(t *testing.T) {
	// Precomputed with the published key/IV: Lab!GPP#2026.
	got, err := Decrypt("kWdVT+5RaKyqQvJ5Y/f9vj/X7m+/orgkCGss2H19U9U=")
	if err != nil {
		t.Fatalf("Decrypt known-answer: %v", err)
	}
	if got != "Lab!GPP#2026" {
		t.Errorf("Decrypt = %q, want Lab!GPP#2026", got)
	}
}

func TestDecryptErrors(t *testing.T) {
	for _, cpass := range []string{"", "!!!", "aGVsbG8", "aGVsbG8="} {
		if _, err := Decrypt(cpass); err == nil {
			t.Errorf("Decrypt(%q): expected error", cpass)
		}
	}
}

func TestFindInXML(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2" changed="2024-01-15 08:30:00" uid="{ABCD}">
    <Properties action="U" newName="" description="" cpassword="kWdVT+5RaKyqQvJ5Y/f9vj/X7m+/orgkCGss2H19U9U=" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="LocalAdmin" changed="2024-01-16 09:00:00"/>
  </User>
</Groups>`

	matches := FindInXML(xml)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	m := matches[0]
	if m.Cpassword != "kWdVT+5RaKyqQvJ5Y/f9vj/X7m+/orgkCGss2H19U9U=" {
		t.Errorf("Cpassword = %q", m.Cpassword)
	}
	if m.UserName != "LocalAdmin" {
		t.Errorf("UserName = %q, want LocalAdmin", m.UserName)
	}
	// changed is captured from the cpassword line when it appears there.
	if m.Changed != "2024-01-16 09:00:00" {
		t.Errorf("Changed = %q", m.Changed)
	}

	if got := FindInXML("<Groups><NoSecrets/></Groups>"); len(got) != 0 {
		t.Errorf("no-cpassword XML: got %d matches", len(got))
	}

	single := `<Properties userName='svc' cpassword='abc123'/>`
	m2 := FindInXML(single)
	if len(m2) != 1 || m2[0].Cpassword != "abc123" || m2[0].UserName != "svc" {
		t.Errorf("single-quote attrs: %+v", m2)
	}
}
