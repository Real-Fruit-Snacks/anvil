package dpapi

import (
	"os"
	"testing"
)

func TestParseRealPlaintext(t *testing.T) {
	data, err := os.ReadFile("testdata/cred-plain.bin")
	if err != nil {
		t.Skip("no fixture")
	}
	c, err := parseCredential(data)
	if err != nil {
		t.Fatalf("parseCredential: %v", err)
	}
	t.Logf("target=%q user=%q secretLen=%d", c.Target, c.User, len(c.Secret))
	if c.Target != "LegacyGeneric:target=anviltest\x00" && c.Target != "LegacyGeneric:target=anviltest" {
		t.Errorf("target = %q", c.Target)
	}
	if renderSecret(c.Secret) != "S3cretP@ssw0rd!" {
		t.Errorf("secret = %q", renderSecret(c.Secret))
	}
}
