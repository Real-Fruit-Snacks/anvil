package dcsync

import (
	"encoding/hex"
	"testing"
)

func TestFormat(t *testing.T) {
	nt, _ := hex.DecodeString("c0ced2de918b4a7c1b9f4efd225dd503")
	lm, _ := hex.DecodeString("aad3b435b51404eeaad3b435b51404ee")
	u := User{SAMAccountName: "Administrator", RID: 500, NTHash: nt, LMHash: lm}
	want := `LAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::`
	if got := Format("LAB", u); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestNetBIOSDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"LAB", "LAB"},
		{"lab.local", "LAB"},
		{"corp.example.com", "CORP"},
	}
	for _, c := range cases {
		if got := NetBIOSDomain(c.in); got != c.want {
			t.Errorf("NetBIOSDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
