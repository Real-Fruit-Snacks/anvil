package sam

import (
	"encoding/hex"
	"testing"
)

func TestFormat(t *testing.T) {
	nt, _ := hex.DecodeString("c0ced2de918b4a7c1b9f4efd225dd503")
	u := User{Username: "Administrator", RID: 500, NTHash: nt, LMHash: emptyLM(), Enabled: true}
	want := "Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::"
	if got := Format(u); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func emptyLM() []byte {
	b, _ := hex.DecodeString("aad3b435b51404eeaad3b435b51404ee")
	return b
}

func TestDumpRejectsGarbage(t *testing.T) {
	if _, err := Dump(nil, nil); err == nil {
		t.Error("nil hives: expected error")
	}
	if _, err := Dump([]byte("not a hive"), []byte("also not")); err == nil {
		t.Error("garbage hives: expected error")
	}
	// Valid-looking but truncated input must error, not panic.
	if _, err := Dump(make([]byte, 4096), make([]byte, 4096)); err == nil {
		t.Error("zeroed 4K buffers: expected error")
	}
}
