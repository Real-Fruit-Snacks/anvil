package ntds

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// secretsdump renders a missing hash as the empty password's hash: the LM
// constant when the account has no stored LM hash, the NT constant when it
// has no stored NT hash.
const (
	wantEmptyLM = "aad3b435b51404eeaad3b435b51404ee"
	wantEmptyNT = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// eseHeader returns a buffer that passes the ESE magic check (signature
// 0x89ABCDEF at offset 4, page size at offset 236) and nothing more — for
// "looks like a .dit but isn't" inputs.
func eseHeader(size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b[4:8], 0x89ABCDEF)
	if size >= 240 {
		binary.LittleEndian.PutUint32(b[236:240], 8192)
	}
	return b
}

func TestFormat(t *testing.T) {
	u := User{
		Name:   "Administrator",
		RID:    500,
		NTHash: mustHex(t, "c0ced2de918b4a7c1b9f4efd225dd503"),
		LMHash: mustHex(t, wantEmptyLM),
	}
	want := `LAB\Administrator:500:` + wantEmptyLM + `:c0ced2de918b4a7c1b9f4efd225dd503:::`
	if got := Format("LAB", u); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestFormatEmptyHashConstants(t *testing.T) {
	nt := mustHex(t, "c0ced2de918b4a7c1b9f4efd225dd503")
	lm := mustHex(t, wantEmptyLM)
	cases := []struct {
		name string
		u    User
		want string
	}{
		{"no LM hash stored", User{Name: "alice", RID: 1103, NTHash: nt},
			`LAB\alice:1103:` + wantEmptyLM + `:c0ced2de918b4a7c1b9f4efd225dd503:::`},
		{"no NT hash stored", User{Name: "alice", RID: 1103, LMHash: lm},
			`LAB\alice:1103:` + wantEmptyLM + `:` + wantEmptyNT + `:::`},
		{"neither hash stored", User{Name: "alice", RID: 1103},
			`LAB\alice:1103:` + wantEmptyLM + `:` + wantEmptyNT + `:::`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Format("LAB", c.u); got != c.want {
				t.Errorf("Format = %q, want %q", got, c.want)
			}
		})
	}
}

// Every malformed input must produce an error, never a panic. (No real
// ntds.dit fixture exists in the gopacket tree — pkg/ese ships no testdata —
// so there is no round-trip test here yet.)
func TestDumpRejectsBadInput(t *testing.T) {
	cases := []struct {
		name                 string
		ntdsData, systemData []byte
	}{
		{"nil hives", nil, nil},
		{"nil ntds", nil, []byte("garbage system")},
		{"nil system", []byte("garbage ntds"), nil},
		{"garbage hives", []byte("not an ntds.dit"), []byte("not a SYSTEM hive")},
		{"zeroed hives", make([]byte, 8192), make([]byte, 8192)},
		// Valid ESE magic but short of one page: the truncated-download case.
		{"truncated ESE", eseHeader(512), eseHeader(512)},
		// Valid ESE magic and size, but no catalog/datatable inside.
		{"ESE magic, no datatable", eseHeader(16384), eseHeader(16384)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Dump(c.ntdsData, c.systemData); err == nil {
				t.Error("expected error")
			}
		})
	}
}
