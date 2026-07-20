package lsa

import "testing"

func TestFormatCached(t *testing.T) {
	c := CachedLogon{Domain: "HACKERBLUEPRINT", User: "Administrator", Hash: []byte{0xde, 0xad, 0xbe, 0xef}}
	want := "HACKERBLUEPRINT/Administrator:deadbeef"
	if got := FormatCached(c); got != want {
		t.Errorf("FormatCached = %q, want %q", got, want)
	}
}

func TestDumpRejectsGarbage(t *testing.T) {
	if _, err := Dump(nil, nil); err == nil {
		t.Error("nil hives: expected error")
	}
	if _, err := Dump([]byte("not a hive"), []byte("also not")); err == nil {
		t.Error("garbage hives: expected error")
	}
	if _, err := Dump(make([]byte, 4096), make([]byte, 4096)); err == nil {
		t.Error("zeroed 4K buffers: expected error")
	}
}

func TestLinesEmptyResult(t *testing.T) {
	r := &Result{}
	if lines := r.Lines(); len(lines) != 0 {
		t.Errorf("Lines on empty Result = %v, want none", lines)
	}
}

func TestLinesGenericSecret(t *testing.T) {
	r := &Result{Secrets: []Secret{{Name: "DefaultPassword", Value: []byte{0x41, 0x42}}}}
	lines := r.Lines()
	if len(lines) != 1 || lines[0] != "DefaultPassword:4142" {
		t.Errorf("Lines = %v", lines)
	}
}
