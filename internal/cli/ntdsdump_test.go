package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNtdsdumpFlags(t *testing.T) {
	cmd := newNtdsdumpCmd()
	for _, name := range []string{"system", "ntds"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("ntdsdump: --%s not registered", name)
		}
	}
}

func TestNtdsdumpOfflineRequiresBothFlags(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	cases := []struct {
		name       string
		systemPath string
		ntdsPath   string
	}{
		{"neither flag set", "", ""},
		{"missing --system", "", hive},
		{"missing --ntds", hive, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ntdsdumpOffline(tc.systemPath, tc.ntdsPath)
			if err == nil || !strings.Contains(err.Error(), "--system and --ntds") {
				t.Errorf("err = %v, want both-required error", err)
			}
		})
	}
}

func TestNtdsdumpOfflineMissingFile(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	missing := filepath.Join(t.TempDir(), "nope.dit")
	cases := []struct {
		name       string
		systemPath string
		ntdsPath   string
	}{
		{"missing SYSTEM hive", missing, hive},
		{"missing NTDS.dit", hive, missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ntdsdumpOffline(tc.systemPath, tc.ntdsPath)
			if err == nil {
				t.Fatal("expected error")
			}
			if want := "cannot read " + missing + ":"; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("err = %q, want prefix %q", err.Error(), want)
			}
		})
	}
}

func TestNtdsdumpOfflineRejectsGarbageHives(t *testing.T) {
	system := writeHiveFixture(t, "system.hive", []byte("not a hive"))
	dit := writeHiveFixture(t, "ntds.dit", []byte("also not"))
	if _, err := ntdsdumpOffline(system, dit); err == nil {
		t.Error("garbage inputs: expected error")
	}
}

func TestPrintNtdsDumpLayout(t *testing.T) {
	note := "  note: dump reflects the last ESE flush (no edb.log replay) — recent accounts may be missing\n"
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			"accounts, count, then ESE-flush note",
			[]string{`LAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::`},
			`LAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::` + "\n" +
				"  1 accounts\n" + note,
		},
		{"no accounts still prints the note", nil, "  no accounts found\n" + note},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := captureDumpStdout(t, func() { printNtdsDump(tc.lines) }); got != tc.want {
				t.Errorf("printNtdsDump = %q, want %q", got, tc.want)
			}
		})
	}
}
