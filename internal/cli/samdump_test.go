package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// No real SAM/SECURITY/SYSTEM hive or NTDS.dit fixtures exist anywhere in
// the repo or the gopacket tree (pkg/registry and pkg/ese ship no
// testdata), so there is no offline round-trip test here — the parsers'
// own tests cover Format and garbage rejection. These tests cover the CLI
// plumbing hermetically: flags, required-flag validation, themed
// missing-file errors, and the exact printed layout.

// writeHiveFixture writes data to a named file in the test's temp dir and
// returns its path — the stand-in for an exported hive.
func writeHiveFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hive fixture: %v", err)
	}
	return path
}

// captureDumpStdout runs fn with stdout redirected to a pipe and returns
// everything it printed. Two sinks need redirecting: plain fmt.* writes to
// os.Stdout, while the ui.* themed printers (fatih/color) write to
// color.Output, which is bound to the real stdout at package init. NoColor
// is forced so the themed printers render plain text.
func captureDumpStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdout, oldOutput, oldNoColor := os.Stdout, color.Output, color.NoColor
	os.Stdout, color.Output, color.NoColor = w, w, true
	defer func() {
		os.Stdout, color.Output, color.NoColor = oldStdout, oldOutput, oldNoColor
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

func TestSamdumpFlags(t *testing.T) {
	cmd := newSamdumpCmd()
	for _, name := range []string{"system", "sam"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("samdump: --%s not registered", name)
		}
	}
}

func TestSamdumpOfflineRequiresBothFlags(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	cases := []struct {
		name       string
		systemPath string
		samPath    string
	}{
		{"neither flag set", "", ""},
		{"missing --system", "", hive},
		{"missing --sam", hive, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := samdumpOffline(tc.systemPath, tc.samPath)
			if err == nil || !strings.Contains(err.Error(), "--system and --sam") {
				t.Errorf("err = %v, want both-required error", err)
			}
		})
	}
}

func TestSamdumpOfflineMissingFile(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	missing := filepath.Join(t.TempDir(), "nope.hive")
	cases := []struct {
		name       string
		systemPath string
		samPath    string
	}{
		{"missing SYSTEM hive", missing, hive},
		{"missing SAM hive", hive, missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := samdumpOffline(tc.systemPath, tc.samPath)
			if err == nil {
				t.Fatal("expected error")
			}
			if want := "cannot read " + missing + ":"; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("err = %q, want prefix %q", err.Error(), want)
			}
		})
	}
}

func TestSamdumpOfflineRejectsGarbageHives(t *testing.T) {
	system := writeHiveFixture(t, "system.hive", []byte("not a hive"))
	sam := writeHiveFixture(t, "sam.hive", []byte("also not"))
	if _, err := samdumpOffline(system, sam); err == nil {
		t.Error("garbage hives: expected error")
	}
}

func TestPrintSamDumpLayout(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			"accounts print raw, no indent",
			[]string{
				"Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::",
				"Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
			},
			"Administrator:500:aad3b435b51404eeaad3b435b51404ee:c0ced2de918b4a7c1b9f4efd225dd503:::\n" +
				"Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n",
		},
		{"no accounts", nil, "  no local accounts found\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := captureDumpStdout(t, func() { printSamDump(tc.lines) }); got != tc.want {
				t.Errorf("printSamDump = %q, want %q", got, tc.want)
			}
		})
	}
}
