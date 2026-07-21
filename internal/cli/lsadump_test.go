package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"anvil/internal/lsa"
)

func TestLsadumpFlags(t *testing.T) {
	cmd := newLsadumpCmd()
	for _, name := range []string{"system", "security"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("lsadump: --%s not registered", name)
		}
	}
}

func TestLsadumpOfflineRequiresBothFlags(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	cases := []struct {
		name         string
		systemPath   string
		securityPath string
	}{
		{"neither flag set", "", ""},
		{"missing --system", "", hive},
		{"missing --security", hive, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lsadumpOffline(tc.systemPath, tc.securityPath)
			if err == nil || !strings.Contains(err.Error(), "--system and --security") {
				t.Errorf("err = %v, want both-required error", err)
			}
		})
	}
}

func TestLsadumpOfflineMissingFile(t *testing.T) {
	hive := writeHiveFixture(t, "system.hive", []byte("x"))
	missing := filepath.Join(t.TempDir(), "nope.hive")
	cases := []struct {
		name         string
		systemPath   string
		securityPath string
	}{
		{"missing SYSTEM hive", missing, hive},
		{"missing SECURITY hive", hive, missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lsadumpOffline(tc.systemPath, tc.securityPath)
			if err == nil {
				t.Fatal("expected error")
			}
			if want := "cannot read " + missing + ":"; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("err = %q, want prefix %q", err.Error(), want)
			}
		})
	}
}

func TestLsadumpOfflineRejectsGarbageHives(t *testing.T) {
	system := writeHiveFixture(t, "system.hive", []byte("not a hive"))
	security := writeHiveFixture(t, "security.hive", []byte("also not"))
	if _, err := lsadumpOffline(system, security); err == nil {
		t.Error("garbage hives: expected error")
	}
}

// The offline output must be byte-identical to the live shell op's:
// CACHED LOGONS first, then LSA SECRETS, both two-space indented.
func TestPrintLSAResultMatchesLiveLayout(t *testing.T) {
	res := &lsa.Result{
		Secrets: []lsa.Secret{{Name: "DefaultPassword", Value: []byte{0x41, 0x42}}},
		CachedLogons: []lsa.CachedLogon{
			{Domain: "HACKERBLUEPRINT", User: "Administrator", Hash: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
	}
	want := "  CACHED LOGONS\n" +
		"  HACKERBLUEPRINT/Administrator:deadbeef\n" +
		"  LSA SECRETS\n" +
		"  DefaultPassword:4142\n"
	if got := captureDumpStdout(t, func() { printLSAResult(res) }); got != want {
		t.Errorf("printLSAResult = %q, want %q", got, want)
	}
}

func TestPrintLSAResultEmpty(t *testing.T) {
	got := captureDumpStdout(t, func() { printLSAResult(&lsa.Result{}) })
	if want := "  (no LSA secrets)\n"; got != want {
		t.Errorf("printLSAResult(empty) = %q, want %q", got, want)
	}
}
