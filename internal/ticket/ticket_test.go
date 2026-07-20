package ticket

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/credentials"
)

// A syntactically valid krbtgt NT hash (value is irrelevant offline) and a
// well-formed domain SID, reused across the forge tests.
const (
	testHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
	testSID  = "S-1-5-21-1004336348-1177238915-682003330"
)

func TestNormalizeNTHash(t *testing.T) {
	valid := []struct {
		name, in, want string
	}{
		{"bare", testHash, testHash},
		{"uppercase", strings.ToUpper(testHash), strings.ToUpper(testHash)},
		{"lm:nt", "aad3b435b51404eeaad3b435b51404ee:" + testHash, testHash},
		{"colon prefix", ":" + testHash, testHash},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeNTHash(tc.in, "-krbtgt", "krbtgt NT hash")
			if err != nil {
				t.Fatalf("normalizeNTHash(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeNTHash(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	invalid := []struct {
		name, in, wantErr string
	}{
		{"empty", "", "-krbtgt is required"},
		{"short", "abcd", "want 32 hex chars"},
		{"aes key length", testHash + testHash, "want 32 hex chars"},
		{"not hex", "zzd6cfe0d16ae931b73c59d7e0c089c0", "not hex"},
		{"lm:nt short nt", "aad3b435b51404eeaad3b435b51404ee:abcd", "want 32 hex chars"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeNTHash(tc.in, "-krbtgt", "krbtgt NT hash")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("normalizeNTHash(%q) error = %v, want substring %q", tc.in, err, tc.wantErr)
			}
		})
	}

	// Silver mode names the -nthash flag in errors instead.
	if _, err := normalizeNTHash("", "-nthash", "NT hash"); err == nil ||
		!strings.Contains(err.Error(), "-nthash is required") {
		t.Errorf("normalizeNTHash empty silver error = %v, want -nthash is required", err)
	}
	if _, err := normalizeNTHash("zz", "-nthash", "NT hash"); err == nil ||
		!strings.Contains(err.Error(), "invalid NT hash: not hex") {
		t.Errorf("normalizeNTHash bad silver error = %v, want invalid NT hash", err)
	}
}

func TestValidateSPN(t *testing.T) {
	valid := []string{"cifs/dc01.lab.local", "http/web.corp.local", "ldap/DC01.LAB.LOCAL"}
	for _, s := range valid {
		if err := validateSPN(s); err != nil {
			t.Errorf("valid SPN %q rejected: %v", s, err)
		}
	}

	invalid := []string{"", "cifs", "/dc01.lab.local", "cifs/", "cifs/dc01.lab.local/extra"}
	for _, s := range invalid {
		if err := validateSPN(s); err == nil || !strings.Contains(err.Error(), "invalid -spn") {
			t.Errorf("validateSPN(%q) error = %v, want invalid -spn", s, err)
		}
	}
}

func TestValidateDomainSID(t *testing.T) {
	if err := validateDomainSID(testSID); err != nil {
		t.Errorf("valid domain SID rejected: %v", err)
	}

	invalid := []struct {
		name, in, wantErr string
	}{
		{"empty", "", "-domain-sid is required"},
		{"garbage", "not-a-sid", "invalid domain SID"},
		{"missing prefix", "1-5-21-1004336348-1177238915-682003330", "invalid domain SID"},
		{"local system", "S-1-5-18", "want S-1-5-21"},
		{"incomplete", "S-1-5-21", "want S-1-5-21"},
		{"user rid appended", testSID + "-500", "want S-1-5-21"},
		{"sub-authority overflow", "S-1-5-21-99999999999-1177238915-682003330", "invalid domain SID"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDomainSID(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateDomainSID(%q) error = %v, want substring %q", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestForgeValidationErrors: bad input fails before anything is written.
func TestForgeValidationErrors(t *testing.T) {
	t.Chdir(t.TempDir())

	base := Options{User: "alice", Domain: "lab.local", DomainSID: testSID, KrbtgtHash: testHash}

	cases := []struct {
		name    string
		mutate  func(*Options)
		wantErr string
	}{
		{"missing user", func(o *Options) { o.User = "" }, "-user is required"},
		{"missing domain", func(o *Options) { o.Domain = "" }, "-domain is required"},
		{"missing hash", func(o *Options) { o.KrbtgtHash = "" }, "exactly one of -krbtgt (golden) or -nthash (silver) is required"},
		{"bad hash length", func(o *Options) { o.KrbtgtHash = "abcd" }, "want 32 hex chars"},
		{"missing sid", func(o *Options) { o.DomainSID = "" }, "-domain-sid is required"},
		{"bad sid", func(o *Options) { o.DomainSID = "S-1-5-18" }, "invalid domain SID"},
		{"both hashes", func(o *Options) {
			o.NTHash = testHash
			o.SPN = "cifs/dc01.lab.local"
		}, "-krbtgt and -nthash are mutually exclusive"},
		{"spn with krbtgt", func(o *Options) { o.SPN = "cifs/dc01.lab.local" }, "-spn is only valid with -nthash"},
		{"nthash without spn", func(o *Options) {
			o.KrbtgtHash = ""
			o.NTHash = testHash
		}, "-spn is required with -nthash"},
		{"bad spn", func(o *Options) {
			o.KrbtgtHash = ""
			o.NTHash = testHash
			o.SPN = "dc01.lab.local"
		}, "invalid -spn"},
		{"bad nthash", func(o *Options) {
			o.KrbtgtHash = ""
			o.NTHash = "abcd"
			o.SPN = "cifs/dc01.lab.local"
		}, "want 32 hex chars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mutate(&opts)
			_, err := Forge(opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Forge error = %v, want substring %q", err, tc.wantErr)
			}
			entries, _ := os.ReadDir(".")
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".ccache") {
					t.Errorf("ccache %s written despite validation failure", e.Name())
				}
			}
		})
	}
}

// TestForgeDefaultOut: no -out lands at <user>.ccache in the cwd.
func TestForgeDefaultOut(t *testing.T) {
	t.Chdir(t.TempDir())

	path, err := Forge(Options{User: "alice", Domain: "lab.local", DomainSID: testSID, KrbtgtHash: testHash})
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if path != "alice.ccache" {
		t.Errorf("path = %q, want alice.ccache", path)
	}
	if _, err := os.Stat("alice.ccache"); err != nil {
		t.Errorf("default ccache not in cwd: %v", err)
	}
}

// TestForgeBadOutDir: a bad -out path errors and leaves no stray ccache.
func TestForgeBadOutDir(t *testing.T) {
	t.Chdir(t.TempDir())

	_, err := Forge(Options{
		User:       "alice",
		Domain:     "lab.local",
		DomainSID:  testSID,
		KrbtgtHash: testHash,
		Out:        filepath.Join("no-such-dir", "x.ccache"),
	})
	if err == nil {
		t.Fatal("Forge: want error for missing -out directory")
	}
	if _, statErr := os.Stat("alice.ccache"); !os.IsNotExist(statErr) {
		t.Errorf("stray intermediate ccache left in cwd after failed move")
	}
}

// TestForgeWritesCcache: -out is honored, the cwd copy is moved away, and
// the result parses back as a v4 ccache holding a krbtgt TGT for the user.
func TestForgeWritesCcache(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	out := filepath.Join(dir, "sub", "Administrator.ccache")
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		t.Fatal(err)
	}

	path, err := Forge(Options{
		User:       "Administrator",
		Domain:     "lab.local",
		DomainSID:  testSID,
		KrbtgtHash: testHash,
		Out:        out,
	})
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if path != out {
		t.Errorf("path = %q, want %q", path, out)
	}
	if _, err := os.Stat("Administrator.ccache"); !os.IsNotExist(err) {
		t.Errorf("stray ccache left in cwd after move")
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read ccache: %v", err)
	}
	if len(data) < 2 || data[0] != 0x05 || data[1] != 0x04 {
		t.Fatalf("ccache header = %x, want 0504", data[:min(2, len(data))])
	}

	cc, err := credentials.LoadCCache(out)
	if err != nil {
		t.Fatalf("LoadCCache round-trip: %v", err)
	}
	if got := cc.DefaultPrincipal.Realm; got != "LAB.LOCAL" {
		t.Errorf("default principal realm = %q, want LAB.LOCAL", got)
	}
	names := cc.DefaultPrincipal.PrincipalName.NameString
	if len(names) != 1 || names[0] != "Administrator" {
		t.Errorf("default principal = %v, want [Administrator]", names)
	}
	if len(cc.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cc.Credentials))
	}
	cred := cc.Credentials[0]
	if sname := strings.Join(cred.Server.PrincipalName.NameString, "/"); sname != "krbtgt/LAB.LOCAL" {
		t.Errorf("server principal = %q, want krbtgt/LAB.LOCAL", sname)
	}
	// Default lifetime is 87600h (~10 years), matching impacket's ticketer.
	if d := time.Until(cred.EndTime); d < 87599*time.Hour || d > 87600*time.Hour {
		t.Errorf("ticket lifetime = %v, want ~87600h", d)
	}
}

// TestForgeSilverWritesCcache: -nthash + -spn forges a service ticket whose
// ccache server principal is the SPN — not krbtgt/REALM — and whose client
// principal, realm, and lifetime match the golden forge.
func TestForgeSilverWritesCcache(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	out := filepath.Join(dir, "sub", "Administrator.ccache")
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		t.Fatal(err)
	}

	path, err := Forge(Options{
		User:      "Administrator",
		Domain:    "lab.local",
		DomainSID: testSID,
		NTHash:    testHash,
		SPN:       "cifs/dc01.lab.local",
		Out:       out,
	})
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if path != out {
		t.Errorf("path = %q, want %q", path, out)
	}
	if _, err := os.Stat("Administrator.ccache"); !os.IsNotExist(err) {
		t.Errorf("stray ccache left in cwd after move")
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read ccache: %v", err)
	}
	if len(data) < 2 || data[0] != 0x05 || data[1] != 0x04 {
		t.Fatalf("ccache header = %x, want 0504", data[:min(2, len(data))])
	}

	cc, err := credentials.LoadCCache(out)
	if err != nil {
		t.Fatalf("LoadCCache round-trip: %v", err)
	}
	if got := cc.DefaultPrincipal.Realm; got != "LAB.LOCAL" {
		t.Errorf("default principal realm = %q, want LAB.LOCAL", got)
	}
	names := cc.DefaultPrincipal.PrincipalName.NameString
	if len(names) != 1 || names[0] != "Administrator" {
		t.Errorf("default principal = %v, want [Administrator]", names)
	}
	if len(cc.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cc.Credentials))
	}
	cred := cc.Credentials[0]
	if sname := strings.Join(cred.Server.PrincipalName.NameString, "/"); sname != "cifs/dc01.lab.local" {
		t.Errorf("server principal = %q, want cifs/dc01.lab.local (not krbtgt/LAB.LOCAL)", sname)
	}
	if got := cred.Server.Realm; got != "LAB.LOCAL" {
		t.Errorf("server realm = %q, want LAB.LOCAL", got)
	}
	if d := time.Until(cred.EndTime); d < 87599*time.Hour || d > 87600*time.Hour {
		t.Errorf("ticket lifetime = %v, want ~87600h", d)
	}
}
