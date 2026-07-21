package cli

import (
	"errors"
	"strings"
	"testing"
)

// testNTHash is a syntactically valid NT hash (the empty-password hash),
// paired with the canonical empty LM hash for LM:NT fixtures.
const (
	testLMHash = "aad3b435b51404eeaad3b435b51404ee"
	testNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

func TestPlanGetTGT(t *testing.T) {
	cases := []struct {
		name    string
		opts    gettgtOptions
		want    gettgtPlan
		wantErr string // substring; empty means success
	}{
		{
			name: "password credential",
			opts: gettgtOptions{user: "alice", domain: "lab.local", password: "Password123"},
			want: gettgtPlan{
				user: "alice", domain: "lab.local", realm: "LAB.LOCAL",
				password: "Password123", out: "alice.ccache",
			},
		},
		{
			name: "hashes credential splits LM:NT",
			opts: gettgtOptions{user: "alice", domain: "lab.local", hashes: testLMHash + ":" + testNTHash},
			want: gettgtPlan{
				user: "alice", domain: "lab.local", realm: "LAB.LOCAL",
				ntHash: testNTHash, out: "alice.ccache",
			},
		},
		{
			name: "realm uppercased from mixed-case domain",
			opts: gettgtOptions{user: "alice", domain: "Lab.Local", password: "x"},
			want: gettgtPlan{
				user: "alice", domain: "Lab.Local", realm: "LAB.LOCAL",
				password: "x", out: "alice.ccache",
			},
		},
		{
			name: "trailing root dot stripped before uppercasing",
			opts: gettgtOptions{user: "alice", domain: "lab.local.", password: "x"},
			want: gettgtPlan{
				user: "alice", domain: "lab.local", realm: "LAB.LOCAL",
				password: "x", out: "alice.ccache",
			},
		},
		{
			name: "explicit out preserved",
			opts: gettgtOptions{user: "alice", domain: "lab.local", password: "x", out: "tickets/a.ccache"},
			want: gettgtPlan{
				user: "alice", domain: "lab.local", realm: "LAB.LOCAL",
				password: "x", out: "tickets/a.ccache",
			},
		},
		{
			name: "dc-ip override passthrough",
			opts: gettgtOptions{user: "alice", domain: "lab.local", password: "x", dcIP: "10.0.0.1"},
			want: gettgtPlan{
				user: "alice", domain: "lab.local", realm: "LAB.LOCAL",
				password: "x", dcIP: "10.0.0.1", out: "alice.ccache",
			},
		},
		{
			name:    "missing user",
			opts:    gettgtOptions{domain: "lab.local", password: "x"},
			wantErr: "-u is required",
		},
		{
			name:    "missing domain",
			opts:    gettgtOptions{user: "alice", password: "x"},
			wantErr: "-d is required",
		},
		{
			name:    "no credential",
			opts:    gettgtOptions{user: "alice", domain: "lab.local"},
			wantErr: "-p <password> or --hashes",
		},
		{
			name:    "both credentials rejected",
			opts:    gettgtOptions{user: "alice", domain: "lab.local", password: "x", hashes: testNTHash},
			wantErr: "mutually exclusive",
		},
		{
			name:    "non-hex NT hash",
			opts:    gettgtOptions{user: "alice", domain: "lab.local", hashes: "zz6cfe0d16ae931b73c59d7e0c089c0"},
			wantErr: "not hex",
		},
		{
			name:    "short NT half in LM:NT",
			opts:    gettgtOptions{user: "alice", domain: "lab.local", hashes: testLMHash + ":31d6cfe0"},
			wantErr: "want 32 hex chars",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := planGetTGT(tc.opts)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("planGetTGT(%+v) succeeded, want error containing %q", tc.opts, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("planGetTGT(%+v) error = %q, want substring %q", tc.opts, err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("planGetTGT(%+v) error = %v", tc.opts, err)
			}
			if got != tc.want {
				t.Errorf("planGetTGT(%+v) = %+v, want %+v", tc.opts, got, tc.want)
			}
		})
	}
}

func TestNTHashHalf(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{"bare NT hash", testNTHash, testNTHash, ""},
		{"secretsdump LM:NT", testLMHash + ":" + testNTHash, testNTHash, ""},
		{"empty LM half", ":" + testNTHash, testNTHash, ""},
		{"not hex", "not-a-hash", "", "not hex"},
		{"wrong length", "31d6cfe0", "", "want 32 hex chars"},
		{"empty", "", "", "want 32 hex chars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ntHashHalf(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ntHashHalf(%q) = %q, want error containing %q", tc.in, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ntHashHalf(%q) error = %q, want substring %q", tc.in, err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ntHashHalf(%q) error = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ntHashHalf(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMapGetTGTError(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want string // substring of the themed message; empty = passthrough
	}{
		{
			"KDC unreachable",
			errors.New("failed to connect to KDC 10.0.0.1:88: dial tcp 10.0.0.1:88: connectex: No route to host"),
			"KDC unreachable",
		},
		{
			"preauth failed is a wrong password",
			errors.New("pre-authentication failed (KDC_ERR_PREAUTH_FAILED) - invalid password/key"),
			"wrong password or NT hash for alice@LAB.LOCAL",
		},
		{
			"unknown user",
			errors.New("client not found in Kerberos database (KDC_ERR_C_PRINCIPAL_UNKNOWN)"),
			"no such user alice@LAB.LOCAL",
		},
		{
			"other KDC errors pass through",
			errors.New("clock skew too great (KDC_ERR_SKEW) - sync time with DC"),
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapGetTGTError(tc.in, "alice", "LAB.LOCAL")
			if tc.want == "" {
				if got != tc.in {
					t.Errorf("mapGetTGTError(%v) = %v, want passthrough", tc.in, got)
				}
				return
			}
			if !strings.Contains(got.Error(), tc.want) {
				t.Errorf("mapGetTGTError(%v) = %q, want substring %q", tc.in, got.Error(), tc.want)
			}
		})
	}
}

func TestGetTGTCommandFlags(t *testing.T) {
	cmd := newGetTGTCmd()
	for _, name := range []string{"user", "domain", "password", "hashes", "dc-ip", "out"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("gettgt: --%s not registered", name)
		}
	}
	for name, shorthand := range map[string]string{"user": "u", "domain": "d", "password": "p"} {
		f := cmd.Flags().Lookup(name)
		if f == nil || f.Shorthand != shorthand {
			t.Errorf("gettgt: --%s shorthand = %q, want %q", name, f.Shorthand, shorthand)
		}
	}
}
