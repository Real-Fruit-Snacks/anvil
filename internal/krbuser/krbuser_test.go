package krbuser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/krberror"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// marshalKRBError builds a wire-form KRB-ERROR the way a KDC would send it,
// for feeding ClassifyReply hermetically.
func marshalKRBError(t *testing.T, code int32) []byte {
	t.Helper()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "LAB.LOCAL"},
	}
	kerr := messages.NewKRBError(sname, "LAB.LOCAL", code, "test error")
	b, err := kerr.Marshal()
	if err != nil {
		t.Fatalf("marshal KRBError code %d: %v", code, err)
	}
	return b
}

func TestClassifyReply(t *testing.T) {
	cases := []struct {
		name        string
		reply       []byte
		wantVerdict Verdict
		wantDetail  string
	}{
		{
			"preauth required means the account exists",
			marshalKRBError(t, 25),
			VerdictValid,
			"KDC_ERR_PREAUTH_REQUIRED",
		},
		{
			"principal unknown means no such account",
			marshalKRBError(t, 6),
			VerdictInvalid,
			"KDC_ERR_C_PRINCIPAL_UNKNOWN",
		},
		{
			"client revoked means locked or disabled",
			marshalKRBError(t, 18),
			VerdictLocked,
			"KDC_ERR_CLIENT_REVOKED",
		},
		{
			"unrelated kdc error stays an error with its symbolic name",
			marshalKRBError(t, 68),
			VerdictError,
			"KDC_ERR_WRONG_REALM",
		},
		{
			// The DONT_REQ_PREAUTH state: the KDC answers the bare
			// AS-REQ with a live AS-REP (tag 0x6B) rather than any
			// KRB-ERROR — that is the roastable finding.
			"as-rep tag means valid account with no preauth (roastable)",
			[]byte{0x6b, 0x30, 0x81, 0x01},
			VerdictValidNoPreauth,
			"AS-REP without pre-authentication (roastable)",
		},
		{
			"non-kerberos garbage is an error",
			[]byte("this is not a kdc reply"),
			VerdictError,
			"unrecognized KDC reply:",
		},
		{
			"empty reply is an error",
			nil,
			VerdictError,
			"unrecognized KDC reply:",
		},
		{
			"krb-error tag with truncated body is an error",
			[]byte{0x7e, 0x30, 0x05},
			VerdictError,
			"unrecognized KDC reply:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, detail := ClassifyReply(tc.reply)
			if v != tc.wantVerdict {
				t.Errorf("ClassifyReply verdict = %v, want %v", v, tc.wantVerdict)
			}
			if !strings.HasPrefix(detail, tc.wantDetail) {
				t.Errorf("ClassifyReply detail = %q, want prefix %q", detail, tc.wantDetail)
			}
		})
	}
}

// loginErrorf reproduces the shape of a gokrb5 client.Login failure for the
// given KDC code: krberror.Errorf flattens the KRBError's rendered text
// (symbolic name included) into the returned error string.
func loginErrorf(t *testing.T, code int32) error {
	t.Helper()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "LAB.LOCAL"},
	}
	kerr := messages.NewKRBError(sname, "LAB.LOCAL", code, "test error")
	return krberror.Errorf(kerr, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
}

func TestClassifyLoginErr(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantVerdict Verdict
		wantOK      bool
		wantDetail  string
	}{
		{
			"nil error means the password is correct",
			nil,
			VerdictValid,
			true,
			"password correct",
		},
		{
			"preauth failed means wrong password on a real account",
			loginErrorf(t, 24),
			VerdictValid,
			false,
			"KDC_ERR_PREAUTH_FAILED",
		},
		{
			"key expired proves the password while refusing the ticket",
			loginErrorf(t, 23),
			VerdictValid,
			true,
			"KDC_ERR_KEY_EXPIRED",
		},
		{
			"client revoked means locked or disabled",
			loginErrorf(t, 18),
			VerdictLocked,
			false,
			"KDC_ERR_CLIENT_REVOKED",
		},
		{
			"principal unknown means no such account",
			loginErrorf(t, 6),
			VerdictInvalid,
			false,
			"KDC_ERR_C_PRINCIPAL_UNKNOWN",
		},
		{
			"unrelated kdc error stays an error",
			loginErrorf(t, 68),
			VerdictError,
			false,
			"KDC_ERR_WRONG_REALM",
		},
		{
			"transport failure stays an error",
			errors.New("communication error with KDC via TCP: dial tcp 10.0.0.1:88: connect: connection refused"),
			VerdictError,
			false,
			"connection refused",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok, detail := ClassifyLoginErr(tc.err)
			if v != tc.wantVerdict {
				t.Errorf("ClassifyLoginErr verdict = %v, want %v", v, tc.wantVerdict)
			}
			if ok != tc.wantOK {
				t.Errorf("ClassifyLoginErr passwordOK = %v, want %v", ok, tc.wantOK)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("ClassifyLoginErr detail = %q, want substring %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestLoadUsers(t *testing.T) {
	dir := t.TempDir()

	t.Run("comments blanks and crlf are skipped", func(t *testing.T) {
		p := filepath.Join(dir, "users.txt")
		content := "# comment line\r\nalice\r\n\r\n   \nbob\n  # indented comment\n carol \n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadUsers(p)
		if err != nil {
			t.Fatalf("LoadUsers: %v", err)
		}
		want := []string{"alice", "bob", "carol"}
		if len(got) != len(want) {
			t.Fatalf("LoadUsers = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("LoadUsers = %v, want %v", got, want)
			}
		}
	})

	t.Run("missing file is an operator-readable error", func(t *testing.T) {
		_, err := LoadUsers(filepath.Join(dir, "does-not-exist.txt"))
		if err == nil || !strings.Contains(err.Error(), "cannot read users file") {
			t.Fatalf("LoadUsers missing file err = %v", err)
		}
	})

	t.Run("file with no usernames is rejected", func(t *testing.T) {
		p := filepath.Join(dir, "empty.txt")
		if err := os.WriteFile(p, []byte("# only comments\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadUsers(p)
		if err == nil || !strings.Contains(err.Error(), "no usernames") {
			t.Fatalf("LoadUsers empty file err = %v", err)
		}
	})
}

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		dcIP       string
		wantErrSub string
	}{
		{"domain and dc-ip accepted", "lab.local", "10.0.0.1", ""},
		{"missing domain rejected", "", "10.0.0.1", "domain required"},
		{"blank domain rejected", "   ", "10.0.0.1", "domain required"},
		{"missing dc-ip rejected", "lab.local", "", "--dc-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTarget(tc.domain, tc.dcIP)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("ValidateTarget = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("ValidateTarget = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func TestValidateSprayParams(t *testing.T) {
	cases := []struct {
		name          string
		password      string
		delay         time.Duration
		stopOnSuccess int
		wantErrSub    string
	}{
		{"one password and zero stop accepted", "Password1!", 0, 0, ""},
		{"delay and stop-on-success accepted", "Password1!", 2 * time.Second, 3, ""},
		{"missing password rejected", "", 0, 0, "exactly one password"},
		{"negative delay rejected", "Password1!", -time.Second, 0, "--delay"},
		{"negative stop-on-success rejected", "Password1!", 0, -1, "--stop-on-success"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSprayParams(tc.password, tc.delay, tc.stopOnSuccess)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("ValidateSprayParams = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("ValidateSprayParams = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	cases := []struct {
		v    Verdict
		want string
	}{
		{VerdictValid, "VALID"},
		{VerdictValidNoPreauth, "VALID_NOPREAUTH"},
		{VerdictInvalid, "INVALID"},
		{VerdictLocked, "LOCKED"},
		{VerdictError, "ERROR"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", int(tc.v), got, tc.want)
		}
	}
}
