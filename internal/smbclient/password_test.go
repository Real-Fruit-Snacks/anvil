package smbclient

import (
	"errors"
	"strings"
	"testing"
)

// TestEnc verifies the unicodePwd encoding: the password wrapped in double
// quotes, UTF-16LE (MS-ADTS 3.1.1.3.1.5.1).
func TestEnc(t *testing.T) {
	got := enc("ab")
	want := "\x22\x00a\x00b\x00\x22\x00" // '"', 'a', 'b', '"' — all UTF-16LE
	if got != want {
		t.Errorf("enc(%q) = %q, want %q", "ab", got, want)
	}

	if got := enc(""); got != "\x22\x00\x22\x00" {
		t.Errorf("enc(%q) = %q, want quoted-empty", "", got)
	}
}

func TestMapPasswordError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // substring expected in the mapped message; "" = passthrough
	}{
		{
			name: "policy violation by Win32 code",
			err:  errors.New(`LDAP Result Code 53 "Unwilling To Perform": 0000052D: AtrErr: DSID-03190F80`),
			want: "password policy",
		},
		{
			name: "policy violation by result-code name",
			err:  errors.New(`LDAP Result Code 19 "Constraint Violation": password too short`),
			want: "password policy",
		},
		{
			name: "insufficient rights by name",
			err:  errors.New(`LDAP Result Code 50 "Insufficient Access Rights": 00000005: SecErr: DSID-03152E13`),
			want: "insufficient rights",
		},
		{
			name: "insufficient rights by Win32 code",
			err:  errors.New(`LDAP Result Code 53 "Unwilling To Perform": 00000005: SecErr`),
			want: "insufficient rights",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapPasswordError(tt.err)
			if !strings.Contains(got.Error(), tt.want) {
				t.Errorf("mapPasswordError(%v) = %q, want substring %q", tt.err, got, tt.want)
			}
			// The original error text is preserved for context.
			if !strings.Contains(got.Error(), tt.err.Error()) {
				t.Errorf("mapPasswordError(%v) = %q, want original text preserved", tt.err, got)
			}
		})
	}

	t.Run("passthrough", func(t *testing.T) {
		err := errors.New("connection refused")
		if got := mapPasswordError(err); got != err {
			t.Errorf("mapPasswordError(%v) = %v, want passthrough", err, got)
		}
	})
}
