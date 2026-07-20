package scan

import (
	"errors"
	"testing"
)

func TestChannelBindingStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil error", nil, "Never"},
		{"bad bindings", errors.New("data 80090346: SEC_E_BAD_BINDINGS"), "Always"},
		{"52e", errors.New("LDAP Result Code 49: data 52e"), "Never"},
		{"invalid creds text", errors.New("Invalid Credentials"), "Never"},
		{"strong auth", errors.New("Strong Auth Required"), "NTLM disabled on LDAPS"},
		{"strongerAuthRequired", errors.New("strongerAuthRequired"), "NTLM disabled on LDAPS"},
		// Unrecognized errors yield "" (unknown) — the UI suppresses the
		// field via omitempty rather than claiming a posture.
		{"other error", errors.New("connection reset"), ""},
	}
	for _, c := range cases {
		if got := channelBindingStatus(c.err); got != c.want {
			t.Errorf("%s: channelBindingStatus = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsStrongerAuthError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"LDAP Result Code 8 (strongerAuthRequired)", true},
		{"Strong Auth Required", true},
		{"server says STRONGER binds only", true},
		{"Invalid Credentials", false},
		{"connection refused", false},
	}
	for _, c := range cases {
		if got := isStrongerAuthError(errors.New(c.msg)); got != c.want {
			t.Errorf("isStrongerAuthError(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}
