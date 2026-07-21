package scan

import (
	"errors"
	"testing"
)

// The probe body is network-bound (dial + pkg/smb session), so the hermetic
// tests cover the pure error mapping: every substring matched against
// gopacket's flattened erref/InvalidResponseError text, plus fallback
// passthrough for both call sites.
func TestDescribeNullSessionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		fallback string
		want     string
	}{
		{
			name: "windows refuses the session outright (STATUS_LOGON_FAILURE)",
			err: errors.New("SMB login failed: response error: The attempted logon is invalid. " +
				"This is either due to a bad username or authentication information."),
			fallback: "null session refused",
			want:     "null session refused",
		},
		{
			name: "samba accepts anonymous setup then denies the enum (STATUS_ACCESS_DENIED erref text)",
			err: errors.New("response error: {Access Denied} A process has requested access to an " +
				"object but has not been granted those access rights."),
			fallback: "share enumeration failed",
			want:     "access denied",
		},
		{
			name:     "samba renders Win32 ERROR_ACCESS_DENIED as a bare code",
			err:      errors.New("rpc fault: status code 0x00000005"),
			fallback: "share enumeration failed",
			want:     "access denied",
		},
		{
			name: "server flags the session anonymous and the client signing check aborts",
			err: errors.New("SMB login failed: invalid response error: anonymous account " +
				"doesn't support signing"),
			fallback: "null session refused",
			want:     "null session accepted but blocked by client signing requirement",
		},
		{
			name: "server flags the session guest and the client signing check aborts",
			err: errors.New("SMB login failed: invalid response error: guest account " +
				"doesn't support signing"),
			fallback: "null session refused",
			want:     "null session accepted but blocked by client signing requirement",
		},
		{
			name:     "unmapped session-setup failure falls back to the connect default",
			err:      errors.New("SMB login failed: response error: some unexpected status"),
			fallback: "null session refused",
			want:     "null session refused",
		},
		{
			name:     "unmapped share-enum failure falls back to the enum default",
			err:      errors.New("session not established"),
			fallback: "share enumeration failed",
			want:     "share enumeration failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeNullSessionError(tt.err, tt.fallback); got != tt.want {
				t.Errorf("describeNullSessionError(%v, %q) = %q, want %q",
					tt.err, tt.fallback, got, tt.want)
			}
		})
	}
}
