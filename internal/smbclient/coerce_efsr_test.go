package smbclient

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

// mustHex decodes a golden hex string, failing the test on a typo.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	return b
}

func TestBuildEfsOpenFileRawRequest(t *testing.T) {
	// Golden stubs reproduced from impacket's marshaling of topotam's
	// EfsRpcOpenFileRaw NDRCALL (('fileName', WSTR), ('Flag', ULONG)) —
	// MaxCount/Offset/ActualCount in WCHARs including the NUL, UTF-16LE
	// data, DWORD alignment gap, Flags=0. impacket fills the gap with
	// 0xbf bytes; C706 §14.2.2 leaves gap octets unspecified, so the
	// goldens here carry zeros instead — the only intentional divergence.
	cases := []struct {
		name string
		path string
		want string // hex
	}{
		{
			name: "UNC path, odd WCHAR count pads before Flags",
			path: `\\L\share\file`, // 14 chars + NUL = 15 WCHARs
			want: "0f000000" + "00000000" + "0f000000" +
				"5c005c004c005c00730068006100720065005c00660069006c0065000000" +
				"0000" + // alignment gap
				"00000000", // Flags
		},
		{
			name: "UNC path, even WCHAR count needs no padding",
			path: `\\H\s\f`, // 7 chars + NUL = 8 WCHARs
			want: "08000000" + "00000000" + "08000000" +
				"5c005c0048005c0073005c0066000000" +
				"00000000",
		},
		{
			name: "single character",
			path: "X",
			want: "02000000" + "00000000" + "02000000" +
				"58000000" +
				"00000000",
		},
		{
			name: "empty path still transmits the terminator",
			path: "",
			want: "01000000" + "00000000" + "01000000" +
				"0000" + // lone NUL
				"0000" + // alignment gap
				"00000000",
		},
		{
			name: "non-ASCII BMP rune is one code unit",
			path: `\\H\share\fïle`, // ï = U+00EF, single UTF-16 unit
			want: "0f000000" + "00000000" + "0f000000" +
				"5c005c0048005c00730068006100720065005c006600ef006c0065000000" +
				"0000" +
				"00000000",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := buildEfsOpenFileRawRequest(tt.path)
			want := mustHex(t, tt.want)
			if !bytes.Equal(got, want) {
				t.Errorf("stub mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}

	t.Run("astral rune counts as a surrogate pair", func(t *testing.T) {
		stub := buildEfsOpenFileRawRequest("😀") // U+1F600 → 2 UTF-16 units
		if got := binary.LittleEndian.Uint32(stub[0:4]); got != 3 {
			t.Errorf("MaxCount = %d, want 3 (2 units + NUL)", got)
		}
		if got := binary.LittleEndian.Uint32(stub[8:12]); got != 3 {
			t.Errorf("ActualCount = %d, want 3", got)
		}
		if len(stub)%4 != 0 {
			t.Errorf("stub length %d not DWORD-aligned", len(stub))
		}
	})

	t.Run("Offset is always zero and counts match", func(t *testing.T) {
		path := `\\192.168.0.10\share\file`
		stub := buildEfsOpenFileRawRequest(path)
		n := uint32(len(utf16.Encode([]rune(path))) + 1)
		if got := binary.LittleEndian.Uint32(stub[0:4]); got != n {
			t.Errorf("MaxCount = %d, want %d", got, n)
		}
		if got := binary.LittleEndian.Uint32(stub[4:8]); got != 0 {
			t.Errorf("Offset = %d, want 0", got)
		}
		if got := binary.LittleEndian.Uint32(stub[8:12]); got != n {
			t.Errorf("ActualCount = %d, want %d", got, n)
		}
		if got := binary.LittleEndian.Uint32(stub[len(stub)-4:]); got != 0 {
			t.Errorf("Flags = %d, want 0", got)
		}
	})
}

// efsResponse builds a synthetic EfsRpcOpenFileRaw response stub: 20 bytes
// of context handle (content ignored by the parser) + the Win32 code.
func efsResponse(code uint32) []byte {
	resp := make([]byte, 24)
	for i := range resp[:20] {
		resp[i] = 0x41
	}
	binary.LittleEndian.PutUint32(resp[20:24], code)
	return resp
}

func TestPetitPotamResult(t *testing.T) {
	cases := []struct {
		name string
		resp []byte
		want string // "" means nil error
	}{
		{name: "ERROR_SUCCESS means the file opened", resp: efsResponse(0), want: ""},
		{name: "ERROR_FILE_NOT_FOUND — listener answered, file absent", resp: efsResponse(0x00000002), want: ""},
		{name: "ERROR_PATH_NOT_FOUND — same class", resp: efsResponse(0x00000003), want: ""},
		{name: "ERROR_BAD_NETPATH — topotam's canonical attack-worked", resp: efsResponse(0x00000035), want: ""},
		{name: "ERROR_UNEXP_NET_ERR — outbound connect failed", resp: efsResponse(0x0000003B), want: ""},
		{name: "ERROR_NETNAME_DELETED — tree-connect dropped", resp: efsResponse(0x00000040), want: ""},
		{name: "ERROR_BAD_NETWORK_NAME — share absent on listener", resp: efsResponse(0x00000043), want: ""},
		{name: "ERROR_INVALID_NAME — path rejected at the redirector", resp: efsResponse(0x0000007B), want: ""},
		{name: "ERROR_LOGON_FAILURE — listener refused the machine account", resp: efsResponse(0x0000052E), want: ""},
		{name: "access denied is themed as blocked", resp: efsResponse(0x00000005), want: "access denied — PetitPotam blocked"},
		{name: "unknown code keeps the number for the operator", resp: efsResponse(87), want: "EfsRpcOpenFileRaw failed on the server (error 87 / 0x00000057)"},
		{name: "short response", resp: make([]byte, 23), want: "short EfsRpcOpenFileRaw response (23 bytes)"},
		{name: "empty response", resp: nil, want: "short EfsRpcOpenFileRaw response (0 bytes)"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := petitPotamResult(tt.resp)
			if tt.want == "" {
				if err != nil {
					t.Errorf("petitPotamResult = %v, want nil (coercion fired)", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("petitPotamResult = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestMapPetitPotamError(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		want        string // "" means pass-through (identity)
		unsupported bool
	}{
		{
			name:        "bind_nak means the pipe won't serve EFSR",
			in:          "bind EFSR: bind rejected: syntaxes_not_supported",
			want:        "MS-EFSR not supported on this server (interface rejected the bind)",
			unsupported: true,
		},
		{
			name: "rpc_s_access_denied fault is themed blocked",
			in:   "EfsRpcOpenFileRaw: RPC Fault: status=0x00000005",
			want: "access denied — PetitPotam blocked",
		},
		{
			name:        "opnum unimplemented (Samba-style nca_s_op_rng_error)",
			in:          "EfsRpcOpenFileRaw: RPC Fault: status=0x1c010002",
			want:        "MS-EFSR not supported on this server (EFSR opnums unimplemented)",
			unsupported: true,
		},
		{
			name:        "op not registered (EPT_S_NOT_REGISTERED)",
			in:          "EfsRpcOpenFileRaw: RPC Fault: status=0x000006f7",
			want:        "MS-EFSR not supported on this server (EFSR opnums unimplemented)",
			unsupported: true,
		},
		{
			name: "transport failure passes through untouched",
			in:   "EfsRpcOpenFileRaw: failed to write Request: broken pipe",
			want: "",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			in := errors.New(tt.in)
			err := mapPetitPotamError(in)
			if tt.want == "" {
				if err != in {
					t.Errorf("mapPetitPotamError = %v, want pass-through", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("mapPetitPotamError = %v, want %q", err, tt.want)
			}
			if got := errors.Is(err, errEFSRUnsupported); got != tt.unsupported {
				t.Errorf("errors.Is(errEFSRUnsupported) = %v, want %v", got, tt.unsupported)
			}
		})
	}
}

func TestCoercePetitPotamRejectsEmptyListener(t *testing.T) {
	// Validation happens before any pipe is opened, so the nil-client
	// Session never touches the network.
	for _, listener := range []string{"", `\\`} {
		err := (&Session{}).CoercePetitPotam(listener)
		if err == nil || !strings.Contains(err.Error(), "no listener address given") {
			t.Errorf("CoercePetitPotam(%q) = %v, want no-listener error", listener, err)
		}
	}
}
