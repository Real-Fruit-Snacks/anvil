package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

// readDfsnmString decodes one [in, string] unique wchar_t* from a built
// stub: referent ID, array counts, UTF-16LE chars, 4-byte padding. It
// enforces the [string] invariants the builder claims — Offset=0,
// MaxCount==ActualCount, NUL terminator counted and present.
func readDfsnmString(t *testing.T, blob []byte, off int) (referent uint32, s string, next int) {
	t.Helper()
	if off+16 > len(blob) {
		t.Fatalf("truncated string header at offset %d (blob %d bytes)", off, len(blob))
	}
	referent = binary.LittleEndian.Uint32(blob[off:])
	maxCount := binary.LittleEndian.Uint32(blob[off+4:])
	offset := binary.LittleEndian.Uint32(blob[off+8:])
	actual := binary.LittleEndian.Uint32(blob[off+12:])
	if offset != 0 || maxCount != actual {
		t.Fatalf("array counts max=%d offset=%d actual=%d, want offset=0, max==actual", maxCount, offset, actual)
	}
	off += 16
	if off+int(actual)*2 > len(blob) {
		t.Fatalf("truncated chars at offset %d: %d code units exceed blob", off, actual)
	}
	units := make([]uint16, actual)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(blob[off+i*2:])
	}
	off += int(actual) * 2
	for off%4 != 0 {
		off++
	}
	if len(units) == 0 || units[len(units)-1] != 0 {
		t.Fatalf("string not NUL-terminated on the wire: %v", units)
	}
	return referent, string(utf16.Decode(units[:len(units)-1])), off
}

// expectDfsnmStrings decodes want-count strings from blob, checking referent
// IDs (0x20000+n*4) and contents, then wants the ApiFlags=0 trailer exactly
// at the end of the blob.
func expectDfsnmStrings(t *testing.T, blob []byte, want ...string) {
	t.Helper()
	off := 0
	for i, w := range want {
		ref, got, next := readDfsnmString(t, blob, off)
		if wantRef := uint32(0x20000 + 4*i); ref != wantRef {
			t.Errorf("string %d referent = %#x, want %#x", i, ref, wantRef)
		}
		if got != w {
			t.Errorf("string %d = %q, want %q", i, got, w)
		}
		off = next
	}
	if off+4 != len(blob) {
		t.Fatalf("after %d strings: offset %d, want exactly the 4-byte ApiFlags trailer left of %d", len(want), off, len(blob))
	}
	if flags := binary.LittleEndian.Uint32(blob[off:]); flags != 0 {
		t.Errorf("ApiFlags = %#x, want 0 (reserved field)", flags)
	}
}

func TestBuildDfsAddStdRoot(t *testing.T) {
	t.Run("exact wire bytes for minimal strings", func(t *testing.T) {
		// "L"/"s"/"c": each is ref + 12-byte counts + two UTF-16 units (NUL
		// counted) = 20 bytes, no padding needed; ApiFlags trailer 4 bytes.
		want := []byte{
			// ServerName "L" — referent 0x20000, counts 2/0/2, 'L' + NUL
			0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x4c, 0x00, 0x00, 0x00,
			// RootShare "s" — referent 0x20004
			0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x73, 0x00, 0x00, 0x00,
			// Comment "c" — referent 0x20008
			0x08, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x63, 0x00, 0x00, 0x00,
			// ApiFlags, reserved
			0x00, 0x00, 0x00, 0x00,
		}
		if got := buildDfsAddStdRoot("L", "s", "c"); !bytes.Equal(got, want) {
			t.Errorf("buildDfsAddStdRoot(L,s,c) = %x,\nwant %x", got, want)
		}
	})

	cases := []struct {
		name                   string
		server, share, comment string
	}{
		{"listener as IPv4 with Coercer artifacts", "192.168.1.10", "share", "x"},
		{"listener as FQDN", "files.corp.local", "share", "x"},
		{"odd-length strings exercise padding", "10.0.0.1", "share", "abc"},
		{"empty comment still transmits its NUL", "10.0.0.5", "share", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectDfsnmStrings(t, buildDfsAddStdRoot(tc.server, tc.share, tc.comment),
				tc.server, tc.share, tc.comment)
		})
	}
}

func TestBuildDfsRemoveStdRoot(t *testing.T) {
	t.Run("exact wire bytes for minimal strings", func(t *testing.T) {
		want := []byte{
			// ServerName "L"
			0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x4c, 0x00, 0x00, 0x00,
			// RootShare "s"
			0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x73, 0x00, 0x00, 0x00,
			// ApiFlags, reserved
			0x00, 0x00, 0x00, 0x00,
		}
		if got := buildDfsRemoveStdRoot("L", "s"); !bytes.Equal(got, want) {
			t.Errorf("buildDfsRemoveStdRoot(L,s) = %x,\nwant %x", got, want)
		}
	})

	cases := []struct {
		name          string
		server, share string
	}{
		{"same target as the add", "192.168.1.10", "share"},
		{"odd-length share exercises padding", "files.corp.local", "dfs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Two strings only — a Remove stub must carry no Comment.
			expectDfsnmStrings(t, buildDfsRemoveStdRoot(tc.server, tc.share), tc.server, tc.share)
		})
	}
}

func TestParseDfsReturn(t *testing.T) {
	cases := []struct {
		name    string
		resp    []byte
		want    uint32
		wantErr string
	}{
		{"success", []byte{0, 0, 0, 0}, 0, ""},
		{"access denied status", []byte{0x05, 0x00, 0x00, 0x00}, 0x00000005, ""},
		{"status read from stub tail", []byte{0xaa, 0xbb, 0x90, 0x04, 0x00, 0x00}, 0x00000490, ""},
		{"short response", []byte{0x05, 0x00, 0x00}, 0, "short response"},
		{"empty response", nil, 0, "short response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDfsReturn(tc.resp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDfsReturn: %v", err)
			}
			if got != tc.want {
				t.Errorf("status = %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestMapDFSCoerceError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"access denied as NET_API_STATUS return", fmt.Errorf("NetrDfsAddStdRoot returned 0x00000005"), "access denied — DFSCoerce needs admin"},
		{"access denied as RPC fault", fmt.Errorf("NetrDfsAddStdRoot: RPC Fault: status=0x00000005"), "access denied — DFSCoerce needs admin"},
		{"missing netdfs pipe (path error)", &os.PathError{Op: "open", Path: "netdfs", Err: os.ErrNotExist}, "not supported on this server"},
		{"missing netdfs pipe (wrapped)", fmt.Errorf("open netdfs pipe: %w", os.ErrNotExist), "not supported on this server"},
		{"interface bind rejected", errors.New("bind DFSNM: bind rejected: syntaxes_not_supported"), "not supported on this server"},
		{"opnum range fault (Samba-style)", errors.New("RPC Fault: status=0x1c010002"), "not supported on this server"},
		{"op not registered", errors.New("RPC Fault: status=0x000006f7"), "not supported on this server"},
		{"namespace missing on cleanup", errors.New("NetrDfsRemoveStdRoot returned 0x00000490"), "DFS root not found"},
		{"unmapped status keeps its context", errors.New("NetrDfsAddStdRoot returned 0x000000b7"), "0x000000b7"},
		{"unmapped error passes through verbatim", errors.New("failed to read Response header: EOF"), "EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapDFSCoerceError(tc.err)
			if !strings.Contains(got.Error(), tc.want) {
				t.Errorf("mapDFSCoerceError(%v) = %q, want substring %q", tc.err, got, tc.want)
			}
		})
	}
}

// The empty-listener guard fires before any pipe is opened, so it is
// exercisable on a bare Session with no SMB client behind it.
func TestCoerceDFSCoerceEmptyListener(t *testing.T) {
	err := (&Session{}).CoerceDFSCoerce("")
	if err == nil || !strings.Contains(err.Error(), "no listener address") {
		t.Fatalf("err = %v, want the no-listener guard", err)
	}
}
