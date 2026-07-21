package smbclient

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
)

// TestPackRegValue covers the wire encodings for every supported REG_*
// type: UTF-16LE+NUL for strings, little-endian for numbers, raw bytes for
// REG_BINARY, NUL-separated + double-NUL for REG_MULTI_SZ.
func TestPackRegValue(t *testing.T) {
	tests := []struct {
		name    string
		valType uint32
		data    string
		want    []byte
		wantErr bool
	}{
		{name: "sz text", valType: winreg.REG_SZ, data: "hi",
			want: []byte{'h', 0, 'i', 0, 0, 0}},
		{name: "sz empty is just the NUL", valType: winreg.REG_SZ, data: "",
			want: []byte{0, 0}},
		{name: "expand sz keeps the variable literal", valType: winreg.REG_EXPAND_SZ, data: "%TEMP%\\x",
			want: []byte{'%', 0, 'T', 0, 'E', 0, 'M', 0, 'P', 0, '%', 0, '\\', 0, 'x', 0, 0, 0}},
		{name: "dword decimal", valType: winreg.REG_DWORD, data: "1234",
			want: []byte{0xd2, 0x04, 0x00, 0x00}},
		{name: "dword hex", valType: winreg.REG_DWORD, data: "0xdeadbeef",
			want: []byte{0xef, 0xbe, 0xad, 0xde}},
		{name: "dword leading zero stays decimal", valType: winreg.REG_DWORD, data: "010",
			want: []byte{0x0a, 0x00, 0x00, 0x00}}, // strconv base 0 would read octal 8
		{name: "dword max", valType: winreg.REG_DWORD, data: "4294967295",
			want: []byte{0xff, 0xff, 0xff, 0xff}},
		{name: "dword overflow", valType: winreg.REG_DWORD, data: "4294967296", wantErr: true},
		{name: "dword negative", valType: winreg.REG_DWORD, data: "-1", wantErr: true},
		{name: "dword garbage", valType: winreg.REG_DWORD, data: "notanumber", wantErr: true},
		{name: "dword empty", valType: winreg.REG_DWORD, data: "", wantErr: true},
		{name: "qword decimal", valType: winreg.REG_QWORD, data: "42",
			want: []byte{0x2a, 0, 0, 0, 0, 0, 0, 0}},
		{name: "qword hex", valType: winreg.REG_QWORD, data: "0x1122334455667788",
			want: []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}},
		{name: "qword too big for dword is fine here", valType: winreg.REG_QWORD, data: "4294967296",
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
		{name: "qword overflow", valType: winreg.REG_QWORD, data: "0x10000000000000000", wantErr: true},
		{name: "binary plain", valType: winreg.REG_BINARY, data: "deadbeef",
			want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "binary with spaces", valType: winreg.REG_BINARY, data: "de ad be ef",
			want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "binary empty", valType: winreg.REG_BINARY, data: "", want: []byte{}},
		{name: "binary odd length", valType: winreg.REG_BINARY, data: "abc", wantErr: true},
		{name: "binary not hex", valType: winreg.REG_BINARY, data: "zz", wantErr: true},
		{name: "multi sz two items", valType: winreg.REG_MULTI_SZ, data: "one|two",
			want: []byte{'o', 0, 'n', 0, 'e', 0, 0, 0, 't', 0, 'w', 0, 'o', 0, 0, 0, 0, 0}},
		{name: "multi sz single item", valType: winreg.REG_MULTI_SZ, data: "solo",
			want: []byte{'s', 0, 'o', 0, 'l', 0, 'o', 0, 0, 0, 0, 0}},
		{name: "multi sz keeps commas inside items", valType: winreg.REG_MULTI_SZ, data: "CN=a,DC=b|c",
			want: []byte{'C', 0, 'N', 0, '=', 0, 'a', 0, ',', 0, 'D', 0, 'C', 0, '=', 0, 'b', 0, 0, 0, 'c', 0, 0, 0, 0, 0}},
		{name: "multi sz empty is the empty list", valType: winreg.REG_MULTI_SZ, data: "",
			want: []byte{0, 0, 0, 0}},
		{name: "unsupported type", valType: winreg.REG_LINK, data: "x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packRegValue(tt.valType, tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("packRegValue(%d, %q) = %x, want error", tt.valType, tt.data, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("packRegValue(%d, %q): %v", tt.valType, tt.data, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("packRegValue(%d, %q) = %x, want %x", tt.valType, tt.data, got, tt.want)
			}
		})
	}
}

// TestRegTypeNames covers the name<->code mapping the shell uses for
// argument parsing and display.
func TestRegTypeNames(t *testing.T) {
	for name, want := range map[string]uint32{
		"REG_SZ": winreg.REG_SZ, "sz": winreg.REG_SZ, "SZ": winreg.REG_SZ,
		"REG_EXPAND_SZ": winreg.REG_EXPAND_SZ, "expand_sz": winreg.REG_EXPAND_SZ,
		"REG_BINARY": winreg.REG_BINARY, "binary": winreg.REG_BINARY,
		"REG_DWORD": winreg.REG_DWORD, "dword": winreg.REG_DWORD,
		"REG_QWORD": winreg.REG_QWORD, "qword": winreg.REG_QWORD,
		"REG_MULTI_SZ": winreg.REG_MULTI_SZ, "multi_sz": winreg.REG_MULTI_SZ,
	} {
		got, err := RegTypeFromName(name)
		if err != nil {
			t.Errorf("RegTypeFromName(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("RegTypeFromName(%q) = %d, want %d", name, got, want)
		}
		if back := RegTypeName(want); back != "REG_"+strings.ToUpper(strings.TrimPrefix(strings.ToUpper(name), "REG_")) {
			t.Errorf("RegTypeName(%d) = %q, does not round-trip %q", want, back, name)
		}
	}
	if _, err := RegTypeFromName("REG_LINK"); err == nil {
		t.Error("RegTypeFromName(REG_LINK) = nil error, want unsupported error")
	}
	if got := RegTypeName(999); got != "REG_999" {
		t.Errorf("RegTypeName(999) = %q, want REG_999", got)
	}
}

// TestPortFwdRuleFormat covers the on-registry representation: value name
// "listenaddr/listenport", data "connectaddr/connectport".
func TestPortFwdRuleFormat(t *testing.T) {
	rule := PortFwdRule{ListenAddr: "0.0.0.0", ListenPort: 14445, ConnectAddr: "127.0.0.1", ConnectPort: 445}
	name, data := formatPortFwdRule(rule)
	if name != "0.0.0.0/14445" || data != "127.0.0.1/445" {
		t.Fatalf("formatPortFwdRule = (%q, %q), want (0.0.0.0/14445, 127.0.0.1/445)", name, data)
	}
	back, err := parsePortFwdRule(name, data)
	if err != nil {
		t.Fatalf("parsePortFwdRule round-trip: %v", err)
	}
	if back != rule {
		t.Errorf("round-trip = %+v, want %+v", back, rule)
	}
	if s := rule.String(); s != "0.0.0.0:14445 -> 127.0.0.1:445" {
		t.Errorf("String() = %q", s)
	}
}

func TestParsePortFwdRuleBad(t *testing.T) {
	tests := []struct{ name, valName, data string }{
		{name: "name missing slash", valName: "0.0.0.0", data: "127.0.0.1/445"},
		{name: "name port not numeric", valName: "0.0.0.0/abc", data: "127.0.0.1/445"},
		{name: "name port zero", valName: "0.0.0.0/0", data: "127.0.0.1/445"},
		{name: "name port too big", valName: "0.0.0.0/65536", data: "127.0.0.1/445"},
		{name: "name empty addr", valName: "/14445", data: "127.0.0.1/445"},
		{name: "data missing slash", valName: "0.0.0.0/14445", data: "127.0.0.1"},
		{name: "data empty", valName: "0.0.0.0/14445", data: ""},
		{name: "data port trailing slash", valName: "0.0.0.0/14445", data: "127.0.0.1/"},
		{name: "data port zero", valName: "0.0.0.0/14445", data: "127.0.0.1/0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rule, err := parsePortFwdRule(tt.valName, tt.data); err == nil {
				t.Errorf("parsePortFwdRule(%q, %q) = %+v, want error", tt.valName, tt.data, rule)
			}
		})
	}
}

// TestParseListenConnect covers the user-facing "host:port" validation.
func TestParseListenConnect(t *testing.T) {
	rule, err := parseListenConnect("127.0.0.1:14445", "127.0.0.1:445")
	if err != nil {
		t.Fatalf("parseListenConnect: %v", err)
	}
	want := PortFwdRule{ListenAddr: "127.0.0.1", ListenPort: 14445, ConnectAddr: "127.0.0.1", ConnectPort: 445}
	if rule != want {
		t.Errorf("parseListenConnect = %+v, want %+v", rule, want)
	}

	for _, tc := range []struct{ name, listen, connect string }{
		{name: "listen missing port", listen: "127.0.0.1", connect: "127.0.0.1:445"},
		{name: "listen empty host", listen: ":14445", connect: "127.0.0.1:445"},
		{name: "listen bad port", listen: "127.0.0.1:http", connect: "127.0.0.1:445"},
		{name: "listen port zero", listen: "127.0.0.1:0", connect: "127.0.0.1:445"},
		{name: "connect missing port", listen: "127.0.0.1:14445", connect: "10.0.0.1"},
		{name: "connect port too big", listen: "127.0.0.1:14445", connect: "10.0.0.1:70000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseListenConnect(tc.listen, tc.connect); err == nil {
				t.Errorf("parseListenConnect(%q, %q) = nil error, want error", tc.listen, tc.connect)
			}
		})
	}
}

// TestUtf16String covers REG_SZ decode: NUL-terminated UTF-16LE, with the
// odd-byte guard for truncated blobs.
func TestUtf16String(t *testing.T) {
	if got := utf16String([]byte{'h', 0, 'i', 0, 0, 0}); got != "hi" {
		t.Errorf("utf16String terminated = %q, want hi", got)
	}
	if got := utf16String([]byte{'h', 0, 'i', 0}); got != "hi" { // no NUL present
		t.Errorf("utf16String unterminated = %q, want hi", got)
	}
	if got := utf16String([]byte{'h', 0, 'i'}); got != "h" { // odd trailing byte dropped
		t.Errorf("utf16String odd length = %q, want h", got)
	}
	if got := utf16String(nil); got != "" {
		t.Errorf("utf16String(nil) = %q, want empty", got)
	}
}

// TestMapRegWriteError checks the themed mappings stay in place.
func TestMapRegWriteError(t *testing.T) {
	for code, hint := range map[string]string{
		"0x00000005": "access denied",
		"0x00000002": "not found",
		"0x00000057": "invalid parameter",
		"0x000006f7": "not supported on this server",
	} {
		err := mapRegWriteError(errString("BaseRegSetValue(x) failed: " + code))
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("mapRegWriteError(%s) = %q, want hint %q", code, err, hint)
		}
	}
	plain := errString("some other failure")
	if got := mapRegWriteError(plain); got != plain {
		t.Errorf("mapRegWriteError passthrough = %v, want original", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
