package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
)

// decodeUniqueString independently decodes one NDR unique string pointer at
// off (referent ID + MaxCount/Offset/ActualCount + UTF-16LE data + padding)
// and returns the string with its NUL terminator stripped plus the offset of
// the next field. The tests assert the builders' layout by decoding, so a
// wrong field order or count breaks the decode itself, not just a golden.
func decodeUniqueString(t *testing.T, b []byte, off int) (string, int) {
	t.Helper()
	if got := binary.LittleEndian.Uint32(b[off:]); got == 0 {
		t.Fatalf("referent ID at offset %d is NULL, want non-zero", off)
	}
	maxCount := binary.LittleEndian.Uint32(b[off+4:])
	offset := binary.LittleEndian.Uint32(b[off+8:])
	actualCount := binary.LittleEndian.Uint32(b[off+12:])
	if offset != 0 {
		t.Errorf("string Offset = %d, want 0", offset)
	}
	if actualCount != maxCount {
		t.Errorf("ActualCount = %d, want equal to MaxCount %d", actualCount, maxCount)
	}
	dataOff := off + 16
	dataEnd := dataOff + int(actualCount)*2
	if dataEnd > len(b) {
		t.Fatalf("string data overruns buffer: end %d > len %d", dataEnd, len(b))
	}
	chars := make([]uint16, actualCount)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(b[dataOff+i*2:])
	}
	if chars[len(chars)-1] != 0 {
		t.Errorf("string not NUL-terminated (last char %#x)", chars[len(chars)-1])
	}
	next := dataEnd
	if rem := next % 4; rem != 0 {
		for i := next; i < next+4-rem; i++ {
			if b[i] != 0 {
				t.Errorf("non-zero padding byte at offset %d", i)
			}
		}
		next += 4 - rem
	}
	return string(utf16.Decode(chars[:len(chars)-1])), next
}

func TestPrinterBugInterfaceAndOpnums(t *testing.T) {
	// MS-RPRN Appendix A (full IDL): interface winspool,
	// uuid(12345678-1234-ABCD-EF00-0123456789AB) version 1.0.
	if got := dcerpc.FormatUUID(rprnUUID); got != "12345678-1234-abcd-ef00-0123456789ab" {
		t.Errorf("rprnUUID = %s, want 12345678-1234-abcd-ef00-0123456789ab", got)
	}
	// MS-RPRN 3.1.4.2.2 — impacket rprn.py agrees.
	if opRPRNOpenPrinter != 1 {
		t.Errorf("opRPRNOpenPrinter = %d, want 1", opRPRNOpenPrinter)
	}
	// MS-RPRN 3.1.4.10.4 — the Ex form is 65; 62 is the legacy non-Ex call
	// (3.1.4.10.1) and must NOT be used.
	if opRPRNRemoteFindFirstPrinterChangeNotifEx != 65 {
		t.Errorf("opRPRNRemoteFindFirstPrinterChangeNotifEx = %d, want 65", opRPRNRemoteFindFirstPrinterChangeNotifEx)
	}
}

func TestPrinterBugCallbackPath(t *testing.T) {
	tests := []struct {
		name     string
		listener string
		want     string
	}{
		{"bare IPv4 listener gains UNC and share path", "192.168.1.10", `\\192.168.1.10\test`},
		{"bare hostname", "listener", `\\listener\test`},
		{"leading UNC prefix stripped, not doubled", `\\192.168.1.10`, `\\192.168.1.10\test`},
		{"IPv6 address kept verbatim", "fd00::1", `\\fd00::1\test`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printerBugCallbackPath(tt.listener); got != tt.want {
				t.Errorf("printerBugCallbackPath(%q) = %q, want %q", tt.listener, got, tt.want)
			}
		})
	}
}

func TestBuildRpcOpenPrinterRequest(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
	}{
		// "DC01" makes the counted string 7 UTF-16 units (odd) — the char
		// data ends on a 2-byte boundary and exercises the 4-byte padding.
		{"odd unit count exercises padding", "DC01"},
		// "DC012" makes it 8 units (even) — data already 4-aligned, no pad.
		{"even unit count needs no padding", "DC012"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := buildRpcOpenPrinterRequest(tt.serverName)

			name, next := decodeUniqueString(t, b, 0)
			if want := `\\` + tt.serverName; name != want {
				t.Errorf("pPrinterName = %q, want %q", name, want)
			}

			// After the string: pDatatype NULL, DEVMODE_CONTAINER all zero,
			// then SERVER_READ — 16 bytes total, nothing else.
			if len(b) != next+16 {
				t.Fatalf("request length = %d, want %d (string end %d + 16)", len(b), next+16, next)
			}
			if got := binary.LittleEndian.Uint32(b[next:]); got != 0 {
				t.Errorf("pDatatype = 0x%08x, want NULL", got)
			}
			if got := binary.LittleEndian.Uint32(b[next+4:]); got != 0 {
				t.Errorf("DEVMODE_CONTAINER.cbBuf = %d, want 0", got)
			}
			if got := binary.LittleEndian.Uint32(b[next+8:]); got != 0 {
				t.Errorf("DEVMODE_CONTAINER.pDevMode = 0x%08x, want NULL", got)
			}
			if got := binary.LittleEndian.Uint32(b[next+12:]); got != serverRead {
				t.Errorf("AccessRequired = 0x%08x, want SERVER_READ 0x%08x", got, serverRead)
			}
		})
	}
}

func TestBuildPrinterChangeNotifExRequest(t *testing.T) {
	tests := []struct {
		name     string
		callback string
	}{
		// Same odd/even unit-count split as the open request.
		{"odd unit count exercises padding", `\\192.168.1.10\test`},
		{"even unit count needs no padding", `\\listener\test`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := bytes.Repeat([]byte{0xAB}, 20)
			b := buildPrinterChangeNotifExRequest(handle, tt.callback)

			// hPrinter: the 20-byte PRINTER_HANDLE verbatim, inline.
			if !bytes.Equal(b[:20], handle) {
				t.Errorf("hPrinter = %x, want the handle verbatim %x", b[:20], handle)
			}
			if got := binary.LittleEndian.Uint32(b[20:]); got != printerChangeAddJob {
				t.Errorf("fdwFlags = 0x%08x, want PRINTER_CHANGE_ADD_JOB 0x%08x", got, printerChangeAddJob)
			}
			if got := binary.LittleEndian.Uint32(b[24:]); got != 0 {
				t.Errorf("fdwOptions = 0x%08x, want 0", got)
			}

			machine, next := decodeUniqueString(t, b, 28)
			if machine != tt.callback {
				t.Errorf("pszLocalMachine = %q, want %q", machine, tt.callback)
			}

			// After the string: dwPrinterLocal 0 and pOptions NULL — 8 bytes.
			if len(b) != next+8 {
				t.Fatalf("request length = %d, want %d (string end %d + 8)", len(b), next+8, next)
			}
			if got := binary.LittleEndian.Uint32(b[next:]); got != 0 {
				t.Errorf("dwPrinterLocal = 0x%08x, want 0", got)
			}
			if got := binary.LittleEndian.Uint32(b[next+4:]); got != 0 {
				t.Errorf("pOptions = 0x%08x, want NULL", got)
			}
		})
	}
}

func TestParseOpenPrinterResponse(t *testing.T) {
	handle := bytes.Repeat([]byte{0x11}, 20)

	t.Run("success returns the 20-byte printer handle", func(t *testing.T) {
		resp := append(append([]byte{}, handle...), 0, 0, 0, 0) // ERROR_SUCCESS
		got, err := parseOpenPrinterResponse(resp)
		if err != nil {
			t.Fatalf("parseOpenPrinterResponse: %v", err)
		}
		if !bytes.Equal(got, handle) {
			t.Errorf("handle = %x, want %x", got, handle)
		}
	})

	t.Run("error code surfaces as hex for the mapper", func(t *testing.T) {
		resp := append(append([]byte{}, handle...), 0x05, 0, 0, 0) // ERROR_ACCESS_DENIED
		if _, err := parseOpenPrinterResponse(resp); err == nil || err.Error() != "RpcOpenPrinter failed: 0x00000005" {
			t.Errorf("err = %v, want \"RpcOpenPrinter failed: 0x00000005\"", err)
		}
	})

	t.Run("short response rejected", func(t *testing.T) {
		if _, err := parseOpenPrinterResponse(make([]byte, 10)); err == nil {
			t.Error("short response: err = nil, want error")
		}
	})
}

func TestNotifyPrinterBugError(t *testing.T) {
	tests := []struct {
		name string
		code uint32
		want string // "" means nil error
	}{
		{"ERROR_SUCCESS — trigger registered", 0x00000000, ""},
		// The spooler tried the reverse channel and failed — but that attempt
		// already carried the machine-account auth, so this is a success for
		// the coercion (krbrelayx printerbug.py: "attack worked").
		{"RPC_S_SERVER_UNAVAILABLE — callback attempt still delivered the auth", 0x000006BA, ""},
		{"ERROR_ACCESS_DENIED — hardened policy blocks the trigger", 0x00000005, "access denied — PrinterBug blocked"},
		{"other Win32 code passes through as hex", 0x00000057, "RpcRemoteFindFirstPrinterChangeNotificationEx failed: 0x00000057"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := notifyPrinterBugError(tt.code)
			if tt.want == "" {
				if err != nil {
					t.Errorf("notifyPrinterBugError(0x%08x) = %v, want nil", tt.code, err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("notifyPrinterBugError(0x%08x) = %v, want %q", tt.code, err, tt.want)
			}
		})
	}
}

func TestMapPrinterBugError(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"pipe absent — spooler stopped or disabled", "open spoolss pipe: The object name is not found.", "print spooler not reachable/disabled"},
		{"pipe exists but no listener — spooler down", "open spoolss pipe: An instance of a named pipe cannot be found in the listening state.", "print spooler not reachable/disabled"},
		{"spooler dropped the pipe mid-call", "RpcOpenPrinter: The specified named pipe is in the disconnected state.", "print spooler not reachable/disabled"},
		{"access denied from RpcOpenPrinter", "RpcOpenPrinter failed: 0x00000005", "access denied — PrinterBug blocked"},
		{"opnum unimplemented on this server", "RpcRemoteFindFirstPrinterChangeNotificationEx: RPC Fault: status=0x1c010002", "not supported on this server (unknown RPC opnum)"},
		{"unrelated failure passes through", "dial tcp: connection refused", "dial tcp: connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapPrinterBugError(errors.New(tt.in)).Error(); got != tt.want {
				t.Errorf("mapPrinterBugError(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
