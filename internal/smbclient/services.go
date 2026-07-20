package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
)

// ServiceInfo is one Windows service from the Service Control Manager.
type ServiceInfo struct {
	Name        string
	DisplayName string
	State       string // svcctl.GetServiceState rendering (RUNNING, STOPPED, ...)
}

// SVCCTL opnums used here (pkg/dcerpc/svcctl does not export them).
const (
	opROpenSCManagerW             = 15
	opREnumServicesStatusW        = 14
	opRCloseServiceHandle         = 0
	scEnumBufSize                 = 256 * 1024
	svcTypeAllWin32               = 0x30 // own + share process
	svcStateAll                   = 0x03
	errorMoreData          uint32 = 0x000000ea
)

// EnumServices lists Windows services via SVCCTL over the existing
// session's IPC$. pkg/dcerpc/svcctl's EnumServicesStatus marshals the
// request without the [out] buffer and misparses the response trailer
// (real Windows answers 0x00000002 while Samba tolerates it), so the enum
// is implemented here directly: correct [out]-array request, referent-aware
// response parsing. Per-service config (BinaryPath/StartName) is not
// fetched — an open/query/close round trip per service for little recon
// value at this level.
func (s *Session) EnumServices() ([]ServiceInfo, error) {
	pipe, err := s.client.OpenPipe("svcctl")
	if err != nil {
		return nil, fmt.Errorf("open svcctl pipe: %v", err)
	}
	defer pipe.Close()

	// Plain bind + plain calls: SCMR over an authenticated SMB pipe needs no
	// RPC-level auth, and CallAuthAuto faults with RPC_S_CANNOT_SUPPORT.
	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return nil, fmt.Errorf("bind svcctl: %v", err)
	}

	handle, err := openSCManager(rpc)
	if err != nil {
		return nil, err
	}
	defer func() {
		buf := new(bytes.Buffer)
		buf.Write(handle)
		_, _ = rpc.Call(opRCloseServiceHandle, buf.Bytes())
	}()

	entries, err := enumServicesStatus(rpc, handle)
	if err != nil {
		return nil, err
	}

	out := make([]ServiceInfo, 0, len(entries))
	for _, e := range entries {
		// The server can return a trailing entry with null name/display
		// pointers (observed on Server 2022) — no recon value; skip it.
		if e.name == "" && e.displayName == "" {
			continue
		}
		out = append(out, ServiceInfo{
			Name:        e.name,
			DisplayName: e.displayName,
			State:       svcctl.GetServiceState(e.state),
		})
	}
	return out, nil
}

// openSCManager opens the SCM database (ROpenSCManagerW, opnum 15) and
// returns the 20-byte RPC handle.
func openSCManager(rpc *dcerpc.Client) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // lpMachineName NULL
	binary.Write(buf, binary.LittleEndian, uint32(0)) // lpDatabaseName NULL
	binary.Write(buf, binary.LittleEndian, uint32(svcctl.SC_MANAGER_ALL_ACCESS))

	resp, err := rpc.Call(opROpenSCManagerW, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenSCManager response too short")
	}
	if retVal := binary.LittleEndian.Uint32(resp[20:24]); retVal != 0 {
		return nil, fmt.Errorf("OpenSCManager failed: 0x%08x", retVal)
	}
	return resp[:20], nil
}

type svcEntry struct {
	name, displayName string
	state             uint32
}

// enumServicesStatus calls REnumServicesStatusW (opnum 14) with the [out]
// buffer marshaled as a conformant array pointer, then parses the response
// (referent + conformant-varying array + out-params + ReturnValue).
// Retries once with a larger buffer on ERROR_MORE_DATA.
func enumServicesStatus(rpc *dcerpc.Client, handle []byte) ([]svcEntry, error) {
	bufSize := uint32(scEnumBufSize)
	for attempt := 0; attempt < 2; attempt++ {
		buf := new(bytes.Buffer)
		buf.Write(handle)
		binary.Write(buf, binary.LittleEndian, uint32(svcTypeAllWin32))
		binary.Write(buf, binary.LittleEndian, uint32(svcStateAll))
		// lpServiceBuf: referent + conformant array (maxCount, offset, actualCount=0)
		binary.Write(buf, binary.LittleEndian, uint32(0x20000))
		binary.Write(buf, binary.LittleEndian, bufSize)
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, bufSize)         // cbBufSize
		binary.Write(buf, binary.LittleEndian, uint32(0x20001)) // pcbBytesNeeded
		binary.Write(buf, binary.LittleEndian, uint32(0x20002)) // lpServicesReturned
		binary.Write(buf, binary.LittleEndian, uint32(0x20003)) // lpResumeHandle
		binary.Write(buf, binary.LittleEndian, uint32(0))       // resume value

		resp, err := rpc.Call(opREnumServicesStatusW, buf.Bytes())
		if err != nil {
			return nil, err
		}
		entries, moreData, err := parseEnumResponse(resp)
		if err != nil {
			return nil, err
		}
		if !moreData {
			return entries, nil
		}
		bufSize *= 2
	}
	return nil, fmt.Errorf("EnumServicesStatusW: buffer still too small after retry")
}

// parseEnumResponse parses the REnumServicesStatusW response. The server
// hand-packs lpServiceBuf, and the layout is implementation-defined — two
// shapes exist in the wild:
//
//	Windows: [referent(4)] then 36-byte records
//	  [nameOff(4)][displayOff(4)][SERVICE_STATUS(28)] — the documented
//	  ENUM_SERVICE_STATUSW field order, with offsets standing in for the
//	  pointers. There is NO maxCount/actualCount header (what looks like
//	  one is the first record's two offsets). The buffer may end with a
//	  trailing record whose name/display offsets are null.
//	Samba:   [referent(4)][maxCount(4)][actualCount(4)] then 36-byte
//	  records [SERVICE_STATUS(28)][nameOff(4)][displayOff(4)].
//
// In both shapes string offsets are relative to resp+4, and the trailer
// carries lpServicesReturned at [len-16] and ReturnValue at [len-4].
// The layout is sniffed from the first record (windowsLayout).
func parseEnumResponse(resp []byte) ([]svcEntry, bool, error) {
	if len(resp) < 32 {
		return nil, false, fmt.Errorf("EnumServicesStatusW response too short (len=%d)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal == errorMoreData {
		return nil, true, nil
	}
	if retVal != 0 {
		return nil, false, fmt.Errorf("EnumServicesStatusW failed: 0x%08x", retVal)
	}
	servicesReturned := binary.LittleEndian.Uint32(resp[len(resp)-16:])
	strings := resp[4:]

	if windowsLayout(resp, strings) {
		return parseWindowsRecords(resp, strings, servicesReturned)
	}
	return parseSambaRecords(resp, strings, servicesReturned)
}

// windowsLayout reports whether resp's first record starts with two string
// offsets (Windows shape): the first dword then resolves to a printable
// UTF-16 service name in the string pool. On the Samba shape that dword is
// maxCount, which points into record bytes — never printable text.
func windowsLayout(resp, strings []byte) bool {
	nameOff := int(binary.LittleEndian.Uint32(resp[4:8]))
	if nameOff <= 0 || nameOff >= len(strings) {
		return false
	}
	name := utf16At(strings, nameOff)
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	return name != ""
}

// parseWindowsRecords walks the Windows shape: 36-byte records
// [nameOff][displayOff][SERVICE_STATUS] starting at resp+4. Stops at the
// trailing null-name sentinel or once servicesReturned names are collected.
func parseWindowsRecords(resp, strings []byte, servicesReturned uint32) ([]svcEntry, bool, error) {
	entries := make([]svcEntry, 0, servicesReturned)
	for i := 0; ; i++ {
		off := 4 + i*36
		if off+36 > len(resp)-16 { // leave the out-params trailer
			break
		}
		nameOff := binary.LittleEndian.Uint32(resp[off : off+4])
		dispOff := binary.LittleEndian.Uint32(resp[off+4 : off+8])
		if nameOff == 0 && dispOff == 0 {
			break // trailing null-name sentinel (Server 2022)
		}
		entries = append(entries, svcEntry{
			name:        utf16At(strings, int(nameOff)),
			displayName: utf16At(strings, int(dispOff)),
			state:       binary.LittleEndian.Uint32(resp[off+12 : off+16]),
		})
		if uint32(len(entries)) >= servicesReturned {
			break
		}
	}
	return entries, false, nil
}

// parseSambaRecords walks the Samba shape: a maxCount/actualCount header,
// then 36-byte records [SERVICE_STATUS][nameOff][displayOff].
func parseSambaRecords(resp, strings []byte, servicesReturned uint32) ([]svcEntry, bool, error) {
	actualCount := binary.LittleEndian.Uint32(resp[8:12])
	arrayEnd := 12 + int(actualCount)
	if arrayEnd+16 > len(resp) {
		return nil, false, fmt.Errorf("EnumServicesStatusW truncated (len=%d, arrayEnd=%d)", len(resp), arrayEnd)
	}
	data := resp[12:arrayEnd]

	entries := make([]svcEntry, 0, servicesReturned)
	for i := uint32(0); i < servicesReturned; i++ {
		entryOff := int(i) * 36
		if entryOff+36 > len(data) {
			break
		}
		nameOff := binary.LittleEndian.Uint32(data[entryOff+28 : entryOff+32])
		dispOff := binary.LittleEndian.Uint32(data[entryOff+32 : entryOff+36])
		entries = append(entries, svcEntry{
			name:        utf16At(strings, int(nameOff)),
			displayName: utf16At(strings, int(dispOff)),
			state:       binary.LittleEndian.Uint32(data[entryOff+4 : entryOff+8]),
		})
	}
	return entries, false, nil
}

// utf16At reads a null-terminated UTF-16LE string from data at offset off.
// ENUM_SERVICE_STATUSW string offsets are relative to the start of the
// marshaled array (the maxCount field, resp+4) — verified against a live
// Server 2022 response dump.
func utf16At(data []byte, off int) string {
	if off <= 0 || off >= len(data) {
		return ""
	}
	var u []uint16
	for i := off; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
