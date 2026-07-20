package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"

	"anvil/internal/ui"
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

// parseEnumResponse parses the REnumServicesStatusW response. Layout
// (verified against a live Server 2022 response dump):
//
//	[0:4]   referent for lpServiceBuf
//	[4:8]   maxCount (array capacity, bytes)
//	[8:12]  actualCount (bytes used)
//	[12:..] array data: 36-byte entries, then the string pool
//	end:    lpServicesReturned at [len-16], ReturnValue at [len-4]
//	        (preceded by referents + resume handle)
//
// Each 36-byte entry is SERVICE_STATUS FIRST, then the two string offsets:
//
//	+0  serviceType  +4  currentState  +8  controlsAccepted  +12 win32Exit
//	+16 specificExit +20 checkpoint    +24 waitHint         +28 nameOff
//	+32 displayOff   (offsets relative to the array data start)
func parseEnumResponse(resp []byte) ([]svcEntry, bool, error) {
	if len(resp) < 32 {
		return nil, false, fmt.Errorf("EnumServicesStatusW response too short (len=%d)", len(resp))
	}
	actualCount := binary.LittleEndian.Uint32(resp[8:12])
	arrayStart := 12
	arrayEnd := arrayStart + int(actualCount)
	if arrayEnd+16 > len(resp) {
		return nil, false, fmt.Errorf("EnumServicesStatusW truncated (len=%d, arrayEnd=%d)", len(resp), arrayEnd)
	}
	data := resp[arrayStart:arrayEnd]

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal == errorMoreData {
		return nil, true, nil
	}
	if retVal != 0 {
		return nil, false, fmt.Errorf("EnumServicesStatusW failed: 0x%08x", retVal)
	}
	servicesReturned := binary.LittleEndian.Uint32(resp[len(resp)-16:])
	ui.Debugf("enum: len=%d actualCount=%d returned=%d retVal=0x%x", len(resp), actualCount, servicesReturned, retVal)

	entries := make([]svcEntry, 0, servicesReturned)
	strings := resp[4:] // string offsets are relative to the array (maxCount field)
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
