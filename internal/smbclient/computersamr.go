package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/samr"

	"anvil/internal/ui"
)

// createComputer creates a machine account via SAMR and sets its password
// with SamrSetInformationUser2/UserInternal4InformationNew — the method that
// works against real Windows (mirrors impacket addcomputer). pkg/samr's
// CreateComputer sets the password via UserInternal1Information, which
// stores a broken value on Server 2022 (verified: the hash the DC recorded
// did not match the supplied password).
func (s *Session) createComputer(name, password string) error {
	name = strings.TrimSuffix(name, "$")

	pipe, err := s.client.OpenPipe("samr")
	if err != nil {
		return fmt.Errorf("open samr pipe: %v", err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return fmt.Errorf("bind samr: %v", err)
	}

	sessionKey := s.client.GetSessionKey()
	if len(sessionKey) == 0 {
		sessionKey = s.smbSessionKey
	}
	sc := samr.NewSamrClient(rpc, sessionKey)
	if err := sc.Connect(); err != nil {
		return fmt.Errorf("samr connect: %v", err)
	}
	defer sc.Close()
	if sc.AccountExists(name) {
		return fmt.Errorf("account %s$ already exists", name)
	}

	serverHandle, err := samrConnect5(rpc)
	ui.Debugf("createComputer: SamrConnect5: %v", err)
	if err != nil {
		return err
	}
	defer samrClose(rpc, serverHandle)

	domainSID, err := samrLookupDomain(rpc, serverHandle, s.netbiosDomain())
	ui.Debugf("createComputer: LookupDomain(%s): %v", s.netbiosDomain(), err)
	if err != nil {
		return err
	}
	domainHandle, err := samrOpenDomain(rpc, serverHandle, domainSID)
	ui.Debugf("createComputer: OpenDomain: %v", err)
	if err != nil {
		return err
	}
	defer samrClose(rpc, domainHandle)

	userHandle, err := samrCreateUser2(rpc, domainHandle, name)
	ui.Debugf("createComputer: CreateUser2: %v", err)
	if err != nil {
		if strings.Contains(err.Error(), "0xc0000022") {
			return fmt.Errorf("no right to create a machine account (quota exceeded or insufficient rights)")
		}
		return fmt.Errorf("create %s$: %v", name, err)
	}
	defer samrClose(rpc, userHandle)

	// Password is set via unicodePwd over LDAPS in ldapComputerAttrs (the
	// SamrSetInformationUser2/Internal4New path is refused on hardened DCs —
	// see ldapComputerAttrs).
	return nil
}

// netbiosDomain returns the NetBIOS domain name for the session's domain
// (first DNS label, uppercased).
func (s *Session) netbiosDomain() string {
	d := s.creds.Domain
	if i := strings.Index(d, "."); i > 0 {
		d = d[:i]
	}
	return strings.ToUpper(d)
}

func samrCall(rpc *dcerpc.Client, op uint16, payload []byte, opname string) ([]byte, error) {
	var resp []byte
	var err error
	if rpc.Authenticated {
		resp, err = rpc.CallAuthAuto(op, payload)
	} else {
		resp, err = rpc.Call(op, payload)
	}
	if err != nil {
		return nil, fmt.Errorf("%s RPC failed: %v", opname, err)
	}
	if len(resp) < 4 {
		return nil, fmt.Errorf("%s: response too short", opname)
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 {
		return nil, fmt.Errorf("%s failed: NTSTATUS 0x%08x", opname, ret)
	}
	return resp, nil
}

const (
	opSamrCloseHandle              = 1
	opSamrLookupDomainInSamServer  = 5
	opSamrOpenDomain               = 7
	opSamrCreateUser2InDomain      = 50
	opSamrSetInformationUser2      = 58
	opSamrConnect5                 = 64
	userInternal4InformationNew    = 25
	samAccessMaximumAllowed        = 0x000F07FF
	samUserWorkstationTrustAccount = 0x00000080
	samOpenDomainAccess            = 0x02000000
	samWhichFieldsInternal4New     = 0x01000000 | 0x08000000
)

func samrConnect5(rpc *dcerpc.Client) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // ServerName ptr
	// ServerName "\\\0": conformant varying string (3 utf16 units incl null)
	binary.Write(buf, binary.LittleEndian, uint32(3))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(3))
	binary.Write(buf, binary.LittleEndian, uint16('\\'))
	binary.Write(buf, binary.LittleEndian, uint16('\\'))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	buf.Write(make([]byte, 2))                           // pad to 4
	binary.Write(buf, binary.LittleEndian, uint32(0x30)) // DesiredAccess
	binary.Write(buf, binary.LittleEndian, uint32(1))    // InVersion
	binary.Write(buf, binary.LittleEndian, uint32(1))    // union disc
	binary.Write(buf, binary.LittleEndian, uint32(3))    // Revision
	binary.Write(buf, binary.LittleEndian, uint32(0))    // SupportedFeatures

	resp, err := samrCall(rpc, opSamrConnect5, buf.Bytes(), "SamrConnect5")
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("SamrConnect5 response too short")
	}
	handle := make([]byte, 20)
	copy(handle, resp[len(resp)-24:len(resp)-4])
	return handle, nil
}

func samrLookupDomain(rpc *dcerpc.Client, serverHandle []byte, domain string) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(serverHandle)
	writeRPCString(buf, domain)

	resp, err := samrCall(rpc, opSamrLookupDomainInSamServer, buf.Bytes(), "SamrLookupDomainInSamServer")
	if err != nil {
		return nil, err
	}
	if len(resp) < 12 {
		return nil, fmt.Errorf("LookupDomain response too short")
	}
	if binary.LittleEndian.Uint32(resp[0:4]) == 0 {
		return nil, fmt.Errorf("LookupDomain: NULL domain SID (is %q the NetBIOS domain?)", domain)
	}
	subAuthCount := int(binary.LittleEndian.Uint32(resp[4:8]))
	sidLen := 8 + subAuthCount*4
	if 8+sidLen > len(resp) {
		return nil, fmt.Errorf("LookupDomain response too short for SID")
	}
	sid := make([]byte, sidLen)
	copy(sid, resp[8:8+sidLen])
	return sid, nil
}

func samrOpenDomain(rpc *dcerpc.Client, serverHandle, domainSID []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(serverHandle)
	binary.Write(buf, binary.LittleEndian, uint32(samOpenDomainAccess))
	subAuthCount := int(domainSID[1])
	binary.Write(buf, binary.LittleEndian, uint32(subAuthCount))
	buf.Write(domainSID)

	resp, err := samrCall(rpc, opSamrOpenDomain, buf.Bytes(), "SamrOpenDomain")
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenDomain response too short")
	}
	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

func samrCreateUser2(rpc *dcerpc.Client, domainHandle []byte, name string) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(domainHandle)
	writeRPCString(buf, name+"$")
	binary.Write(buf, binary.LittleEndian, uint32(samUserWorkstationTrustAccount))
	binary.Write(buf, binary.LittleEndian, uint32(samAccessMaximumAllowed))

	resp, err := samrCall(rpc, opSamrCreateUser2InDomain, buf.Bytes(), "SamrCreateUser2InDomain")
	if err != nil {
		return nil, err
	}
	if len(resp) < 28 {
		return nil, fmt.Errorf("CreateUser2 response too short")
	}
	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

func samrClose(rpc *dcerpc.Client, handle []byte) {
	buf := new(bytes.Buffer)
	buf.Write(handle)
	_, _ = samrCall(rpc, opSamrCloseHandle, buf.Bytes(), "SamrCloseHandle")
}

// writeRPCString writes an RPC_UNICODE_STRING inline header + deferred
// conformant varying UTF-16 data, 4-byte aligned. No null terminator, per
// pkg/samr's own convention for these calls.
func writeRPCString(buf *bytes.Buffer, s string) {
	u16 := utf16.Encode([]rune(s))
	n := uint16(len(u16) * 2)
	binary.Write(buf, binary.LittleEndian, n)                  // Length
	binary.Write(buf, binary.LittleEndian, n)                  // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer ptr
	count := uint32(len(u16))
	binary.Write(buf, binary.LittleEndian, count) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, count) // ActualCount
	for _, c := range u16 {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if dataLen := int(count) * 2; dataLen%4 != 0 {
		buf.Write(make([]byte, 4-dataLen%4))
	}
}
