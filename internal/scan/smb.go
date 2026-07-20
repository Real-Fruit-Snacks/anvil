package scan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/mandiant/gopacket/pkg/ntlm"
	"github.com/mandiant/gopacket/pkg/utf16le"
)

// Packet construction adapted from gopacket tools/DumpNTLMInfo (Apache-2.0).
// Deviations from the source tool: io.ReadFull is used for NetBIOS reads
// (identical wire behavior, robust against short reads), and the SMB1
// security-mode byte is interpreted with the MS-CIFS bits (0x04 signatures
// enabled, 0x08 signatures required) instead of the SMB2 bits.

const (
	smb1HeaderMagic = "\xffSMB"
	smb2HeaderMagic = "\xfeSMB"
	smbComNegotiate = 0x72

	// SMB2 commands
	smb2Negotiate    = 0x0000
	smb2SessionSetup = 0x0001

	// SMB2 dialects
	smb2Dialect002  = 0x0202
	smb2Dialect21   = 0x0210
	smb2Dialect30   = 0x0300
	smb2Dialect302  = 0x0302
	smb2Dialect311  = 0x0311
	smb2DialectWild = 0x02FF

	// SMB2 security mode
	smb2NegotiateSigningEnabled  = 0x0001
	smb2NegotiateSigningRequired = 0x0002

	// SMB2 capabilities
	smb2GlobalCapEncryption = 0x00000040

	statusMoreProcessingRequired = 0xC0000016
)

// probeSMB fingerprints SMB on target:port without authentication.
func probeSMB(target string, port int, timeout time.Duration) *SMBInfo {
	info := &SMBInfo{Probed: true}
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	// SMB1 detection on a separate connection (SMB1-only negotiate).
	info.SMB1Enabled = checkSMB1(addr, timeout)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		info.Error = fmt.Sprintf("connect: %v", err)
		return info
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * timeout))

	resp, err := smbExchange(conn, buildMultiDialectNegotiate())
	if err != nil {
		info.Error = fmt.Sprintf("negotiate: %v", err)
		return info
	}
	if len(resp) < 4 {
		info.Error = "negotiate: response too short"
		return info
	}

	var dialect, securityMode uint16

	switch string(resp[0:4]) {
	case smb2HeaderMagic:
		dialect, securityMode, err = parseSMB2NegotiateResponse(resp)
		if err != nil {
			info.Error = err.Error()
			return info
		}

		// Wildcard dialect: redo the negotiate as real SMB2 on a fresh
		// connection, offering up to SMB 3.1.1.
		if dialect == smb2DialectWild {
			conn.Close()

			conn, resp, err = dialSMB2Negotiate(addr, timeout, buildSMB2Negotiate())
			if err != nil {
				// Some servers react badly to negotiate contexts; retry
				// once with the legacy 3-dialect offer (max 3.0).
				conn, resp, err = dialSMB2Negotiate(addr, timeout, buildSMB2NegotiateLegacy())
				if err != nil {
					info.Error = fmt.Sprintf("smb2 negotiate: %v", err)
					return info
				}
			}
			defer conn.Close()

			dialect, securityMode, err = parseSMB2NegotiateResponse(resp)
			if err != nil {
				info.Error = err.Error()
				return info
			}
		}

		info.Dialect = smbDialectString(dialect)
		info.SigningEnabled = securityMode&smb2NegotiateSigningEnabled != 0
		info.SigningRequired = securityMode&smb2NegotiateSigningRequired != 0

	case smb1HeaderMagic:
		// Server speaks SMB1 only. The SMB1 security mode byte uses MS-CIFS
		// bits: 0x04 signatures enabled, 0x08 signatures required.
		secMode, err := parseSMB1SecurityMode(resp)
		if err != nil {
			info.Error = err.Error()
			return info
		}
		info.Dialect = "SMB 1.0"
		info.SigningEnabled = secMode&0x04 != 0
		info.SigningRequired = secMode&0x08 != 0
		return info // no SMB2 session setup possible on an SMB1 connection

	default:
		info.Error = "unknown SMB response"
		return info
	}

	// NTLM challenge via SMB2 SESSION_SETUP on the same connection. A failure
	// here does not invalidate the negotiate results.
	if challenge, err := smbGetNTLMChallenge(conn); err == nil {
		parseNTLMChallenge(challenge, info)
	}
	return info
}

// checkSMB1 reports whether the server answers an SMB1-only negotiate with
// the SMB1 magic.
func checkSMB1(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * timeout))

	resp, err := smbExchange(conn, buildSMB1Negotiate())
	if err != nil {
		return false
	}
	return len(resp) >= 4 && string(resp[0:4]) == smb1HeaderMagic
}

func smbDialectString(d uint16) string {
	switch d {
	case smb2Dialect002:
		return "SMB 2.0.2"
	case smb2Dialect21:
		return "SMB 2.1"
	case smb2Dialect30:
		return "SMB 3.0"
	case smb2Dialect302:
		return "SMB 3.0.2"
	case smb2Dialect311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}

func smbGetNTLMChallenge(conn net.Conn) ([]byte, error) {
	resp, err := smbExchange(conn, buildSMB2SessionSetup())
	if err != nil {
		return nil, err
	}
	return extractNTLMChallenge(resp)
}

// dialSMB2Negotiate dials addr, sends an SMB2 negotiate offer, and returns
// the open connection plus the raw response. The caller owns the connection.
func dialSMB2Negotiate(addr string, timeout time.Duration, offer []byte) (net.Conn, []byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(4 * timeout))

	resp, err := smbExchange(conn, offer)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, resp, nil
}

// parseNTLMChallenge extracts the OS version and AV pairs from an NTLM
// Type 2 (challenge) message.
func parseNTLMChallenge(ntlmMsg []byte, info *SMBInfo) {
	if len(ntlmMsg) < 56 {
		return
	}

	targetInfoLen := binary.LittleEndian.Uint16(ntlmMsg[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(ntlmMsg[44:48])
	if targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(ntlmMsg) {
		targetInfo := ntlmMsg[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
		if pairs, ok := ntlm.ParseAvPairs(targetInfo); ok {
			if val, ok := pairs[ntlm.MsvAvNbDomainName]; ok {
				info.NBDomain = utf16le.DecodeToString(val)
			}
			if val, ok := pairs[ntlm.MsvAvNbComputerName]; ok {
				info.NBComputer = utf16le.DecodeToString(val)
			}
			if val, ok := pairs[ntlm.MsvAvDnsComputerName]; ok {
				info.DNSComputer = utf16le.DecodeToString(val)
			}
			if val, ok := pairs[ntlm.MsvAvDnsDomainName]; ok {
				info.DNSDomain = utf16le.DecodeToString(val)
			}
		}
	}

	// OS version at offset 48: major, minor, build (LE16).
	version := ntlmMsg[48:56]
	info.OSVersion = fmt.Sprintf("Windows NT %d.%d Build %d",
		version[0], version[1], binary.LittleEndian.Uint16(version[2:4]))
}

// --- NetBIOS session framing ---

func smbExchange(conn net.Conn, packet []byte) ([]byte, error) {
	if err := sendNetBIOS(conn, packet); err != nil {
		return nil, err
	}
	return recvNetBIOS(conn)
}

func sendNetBIOS(conn net.Conn, data []byte) error {
	// 4-byte header: 0x00 (session message) + 3-byte big-endian length.
	header := []byte{0x00, byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
	_, err := conn.Write(append(header, data...))
	return err
}

func recvNetBIOS(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length == 0 {
		return nil, fmt.Errorf("empty NetBIOS response")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

// --- Packet builders ---

func buildSMB1Negotiate() []byte {
	dialects := []byte("\x02NT LM 0.12\x00")

	header := make([]byte, 32)
	copy(header[0:4], smb1HeaderMagic)
	header[4] = smbComNegotiate
	header[13] = 0x18 // Flags1: PATHCASELESS | CANONICALIZED_PATHS
	// Flags2: EXTENDED_SECURITY | NT_STATUS | LONG_NAMES | UNICODE
	binary.LittleEndian.PutUint16(header[14:16], 0xc803)

	cmd := []byte{0x00} // WordCount = 0
	cmd = append(cmd, byte(len(dialects)), byte(len(dialects)>>8))
	cmd = append(cmd, dialects...)

	return append(header, cmd...)
}

func buildMultiDialectNegotiate() []byte {
	// SMB1 negotiate carrying SMB2 dialect strings to trigger an SMB2 response.
	dialects := []byte("\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00")

	header := make([]byte, 32)
	copy(header[0:4], smb1HeaderMagic)
	header[4] = smbComNegotiate
	header[13] = 0x18
	binary.LittleEndian.PutUint16(header[14:16], 0xc803)

	cmd := []byte{0x00}
	cmd = append(cmd, byte(len(dialects)), byte(len(dialects)>>8))
	cmd = append(cmd, dialects...)

	return append(header, cmd...)
}

// buildSMB2Negotiate offers dialects up to SMB 3.1.1. Offering 0x0311
// requires an SMB2_PREAUTH_INTEGRITY_CAPABILITIES negotiate context
// (MS-SMB2 2.2.3.1), or servers fail the negotiate with
// STATUS_INVALID_PARAMETER. Note: only the NTLM Type 1 → Type 2 exchange
// follows the negotiate, so preauth key derivation never comes into play.
func buildSMB2Negotiate() []byte {
	dialects := []uint16{smb2Dialect002, smb2Dialect21, smb2Dialect30, smb2Dialect302, smb2Dialect311}

	header := make([]byte, 64)
	copy(header[0:4], smb2HeaderMagic)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], smb2Negotiate)
	binary.LittleEndian.PutUint16(header[14:16], 1) // Credits

	// Negotiate request fixed part (36 bytes).
	nego := make([]byte, 36)
	binary.LittleEndian.PutUint16(nego[0:2], 36)
	binary.LittleEndian.PutUint16(nego[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(nego[4:6], smb2NegotiateSigningEnabled) // SecurityMode
	// nego[6:8] Reserved = 0
	binary.LittleEndian.PutUint32(nego[8:12], smb2GlobalCapEncryption) // Capabilities
	for i := 12; i < 28; i++ {
		nego[i] = byte(i) // Client GUID (pseudo-random)
	}

	// The negotiate context offset is absolute from the start of the 64-byte
	// SMB2 header and must be 8-byte aligned: 64 + 36 + 10 dialect bytes =
	// 110 → pad 2 → context at 112.
	contextOffset := 64 + 36 + len(dialects)*2
	contextOffset += (8 - contextOffset%8) % 8
	binary.LittleEndian.PutUint32(nego[28:32], uint32(contextOffset))
	binary.LittleEndian.PutUint16(nego[32:34], 1) // NegotiateContextCount
	// nego[34:36] Reserved2 = 0

	packet := append(header, nego...)
	for _, dialect := range dialects {
		var d [2]byte
		binary.LittleEndian.PutUint16(d[:], dialect)
		packet = append(packet, d[:]...)
	}
	for len(packet) < contextOffset {
		packet = append(packet, 0x00)
	}

	// SMB2_PREAUTH_INTEGRITY_CAPABILITIES context (type 0x0001).
	ctx := make([]byte, 8+38)
	binary.LittleEndian.PutUint16(ctx[0:2], 0x0001) // Type
	binary.LittleEndian.PutUint16(ctx[2:4], 38)     // DataLength
	// ctx[4:8] Reserved = 0
	data := ctx[8:]
	binary.LittleEndian.PutUint16(data[0:2], 1)      // HashAlgorithmCount
	binary.LittleEndian.PutUint16(data[2:4], 32)     // SaltLength
	binary.LittleEndian.PutUint16(data[4:6], 0x0001) // SHA-512
	for i := 6; i < 38; i++ {
		data[i] = byte(i) // Salt: 32 arbitrary nonzero bytes
	}

	return append(packet, ctx...)
}

// buildSMB2NegotiateLegacy is the original gopacket tools/DumpNTLMInfo offer
// (max dialect 3.0, no negotiate contexts), kept as a fallback for servers
// that reject the extended offer.
func buildSMB2NegotiateLegacy() []byte {
	dialects := []uint16{smb2Dialect002, smb2Dialect21, smb2Dialect30}

	header := make([]byte, 64)
	copy(header[0:4], smb2HeaderMagic)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], smb2Negotiate)
	binary.LittleEndian.PutUint16(header[14:16], 1) // Credits

	// Negotiate request (36 bytes + dialects)
	nego := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(nego[0:2], 36)
	binary.LittleEndian.PutUint16(nego[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(nego[4:6], smb2NegotiateSigningEnabled) // SecurityMode
	binary.LittleEndian.PutUint32(nego[8:12], smb2GlobalCapEncryption)    // Capabilities
	for i := 12; i < 28; i++ {
		nego[i] = byte(i) // Client GUID (pseudo-random)
	}
	for i, dialect := range dialects {
		binary.LittleEndian.PutUint16(nego[36+i*2:38+i*2], dialect)
	}

	return append(header, nego...)
}

func buildSMB2SessionSetup() []byte {
	ntlmType1 := buildNTLMType1()
	spnego := wrapInSPNEGO(ntlmType1)

	header := make([]byte, 64)
	copy(header[0:4], smb2HeaderMagic)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], smb2SessionSetup)
	binary.LittleEndian.PutUint16(header[14:16], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(header[18:20], 31) // CreditRequest
	binary.LittleEndian.PutUint64(header[24:32], 1)  // MessageId = 1 (negotiate was 0)

	// Session setup request: StructureSize 25 = 24 fixed + 1 byte buffer.
	setup := make([]byte, 24)
	binary.LittleEndian.PutUint16(setup[0:2], 25)
	setup[2] = 0                                       // Flags
	setup[3] = 0x01                                    // SecurityMode = SIGNING_ENABLED
	binary.LittleEndian.PutUint32(setup[4:8], 0)       // Capabilities
	binary.LittleEndian.PutUint32(setup[8:12], 0)      // Channel
	binary.LittleEndian.PutUint16(setup[12:14], 64+24) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(setup[14:16], uint16(len(spnego)))
	binary.LittleEndian.PutUint64(setup[16:24], 0) // PreviousSessionId

	packet := append(header, setup...)
	return append(packet, spnego...)
}

func buildNTLMType1() []byte {
	msg := []byte("NTLMSSP\x00")
	msg = append(msg, 0x01, 0x00, 0x00, 0x00) // Type 1

	// NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET |
	// NEGOTIATE_EXTENDED_SESSIONSECURITY (and friends)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, 0xe2088297)
	msg = append(msg, flags...)

	// Domain (empty)
	msg = append(msg, 0x00, 0x00)             // DomainLen
	msg = append(msg, 0x00, 0x00)             // DomainMaxLen
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // DomainOffset

	// Workstation (empty)
	msg = append(msg, 0x00, 0x00)             // WorkstationLen
	msg = append(msg, 0x00, 0x00)             // WorkstationMaxLen
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // WorkstationOffset

	// Version 6.1 (Win7), NTLM revision 0x0f
	msg = append(msg, 0x06, 0x01, 0x00, 0x00)
	msg = append(msg, 0x00, 0x00, 0x00, 0x0f)

	return msg
}

func wrapInSPNEGO(ntlmMsg []byte) []byte {
	// NTLM OID 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechType := append([]byte{0x06, byte(len(ntlmOID))}, ntlmOID...)
	mechTypes := asn1Wrap(0xa0, asn1Wrap(0x30, mechType))
	mechToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlmMsg))
	negTokenInit := asn1Wrap(0x30, append(mechTypes, mechToken...))

	// SPNEGO OID 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	app := append(spnegoOID, asn1Wrap(0xa0, negTokenInit)...)
	return asn1Wrap(0x60, app)
}

func asn1Wrap(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	} else if length < 256 {
		return append([]byte{tag, 0x81, byte(length)}, data...)
	}
	return append([]byte{tag, 0x82, byte(length >> 8), byte(length)}, data...)
}

// --- Response parsers ---

func parseSMB2NegotiateResponse(data []byte) (dialect, securityMode uint16, err error) {
	if len(data) < 64+65 {
		return 0, 0, fmt.Errorf("SMB2 response too short")
	}
	// Negotiate response starts past the 64-byte SMB2 header.
	negoResp := data[64:]
	securityMode = binary.LittleEndian.Uint16(negoResp[2:4])
	dialect = binary.LittleEndian.Uint16(negoResp[4:6])
	return dialect, securityMode, nil
}

func parseSMB1SecurityMode(data []byte) (uint8, error) {
	if len(data) < 39 {
		return 0, fmt.Errorf("SMB1 response too short")
	}
	if wordCount := data[32]; wordCount < 17 {
		return 0, fmt.Errorf("unexpected word count: %d", wordCount)
	}
	params := data[33:]
	return params[2], nil
}

func extractNTLMChallenge(data []byte) ([]byte, error) {
	// SMB2 status: STATUS_MORE_PROCESSING_REQUIRED means a Type 2 follows.
	if len(data) >= 12 {
		status := binary.LittleEndian.Uint32(data[8:12])
		if status != statusMoreProcessingRequired && status != 0 {
			return nil, fmt.Errorf("session setup failed with status 0x%08x", status)
		}
	}

	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil, fmt.Errorf("NTLMSSP not found in response")
	}

	ntlmMsg := data[idx:]
	if len(ntlmMsg) < 56 {
		return nil, fmt.Errorf("NTLM message too short")
	}
	if msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12]); msgType != 2 {
		return nil, fmt.Errorf("expected NTLM Type 2, got %d", msgType)
	}
	return ntlmMsg, nil
}
