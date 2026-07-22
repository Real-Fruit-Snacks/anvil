package scan

// MSSQL prelogin probe (port 1433).
//
// TDS opens every connection with an unauthenticated PRELOGIN handshake:
// the client announces its capabilities in a token stream and the server
// answers with its own — its exact build version and its encryption
// posture ([MS-TDS] §2.2.6.5 PRELOGIN). Because the exchange completes
// before any credential is offered, one request/reply yields a free
// fingerprint of the service.
//
// The client sends ENCRYPT_OFF and the server's answer is constrained by
// the response table in [MS-TDS] §2.2.6.5 to one of exactly three values,
// which is what TDSInfo.Encrypt reports:
//
//   - ENCRYPT_REQ (0x03) — the server was configured "Force Encryption:
//     Yes"; it refuses to speak to a client that will not encrypt.
//   - ENCRYPT_OFF (0x00) — encryption available but off (the default):
//     only the login packet is encrypted and the rest of the session is
//     plaintext, which is what makes TDS session snooping worth flagging.
//   - ENCRYPT_NOT_SUP (0x02) — the server has no certificate at all.
//
// The probe sends one PRELOGIN packet and reads one table response; dial,
// write, read, and parse problems are recorded in Error and the scan
// moves on.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	tdsPktPrelogin = 0x12 // client's PRELOGIN message ([MS-TDS] §2.2.6.5)
	tdsPktTabular  = 0x04 // a PRELOGIN answer arrives as a "table response" (same section)
	tdsStatusEOM   = 0x01 // Status bit: last packet of the message ([MS-TDS] §2.2.3.1.2)

	// PRELOGIN token types ([MS-TDS] §2.2.6.5, PL_OPTION_TOKEN table).
	tdsTokVersion    = 0x00
	tdsTokEncrypt    = 0x01
	tdsTokThreadID   = 0x03
	tdsTokMARS       = 0x04
	tdsTokTerminator = 0xFF
)

// ENCRYPTION token values ([MS-TDS] §2.2.6.5, "Encryption" subsection).
const (
	tdsEncryptOff    = 0x00 // encryption available but off
	tdsEncryptOn     = 0x01 // encryption available and on
	tdsEncryptNotSup = 0x02 // encryption not available
	tdsEncryptReq    = 0x03 // encryption required
)

// maxTDSMessage caps the reassembled message we will buffer across the
// EOM packet loop. A prelogin answer is under 100 bytes and virtually
// always a single packet; the cap exists so a hostile peer streaming
// non-EOM packets cannot make the scan grow a buffer on its say-so.
const maxTDSMessage = 1 << 20

// probeTDS fingerprint an MSSQL listener on target:port from the prelogin
// exchange: Version from the server's VERSION token and Encrypt from its
// ENCRYPTION token. Probed is always true — Error records why a verdict
// is absent rather than failing the scan.
func probeTDS(target string, port int, timeout time.Duration) *TDSInfo {
	info := &TDSInfo{Probed: true}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), timeout)
	if err != nil {
		info.Error = fmt.Sprintf("dial: %v", err)
		return info
	}
	defer conn.Close()
	// One deadline covering the whole write+read exchange; the server
	// either answers a prelogin immediately or not at all.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildTDSPrelogin()); err != nil {
		info.Error = fmt.Sprintf("write: %v", err)
		return info
	}
	msgType, payload, err := readTDSMessage(conn)
	if err != nil {
		info.Error = fmt.Sprintf("read: %v", err)
		return info
	}
	// [MS-TDS] §2.2.6.5: "The server responds to a client PRELOGIN
	// message with a message of packet header type 0x04." Enforcing it
	// doubles as a service check — anything else on the port is not
	// speaking TDS.
	if msgType != tdsPktTabular {
		info.Error = fmt.Sprintf("reply is TDS packet type 0x%02x, not the 0x04 table response that carries a prelogin answer", msgType)
		return info
	}

	version, encrypt, err := parseTDSPrelogin(payload)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Version = version
	info.Encrypt = encrypt
	return info
}

// buildTDSPrelogin marshals the probe's PRELOGIN message: an 8-byte TDS
// packet header followed by the token list and token data
// ([MS-TDS] §2.2.6.5, sample in §4.1). Each token record is
// {type, big-endian offset, big-endian length} with offsets counted from
// the first token byte, and 0xFF terminates the list. VERSION is required
// to be first or the server closes the connection. The client's own
// VERSION/THREADID payloads are debugging information the server ignores,
// so they are zeros; ENCRYPTION is ENCRYPT_OFF for the posture split
// documented at the top of this file; MARS is off.
func buildTDSPrelogin() []byte {
	tokens := []struct {
		typ  byte
		data []byte
	}{
		{tdsTokVersion, make([]byte, 6)},
		{tdsTokEncrypt, []byte{tdsEncryptOff}},
		{tdsTokThreadID, make([]byte, 4)},
		{tdsTokMARS, []byte{0x00}},
	}

	// The token data begins right after the list: 5 bytes per record plus
	// the 1-byte terminator (the §4.1 sample lays out four tokens exactly
	// this way).
	offset := 5*len(tokens) + 1
	var list, data []byte
	for _, t := range tokens {
		list = append(list, t.typ, byte(offset>>8), byte(offset), byte(len(t.data)>>8), byte(len(t.data)))
		data = append(data, t.data...)
		offset += len(t.data)
	}
	payload := append(append(list, tdsTokTerminator), data...)

	pkt := make([]byte, 8, 8+len(payload))
	pkt[0] = tdsPktPrelogin
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(8+len(payload)))
	// SPID (4:6) is 0 pre-login, PacketID (6) is 1, Window (7) is 0.
	pkt[6] = 1
	return append(pkt, payload...)
}

// readTDSMessage reads TDS packets until one arrives with the EOM status
// bit and returns the message type of the first packet and the
// concatenated payload. The prelogin answer never spans packets in
// practice, but [MS-TDS] permits any message to be split, with EOM
// marking the last packet ([MS-TDS] §2.2.3.1.2) — clients are expected
// to reassemble rather than assume one packet per message.
func readTDSMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	first := true
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, err
		}
		// The Length field is big-endian and counts the header itself
		// ([MS-TDS] §2.2.3.1).
		length := int(binary.BigEndian.Uint16(hdr[2:4]))
		if length < 8 {
			return 0, nil, fmt.Errorf("implausible packet length %d", length)
		}
		if len(payload)+length-8 > maxTDSMessage {
			return 0, nil, fmt.Errorf("message exceeds %d bytes without an end-of-message packet", maxTDSMessage)
		}
		if first {
			msgType = hdr[0]
			first = false
		}
		body := make([]byte, length-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
		payload = append(payload, body...)
		if hdr[1]&tdsStatusEOM != 0 {
			return msgType, payload, nil
		}
	}
}

// parseTDSPrelogin decodes the token stream of a PRELOGIN structure (the
// payload of the server's 0x04 response, packet header already stripped)
// and returns the server version as "major.minor.build" and the
// encryption posture. The walk tolerates tokens it does not know (the
// spec's list keeps growing — FEDAUTHREQUIRED, NONCEOPT, ...), bounded
// strictly so a malformed offset cannot read outside the message.
func parseTDSPrelogin(b []byte) (version, encrypt string, err error) {
	tokens := map[byte][]byte{}
	for i := 0; ; {
		if i >= len(b) {
			return "", "", fmt.Errorf("token stream has no TERMINATOR (0xFF)")
		}
		tok := b[i]
		if tok == tdsTokTerminator {
			break
		}
		if i+5 > len(b) {
			return "", "", fmt.Errorf("truncated token record for type 0x%02x", tok)
		}
		off := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
		ln := int(binary.BigEndian.Uint16(b[i+3 : i+5]))
		if off+ln > len(b) {
			return "", "", fmt.Errorf("token 0x%02x data (offset %d, %d bytes) runs past the end of the message", tok, off, ln)
		}
		tokens[tok] = b[off : off+ln]
		i += 5
	}

	// VERSION is the one token [MS-TDS] requires in every prelogin
	// message; an answer without it is not a real prelogin response.
	v, ok := tokens[tdsTokVersion]
	if !ok {
		return "", "", fmt.Errorf("prelogin response carries no VERSION token")
	}
	if len(v) != 6 {
		return "", "", fmt.Errorf("VERSION token is %d bytes, want 6", len(v))
	}
	version = tdsVersionString(v)

	if e, ok := tokens[tdsTokEncrypt]; ok {
		if len(e) != 1 {
			return "", "", fmt.Errorf("ENCRYPTION token is %d bytes, want 1", len(e))
		}
		encrypt = tdsEncryptName(e[0])
	}
	return version, encrypt, nil
}

// tdsVersionString renders the 6-byte VERSION token data as
// "major.minor.build". The layout is major (1 byte), minor (1 byte),
// build (2 bytes big-endian), sub-build (2 bytes) ([MS-TDS] §2.2.6.5,
// UL_VERSION + US_SUBBUILD); the sub-build is dropped because it never
// discriminates the product. The major byte maps to the product name per
// Microsoft's version table (KB 321185):
//
//	8 = SQL Server 2000, 9 = 2005, 10 = 2008 (10.5 = 2008 R2), 11 = 2012,
//	12 = 2014, 13 = 2016, 14 = 2017, 15 = 2019, 16 = 2022
//
// The mapping is orientation for the operator reading a scan; the probe
// reports the numeric form only.
func tdsVersionString(v []byte) string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.BigEndian.Uint16(v[2:4]))
}

// tdsEncryptName maps the ENCRYPTION byte to the reported posture. "on"
// is unreachable in practice — the §2.2.6.5 response table only returns
// ENCRYPT_ON to a client that asked for encryption, and the probe sends
// ENCRYPT_OFF — but it is mapped so a non-compliant server still renders
// legibly. Unknown values are kept verbatim rather than dropped.
func tdsEncryptName(b byte) string {
	switch b {
	case tdsEncryptOff:
		return "off"
	case tdsEncryptOn:
		return "on"
	case tdsEncryptNotSup:
		return "not supported"
	case tdsEncryptReq:
		return "required"
	default:
		return fmt.Sprintf("unknown (0x%02x)", b)
	}
}
