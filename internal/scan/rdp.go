package scan

// RDP security-negotiation probe (port 3389).
//
// An RDP connection opens with an X.224 Connection Request inside a TPKT
// (RFC 1006). A client that understands Enhanced Security appends an
// RDP_NEG_REQ offering the external security protocols it supports
// ([MS-RDPBCGR] §2.2.1.1.1), and a server in the default "Negotiate"
// posture answers the X.224 Connection Confirm with an RDP_NEG_RSP
// naming the one it picked (§2.2.1.2.1). That single byte answers the
// pre-auth hardening question:
//
//   - PROTOCOL_HYBRID (0x02) = CredSSP → Network Level Authentication is
//     enforced: credentials are validated before any session exists,
//     which is what kills pre-auth RCE surface (the BlueKeep class) and
//     anonymous logon-screen interaction. HYBRID_EX (0x08, CredSSP with
//     Early User Auth) implies CredSSP and counts as NLA too.
//   - PROTOCOL_SSL (0x01) = TLS without CredSSP → the channel is
//     encrypted but the logon screen is reached unauthenticated: NLA is
//     NOT enforced.
//
// Two non-answers are also verdicts. A server configured for "RDP
// Security Layer" only, or a pre-Vista host that does not understand
// negotiation at all, returns a bare Connection Confirm with no
// negotiation structure — legacy RDP security, so NLA cannot be
// enforced. And a server that dislikes the offer returns an
// RDP_NEG_FAILURE (§2.2.1.2.2); the probe records it as an error with
// the failure code named. One request, one reply; dial, write, read, and
// parse problems land in Error and the scan moves on.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	tpktVersion = 3    // RFC 1006 §6 TPKT version
	x224CR      = 0xE0 // X.224 Connection Request TPDU code
	x224CC      = 0xD0 // X.224 Connection Confirm TPDU code
	x224DR      = 0x80 // X.224 Disconnect Request TPDU code

	// Negotiation structure types ([MS-RDPBCGR] §2.2.1.1.1, §2.2.1.2.1,
	// §2.2.1.2.2).
	rdpNegReq     = 1
	rdpNegRsp     = 2
	rdpNegFailure = 3

	// requestedProtocols / selectedProtocol flags ([MS-RDPBCGR]
	// §2.2.1.1.1).
	protoRDP      = 0x00000000 // Standard RDP Security (§5.3)
	protoSSL      = 0x00000001 // TLS (§5.4.5.1)
	protoHybrid   = 0x00000002 // CredSSP — NLA (§5.4.5.2)
	protoRDSTLS   = 0x00000004 // RDSTLS (§5.4.5.3)
	protoHybridEx = 0x00000008 // CredSSP with Early User Auth (§5.4.5.2.1)
)

// maxRDPReply caps the TPKT we will buffer. A Connection Confirm carrying
// a negotiation structure is 19 bytes; the cap only guards against a
// hostile peer making the scan allocate on its length field's say-so.
const maxRDPReply = 4096

// probeRDP reports whether the RDP server on target:port enforces NLA,
// from the protocol its Connection Confirm selects. NLA stays nil when
// no verdict was reached (transport or parse failure, or a negotiation
// failure the server answered instead of selecting a protocol).
func probeRDP(target string, port int, timeout time.Duration) *RDPInfo {
	info := &RDPInfo{Probed: true}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), timeout)
	if err != nil {
		info.Error = fmt.Sprintf("dial: %v", err)
		return info
	}
	defer conn.Close()
	// One deadline covering the whole write+read exchange; the server
	// either answers the Connection Request immediately or not at all.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildRDPConnRequest()); err != nil {
		info.Error = fmt.Sprintf("write: %v", err)
		return info
	}
	reply, err := readTPKT(conn)
	if err != nil {
		info.Error = fmt.Sprintf("read: %v", err)
		return info
	}

	nla, err := parseRDPConnConfirm(reply)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.NLA = &nla
	return info
}

// buildRDPConnRequest marshals the probe's TPKT + X.224 Connection
// Request with an RDP_NEG_REQ offering TLS, CredSSP, and CredSSP with
// Early User Auth (PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX).
// Offering the full enhanced-security menu — the same shape nmap's
// rdp-enum-encryption sends — forces the server to name its strongest
// protocol, so the answer cannot hide NLA behind a weaker client offer.
// RDSTLS is not offered: it is only negotiated for AAD-joined or
// restricted-admin scenarios, and asking for it would muddy the NLA
// verdict the probe exists for.
//
// Layout: 4-byte TPKT header (version 3, big-endian total length), then
// the X.224 CR TPDU — LI (bytes following it), code 0xE0, DST-REF 0,
// SRC-REF 0, class 0 — with the 8-byte RDP_NEG_REQ as user data. All
// multi-byte fields inside the negotiation structure are little-endian;
// the TPKT length is big-endian.
func buildRDPConnRequest() []byte {
	neg := make([]byte, 8)
	neg[0] = rdpNegReq
	// flags (1) stay 0: none of the RESTRICTED_ADMIN / REDIRECTION flags
	// apply to a probe that never proceeds past negotiation.
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], protoSSL|protoHybrid|protoHybridEx)

	// LI counts the TPDU bytes after itself; Microsoft's RDP stack
	// counts the negotiation structure in (the X.224 CR from a real mstsc
	// has LI = 6 + 8 = 14), so it is part of the value here too.
	tpdu := []byte{byte(6 + len(neg)), x224CR, 0x00, 0x00, 0x00, 0x00, 0x00}
	tpdu = append(tpdu, neg...)

	pkt := make([]byte, 4, 4+len(tpdu))
	pkt[0] = tpktVersion
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(tpdu)))
	return append(pkt, tpdu...)
}

// readTPKT reads one TPKT (RFC 1006 §6): 4-byte header with version 3 and
// a big-endian total length, then the remainder. The packet is returned
// whole, header included, so the parser can cross-check the length.
func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tpktVersion {
		return nil, fmt.Errorf("not a TPKT packet (version byte 0x%02x, want 0x03)", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 4 || n > maxRDPReply {
		return nil, fmt.Errorf("implausible TPKT length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr[:], body...), nil
}

// parseRDPConnConfirm decodes one server reply to the Connection Request
// and returns whether the selected protocol enforces NLA. A bare
// Connection Confirm (no negotiation structure) is a verdict, not an
// error: the server ignored the RDP_NEG_REQ entirely, which is what
// pre-negotiation hosts (XP/2003-era, or non-Microsoft xrdp in its
// default mode) do — they only speak Standard RDP Security.
func parseRDPConnConfirm(b []byte) (nla bool, err error) {
	if len(b) < 11 {
		return false, fmt.Errorf("packet is %d bytes, an X.224 Connection Confirm is at least 11", len(b))
	}
	if b[0] != tpktVersion {
		return false, fmt.Errorf("not a TPKT packet (version byte 0x%02x, want 0x03)", b[0])
	}
	if n := int(binary.BigEndian.Uint16(b[2:4])); n != len(b) {
		return false, fmt.Errorf("TPKT declares %d bytes but %d arrived", n, len(b))
	}
	li := int(b[4])
	if li < 6 || 5+li > len(b) {
		return false, fmt.Errorf("X.224 length indicator %d does not fit a %d-byte packet", li, len(b))
	}
	switch code := b[5]; code {
	case x224DR:
		return false, fmt.Errorf("server rejected the connection outright (X.224 Disconnect Request)")
	case x224CC:
	default:
		return false, fmt.Errorf("X.224 TPDU code 0x%02x is not a Connection Confirm (0xD0)", code)
	}

	// The CC fixed part is always 6 bytes after LI (code, DST-REF,
	// SRC-REF, class), so negotiation data — when present — starts at
	// offset 11. LI is deliberately not used to locate it: Microsoft
	// counts the negotiation structure inside LI while a strict X.224
	// sender would not, and both forms parse the same way from the fixed
	// offset.
	data := b[11:]
	if len(data) == 0 {
		return false, nil
	}
	if len(data) < 8 {
		return false, fmt.Errorf("negotiation structure is %d bytes, want 8", len(data))
	}
	if n := binary.LittleEndian.Uint16(data[2:4]); n != 8 {
		return false, fmt.Errorf("negotiation structure declares %d bytes, want 8", n)
	}

	switch typ := data[0]; typ {
	case rdpNegRsp:
		selected := binary.LittleEndian.Uint32(data[4:8])
		// CredSSP in either flavor is NLA; TLS or Standard RDP Security
		// alone is not. PROTOCOL_HYBRID_EX is only valid alongside
		// HYBRID (§2.2.1.1.1), but OR-ing it in keeps the verdict right
		// even for a server that sets it alone.
		return selected&(protoHybrid|protoHybridEx) != 0, nil
	case rdpNegFailure:
		return false, fmt.Errorf("server refused the security negotiation: %s", rdpFailureName(binary.LittleEndian.Uint32(data[4:8])))
	default:
		return false, fmt.Errorf("unexpected negotiation structure type 0x%02x", typ)
	}
}

// rdpFailureName renders an RDP_NEG_FAILURE code ([MS-RDPBCGR]
// §2.2.1.2.2) with its plain-language meaning. Codes beyond the table
// are kept as hex rather than dropped.
func rdpFailureName(code uint32) string {
	switch code {
	case 1:
		return "SSL_REQUIRED_BY_SERVER (server insists on TLS)"
	case 2:
		return "SSL_NOT_ALLOWED_BY_SERVER (server only speaks Standard RDP Security — no TLS or CredSSP)"
	case 3:
		return "SSL_CERT_NOT_ON_SERVER (server has no TLS certificate)"
	case 4:
		return "INCONSISTENT_FLAGS (malformed negotiation request)"
	case 5:
		return "HYBRID_REQUIRED_BY_SERVER (server insists on CredSSP/NLA)"
	case 6:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER (server insists on TLS with user authentication)"
	default:
		return fmt.Sprintf("unrecognized failure code 0x%08x", code)
	}
}
