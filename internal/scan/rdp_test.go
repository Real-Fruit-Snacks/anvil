package scan

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// buildConnConfirm assembles a synthetic server reply: TPKT header
// (RFC 1006) + X.224 Connection Confirm TPDU (LI, code 0xD0, DST-REF,
// SRC-REF, class) + the optional negotiation structure as user data —
// the layout of [MS-RDPBCGR] §2.2.1.2. LI counts every TPDU byte after
// itself, the way Microsoft's servers send it.
func buildConnConfirm(neg []byte) []byte {
	tpdu := []byte{0x00, x224CC, 0x00, 0x00, 0x00, 0x00, 0x00}
	tpdu = append(tpdu, neg...)
	tpdu[0] = byte(len(tpdu) - 1)

	pkt := make([]byte, 4, 4+len(tpdu))
	pkt[0] = tpktVersion
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(tpdu)))
	return append(pkt, tpdu...)
}

// negRsp builds an RDP_NEG_RSP selecting the given protocol
// ([MS-RDPBCGR] §2.2.1.2.1).
func negRsp(selected uint32) []byte {
	b := make([]byte, 8)
	b[0] = rdpNegRsp
	binary.LittleEndian.PutUint16(b[2:4], 8)
	binary.LittleEndian.PutUint32(b[4:8], selected)
	return b
}

// negFailure builds an RDP_NEG_FAILURE carrying the given code
// ([MS-RDPBCGR] §2.2.1.2.2).
func negFailure(code uint32) []byte {
	b := make([]byte, 8)
	b[0] = rdpNegFailure
	binary.LittleEndian.PutUint16(b[2:4], 8)
	binary.LittleEndian.PutUint32(b[4:8], code)
	return b
}

func TestParseRDPConnConfirm(t *testing.T) {
	cases := []struct {
		name    string
		b       []byte
		wantNLA bool
	}{
		{
			// The hardened posture: CredSSP selected, authentication
			// happens before any session exists.
			"hybrid selected means NLA enforced",
			buildConnConfirm(negRsp(protoHybrid)),
			true,
		},
		{
			"ssl and hybrid selected means NLA enforced",
			buildConnConfirm(negRsp(protoSSL | protoHybrid)),
			true,
		},
		{
			"hybrid with early user auth means NLA enforced",
			buildConnConfirm(negRsp(protoHybrid | protoHybridEx)),
			true,
		},
		{
			// Only valid alongside HYBRID, but a server setting it
			// alone still means CredSSP.
			"hybrid ex alone still means NLA",
			buildConnConfirm(negRsp(protoHybridEx)),
			true,
		},
		{
			// TLS without CredSSP: encrypted channel, but the logon
			// screen is reachable unauthenticated.
			"ssl selected means NLA not enforced",
			buildConnConfirm(negRsp(protoSSL)),
			false,
		},
		{
			// The server picked Standard RDP Security despite the
			// enhanced offer.
			"standard rdp security selected means no NLA",
			buildConnConfirm(negRsp(protoRDP)),
			false,
		},
		{
			// No CredSSP in RDSTLS — and the probe never offers it, so
			// a server selecting it is already odd.
			"rdstls selected means no NLA",
			buildConnConfirm(negRsp(protoRDSTLS)),
			false,
		},
		{
			// Bare Connection Confirm: a pre-negotiation host (or
			// default xrdp) ignored the RDP_NEG_REQ — only legacy RDP
			// security exists, so NLA cannot be enforced.
			"bare confirm means legacy server without NLA",
			buildConnConfirm(nil),
			false,
		},
	}
	for _, c := range cases {
		nla, err := parseRDPConnConfirm(c.b)
		if err != nil {
			t.Errorf("%s: parseRDPConnConfirm err = %v, want nil", c.name, err)
			continue
		}
		if nla != c.wantNLA {
			t.Errorf("%s: parseRDPConnConfirm = %v, want %v", c.name, nla, c.wantNLA)
		}
	}
}

func TestParseRDPConnConfirmFailures(t *testing.T) {
	// Every documented RDP_NEG_FAILURE code ([MS-RDPBCGR] §2.2.1.2.2)
	// must surface by name, never as a bare number.
	codes := []struct {
		code uint32
		name string
	}{
		{1, "SSL_REQUIRED_BY_SERVER"},
		{2, "SSL_NOT_ALLOWED_BY_SERVER"},
		{3, "SSL_CERT_NOT_ON_SERVER"},
		{4, "INCONSISTENT_FLAGS"},
		{5, "HYBRID_REQUIRED_BY_SERVER"},
		{6, "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"},
	}
	for _, c := range codes {
		_, err := parseRDPConnConfirm(buildConnConfirm(negFailure(c.code)))
		if err == nil {
			t.Errorf("failure code %d: err = nil, want %s", c.code, c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("failure code %d: err = %q, want substring %q", c.code, err, c.name)
		}
	}

	// Codes beyond the table are kept as hex.
	if _, err := parseRDPConnConfirm(buildConnConfirm(negFailure(0x42))); err == nil ||
		!strings.Contains(err.Error(), "0x00000042") {
		t.Errorf("unknown failure code: err = %v, want hex rendering", err)
	}
}

func TestParseRDPConnConfirmErrors(t *testing.T) {
	// The length field disagrees with the captured bytes.
	badTPKTLen := buildConnConfirm(nil)
	badTPKTLen[3]++

	// A CR (0xE0) where a CC belongs — e.g. our own request echoed back.
	crEcho := buildConnConfirm(nil)
	crEcho[5] = x224CR

	// The server refused the connection before negotiating.
	dr := buildConnConfirm(nil)
	dr[5] = x224DR

	// LI claims more header than the packet holds.
	badLI := buildConnConfirm(nil)
	badLI[4] = 0x40

	// Negotiation structure cut short.
	shortNeg := buildConnConfirm([]byte{rdpNegRsp, 0x00, 0x08})

	// Declared structure length other than 8.
	wrongNegLen := buildConnConfirm([]byte{rdpNegRsp, 0x00, 0x10, 0x00, 1, 0, 0, 0})

	// A type byte outside the RDP_NEG_* table.
	unknownNegType := buildConnConfirm([]byte{0x07, 0x00, 0x08, 0x00, 0, 0, 0, 0})

	cases := []struct {
		name        string
		b           []byte
		wantErrPart string
	}{
		{"empty reply", nil, "at least 11"},
		{"tpkt version wrong", append([]byte{0x09}, buildConnConfirm(nil)[1:]...), "not a TPKT"},
		{"tpkt length mismatch", badTPKTLen, "declares"},
		{"connection request echoed back", crEcho, "not a Connection Confirm"},
		{"disconnect request is a plain rejection", dr, "rejected the connection"},
		{"length indicator out of bounds", badLI, "length indicator"},
		{"negotiation structure truncated", shortNeg, "want 8"},
		{"negotiation structure declares wrong length", wrongNegLen, "declares 16 bytes"},
		{"unknown negotiation type", unknownNegType, "type 0x07"},
	}
	for _, c := range cases {
		_, err := parseRDPConnConfirm(c.b)
		if err == nil {
			t.Errorf("%s: parseRDPConnConfirm err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: parseRDPConnConfirm err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

func TestBuildRDPConnRequest(t *testing.T) {
	// The exact 19 bytes of a Connection Request offering
	// SSL|HYBRID|HYBRID_EX: TPKT (03, reserved, BE length 19), X.224 CR
	// (LI 14, code E0, refs 0, class 0), RDP_NEG_REQ (type 1, flags 0,
	// LE length 8, LE protocols 0x0B) — [MS-RDPBCGR] §2.2.1.1.1.
	want := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00,
	}
	if got := buildRDPConnRequest(); !bytes.Equal(got, want) {
		t.Errorf("buildRDPConnRequest = %x, want %x", got, want)
	}
}

func TestReadTPKT(t *testing.T) {
	pkt := buildConnConfirm(negRsp(protoHybrid))
	got, err := readTPKT(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("readTPKT: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Errorf("readTPKT = %x, want %x", got, pkt)
	}
}

func TestReadTPKTErrors(t *testing.T) {
	// Declares 19 bytes, stream ends right after the header.
	truncated := []byte{0x03, 0x00, 0x00, 0x13}
	// Length smaller than the header itself.
	tiny := []byte{0x03, 0x00, 0x00, 0x03}

	cases := []struct {
		name        string
		b           []byte
		wantErrPart string
	}{
		{"empty stream", nil, "EOF"},
		{"short header", []byte{0x03, 0x00}, "EOF"},
		{"not a tpkt version", []byte{0x07, 0x00, 0x00, 0x04}, "not a TPKT"},
		{"length smaller than header", tiny, "implausible"},
		{"truncated body", truncated, "EOF"},
	}
	for _, c := range cases {
		_, err := readTPKT(bytes.NewReader(c.b))
		if err == nil {
			t.Errorf("%s: readTPKT err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: readTPKT err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

// TestProbeRDPAgainstScriptedServer runs the whole probe — dial, write,
// read, parse — against a loopback listener playing a one-shot RDP
// server, for each of the three server behaviors that matter. Hermetic:
// loopback only, no external network.
func TestProbeRDPAgainstScriptedServer(t *testing.T) {
	cases := []struct {
		name        string
		reply       []byte
		wantNLA     *bool
		wantErrPart string
	}{
		{"hybrid selected", buildConnConfirm(negRsp(protoHybrid)), ptr(true), ""},
		{"ssl only selected", buildConnConfirm(negRsp(protoSSL)), ptr(false), ""},
		{"bare confirm from legacy server", buildConnConfirm(nil), ptr(false), ""},
		{"negotiation failure", buildConnConfirm(negFailure(5)), nil, "HYBRID_REQUIRED_BY_SERVER"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				// Reading the request with our own reader also proves
				// the probe's framing is a parseable TPKT.
				req, err := readTPKT(conn)
				if err != nil || len(req) < 6 || req[5] != x224CR {
					return
				}
				_, _ = conn.Write(c.reply)
			}()

			port := ln.Addr().(*net.TCPAddr).Port
			info := probeRDP("127.0.0.1", port, 5*time.Second)
			if !info.Probed {
				t.Error("Probed = false, want true")
			}
			if c.wantErrPart != "" {
				if !strings.Contains(info.Error, c.wantErrPart) {
					t.Errorf("Error = %q, want substring %q", info.Error, c.wantErrPart)
				}
				if info.NLA != nil {
					t.Errorf("NLA = %v, want nil on negotiation failure", *info.NLA)
				}
				return
			}
			if info.Error != "" {
				t.Errorf("Error = %q, want empty", info.Error)
			}
			if info.NLA == nil || *info.NLA != *c.wantNLA {
				t.Errorf("NLA = %v, want %v", info.NLA, *c.wantNLA)
			}
		})
	}
}

func ptr(b bool) *bool { return &b }

func TestProbeRDPConnectionRefused(t *testing.T) {
	// Grab a loopback port and release it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	info := probeRDP("127.0.0.1", port, 2*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error == "" {
		t.Error("Error = empty, want dial failure recorded")
	}
	if info.NLA != nil {
		t.Errorf("NLA = %v, want nil on dial failure", *info.NLA)
	}
}
