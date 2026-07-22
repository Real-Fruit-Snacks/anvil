package scan

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// tdsVersionToken packs the 6-byte VERSION token data ([MS-TDS]
// §2.2.6.5: major, minor, big-endian build, big-endian sub-build).
func tdsVersionToken(major, minor byte, build, subbuild uint16) []byte {
	v := make([]byte, 6)
	v[0] = major
	v[1] = minor
	binary.BigEndian.PutUint16(v[2:4], build)
	binary.BigEndian.PutUint16(v[4:6], subbuild)
	return v
}

// preloginPayload assembles a well-formed PRELOGIN token stream (no
// packet header) from the given token list, offsets counted from the
// first token byte per the §4.1 sample.
func preloginPayload(tokens ...[]byte) []byte {
	offset := 5*len(tokens) + 1
	var list, data []byte
	for _, t := range tokens {
		n := len(t) - 1 // first byte of each entry is the token type
		list = append(list, t[0], byte(offset>>8), byte(offset), byte(n>>8), byte(n))
		data = append(data, t[1:]...)
		offset += n
	}
	return append(append(list, tdsTokTerminator), data...)
}

// tdsPacket wraps a payload in one TDS packet with the EOM status bit.
func tdsPacket(typ byte, payload []byte) []byte {
	pkt := make([]byte, 8, 8+len(payload))
	pkt[0] = typ
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(8+len(payload)))
	pkt[6] = 1
	return append(pkt, payload...)
}

// preloginReply builds a synthetic server answer: a 0x04 packet whose
// token stream carries VERSION, ENCRYPTION and MARS — the shape a real
// SQL Server returns (it echoes the client's token set minus THREADID).
func preloginReply(version []byte, enc byte) []byte {
	return tdsPacket(tdsPktTabular, preloginPayload(
		append([]byte{tdsTokVersion}, version...),
		[]byte{tdsTokEncrypt, enc},
		[]byte{tdsTokMARS, 0x00},
	))
}

func TestParseTDSPrelogin(t *testing.T) {
	cases := []struct {
		name        string
		payload     []byte
		wantVersion string
		wantEncrypt string
	}{
		{
			// SQL Server 2022 RTM is 16.0.1000.x (KB 321185).
			"sql server 2022 with encryption required",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(16, 0, 1000, 6)...),
				[]byte{tdsTokEncrypt, tdsEncryptReq},
				[]byte{tdsTokMARS, 0x00},
			),
			"16.0.1000", "required",
		},
		{
			// SQL Server 2019 RTM is 15.0.2000.x — the build is the
			// big-endian uint16 in bytes 2:4.
			"sql server 2019 encryption available but off",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(15, 0, 2000, 5)...),
				[]byte{tdsTokEncrypt, tdsEncryptOff},
			),
			"15.0.2000", "off",
		},
		{
			"sql server 2014 encryption on",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(12, 0, 5000, 0)...),
				[]byte{tdsTokEncrypt, tdsEncryptOn},
			),
			"12.0.5000", "on",
		},
		{
			"encryption not supported",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(11, 0, 7001, 0)...),
				[]byte{tdsTokEncrypt, tdsEncryptNotSup},
			),
			"11.0.7001", "not supported",
		},
		{
			// The reserved ENCRYPT_EXT bit (0x20) or anything else
			// unmapped renders verbatim, never silently dropped.
			"unknown encryption byte kept verbatim",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(16, 0, 1000, 0)...),
				[]byte{tdsTokEncrypt, 0x20},
			),
			"16.0.1000", "unknown (0x20)",
		},
		{
			// No ENCRYPTION token: version is still a valid verdict.
			"missing encryption token is not an error",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(13, 0, 4001, 0)...),
			),
			"13.0.4001", "",
		},
		{
			// Tokens the parser does not know (FEDAUTHREQUIRED 0x06 and
			// NONCEOPT 0x07 were added in TDS 7.4) must be skipped, and
			// token order other than VERSION-first must not matter.
			"unknown tokens skipped and order ignored",
			preloginPayload(
				[]byte{0x06, 0x01},
				append([]byte{tdsTokVersion}, tdsVersionToken(14, 0, 1000, 0)...),
				[]byte{0x07, 1, 2, 3, 4},
				[]byte{tdsTokEncrypt, tdsEncryptReq},
			),
			"14.0.1000", "required",
		},
	}
	for _, c := range cases {
		version, encrypt, err := parseTDSPrelogin(c.payload)
		if err != nil {
			t.Errorf("%s: parseTDSPrelogin err = %v, want nil", c.name, err)
			continue
		}
		if version != c.wantVersion || encrypt != c.wantEncrypt {
			t.Errorf("%s: parseTDSPrelogin = (%q, %q), want (%q, %q)", c.name, version, encrypt, c.wantVersion, c.wantEncrypt)
		}
	}
}

func TestParseTDSPreloginErrors(t *testing.T) {
	// A stream whose VERSION token record points past the end of the
	// message: offset 60 with a 6-byte length in a ~30-byte payload.
	badOffset := []byte{
		tdsTokVersion, 0x00, 0x3C, 0x00, 0x06,
		tdsTokTerminator,
		0, 0, 0, 0, 0, 0,
	}

	cases := []struct {
		name        string
		payload     []byte
		wantErrPart string
	}{
		{
			"empty payload has no terminator",
			nil,
			"no TERMINATOR",
		},
		{
			"token record cut short",
			[]byte{tdsTokVersion, 0x00, 0x06},
			"truncated token record",
		},
		{
			"token data offset out of bounds",
			badOffset,
			"runs past the end",
		},
		{
			// Only an ENCRYPTION token: VERSION is the one token
			// [MS-TDS] mandates in every prelogin message.
			"version token missing",
			preloginPayload([]byte{tdsTokEncrypt, tdsEncryptOff}),
			"no VERSION token",
		},
		{
			"version token wrong length",
			preloginPayload(append([]byte{tdsTokVersion}, 9, 0, 0, 0)),
			"VERSION token is 4 bytes",
		},
		{
			"encryption token wrong length",
			preloginPayload(
				append([]byte{tdsTokVersion}, tdsVersionToken(16, 0, 1000, 0)...),
				[]byte{tdsTokEncrypt, 0x00, 0x00},
			),
			"ENCRYPTION token is 2 bytes",
		},
	}
	for _, c := range cases {
		_, _, err := parseTDSPrelogin(c.payload)
		if err == nil {
			t.Errorf("%s: parseTDSPrelogin err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: parseTDSPrelogin err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

func TestBuildTDSPrelogin(t *testing.T) {
	pkt := buildTDSPrelogin()

	// Header ([MS-TDS] §2.2.3.1): type 0x12, EOM set, length counts the
	// header, SPID 0 pre-login, PacketID 1, Window 0.
	if pkt[0] != tdsPktPrelogin {
		t.Errorf("type = 0x%02x, want 0x12 (PRELOGIN)", pkt[0])
	}
	if pkt[1] != tdsStatusEOM {
		t.Errorf("status = 0x%02x, want EOM only (0x01)", pkt[1])
	}
	if got := int(binary.BigEndian.Uint16(pkt[2:4])); got != len(pkt) {
		t.Errorf("declared length = %d, want %d", got, len(pkt))
	}
	if pkt[4] != 0 || pkt[5] != 0 {
		t.Errorf("SPID = %d, want 0 pre-login", binary.BigEndian.Uint16(pkt[4:6]))
	}
	if pkt[6] != 1 || pkt[7] != 0 {
		t.Errorf("PacketID/Window = %d/%d, want 1/0", pkt[6], pkt[7])
	}

	// Round-trip: our own parser must find the client's VERSION (zeros)
	// and ENCRYPT_OFF at the offsets the builder wrote — proves the
	// offset base matches the §4.1 layout the parser assumes.
	version, encrypt, err := parseTDSPrelogin(pkt[8:])
	if err != nil {
		t.Fatalf("parseTDSPrelogin(buildTDSPrelogin payload): %v", err)
	}
	if version != "0.0.0" {
		t.Errorf("client version = %q, want 0.0.0", version)
	}
	if encrypt != "off" {
		t.Errorf("client encryption = %q, want off", encrypt)
	}

	// VERSION must be the first token or the server closes the
	// connection ([MS-TDS] §2.2.6.5, Notes).
	if pkt[8] != tdsTokVersion {
		t.Errorf("first token = 0x%02x, want VERSION (0x00)", pkt[8])
	}
}

func TestReadTDSMessage(t *testing.T) {
	// A message split across two packets: the first carries the EOM bit
	// clear, the second closes the message. Reassembly honors EOM rather
	// than assuming one packet per message.
	p1 := tdsPacket(tdsPktTabular, []byte("token stream part one, "))
	p1[1] = 0x00 // not end of message
	p2 := tdsPacket(tdsPktTabular, []byte("part two"))

	msgType, payload, err := readTDSMessage(bytes.NewReader(append(p1, p2...)))
	if err != nil {
		t.Fatalf("readTDSMessage: %v", err)
	}
	if msgType != tdsPktTabular {
		t.Errorf("msgType = 0x%02x, want 0x04", msgType)
	}
	if string(payload) != "token stream part one, part two" {
		t.Errorf("payload = %q, want concatenated parts", payload)
	}
}

func TestReadTDSMessageErrors(t *testing.T) {
	// Declares 12 bytes but the stream ends after the header.
	truncated := make([]byte, 8)
	binary.BigEndian.PutUint16(truncated[2:4], 12)
	// Length field smaller than the header itself.
	tiny := make([]byte, 8)
	binary.BigEndian.PutUint16(tiny[2:4], 7)

	cases := []struct {
		name        string
		b           []byte
		wantErrPart string
	}{
		{"empty stream", nil, "EOF"},
		{"short header", []byte{0x04, 0x01}, "EOF"},
		{"length smaller than header", tiny, "implausible"},
		{"truncated body", truncated, "EOF"},
	}
	for _, c := range cases {
		_, _, err := readTDSMessage(bytes.NewReader(c.b))
		if err == nil {
			t.Errorf("%s: readTDSMessage err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: readTDSMessage err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

// TestProbeTDSAgainstScriptedServer runs the whole probe — dial, write,
// read, parse — against a loopback listener playing a one-shot SQL
// Server. Hermetic: loopback only, no external network.
func TestProbeTDSAgainstScriptedServer(t *testing.T) {
	reply := preloginReply(tdsVersionToken(16, 0, 1000, 6), tdsEncryptReq)

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
		// Reading the request with our own reader also proves the
		// probe's framing is a parseable TDS message.
		msgType, _, err := readTDSMessage(conn)
		if err != nil || msgType != tdsPktPrelogin {
			return
		}
		_, _ = conn.Write(reply)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	info := probeTDS("127.0.0.1", port, 5*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error != "" {
		t.Errorf("Error = %q, want empty", info.Error)
	}
	if info.Version != "16.0.1000" {
		t.Errorf("Version = %q, want 16.0.1000", info.Version)
	}
	if info.Encrypt != "required" {
		t.Errorf("Encrypt = %q, want required", info.Encrypt)
	}
}

// TestProbeTDSRejectsNonTabularReply: a listener answering with a TDS
// packet type other than 0x04 (e.g. a LOGIN7 0x10 echo) is not a
// prelogin response — the probe says so instead of parsing garbage.
func TestProbeTDSRejectsNonTabularReply(t *testing.T) {
	reply := tdsPacket(0x10, preloginPayload(
		append([]byte{tdsTokVersion}, tdsVersionToken(16, 0, 1000, 0)...),
	))

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
		if _, _, err := readTDSMessage(conn); err != nil {
			return
		}
		_, _ = conn.Write(reply)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	info := probeTDS("127.0.0.1", port, 5*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if !strings.Contains(info.Error, "not the 0x04 table response") {
		t.Errorf("Error = %q, want mention of the 0x04 table response", info.Error)
	}
	if info.Version != "" || info.Encrypt != "" {
		t.Errorf("Version/Encrypt = %q/%q, want both empty on a rejected reply", info.Version, info.Encrypt)
	}
}

func TestProbeTDSConnectionRefused(t *testing.T) {
	// Grab a loopback port and release it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	info := probeTDS("127.0.0.1", port, 2*time.Second)
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error == "" {
		t.Error("Error = empty, want dial failure recorded")
	}
	if info.Version != "" || info.Encrypt != "" {
		t.Errorf("Version/Encrypt = %q/%q, want both empty on dial failure", info.Version, info.Encrypt)
	}
}
