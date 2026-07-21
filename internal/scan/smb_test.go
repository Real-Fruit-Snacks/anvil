package scan

import (
	"encoding/binary"
	"testing"

	"github.com/mandiant/gopacket/pkg/ntlm"
)

func TestSMBDialectString(t *testing.T) {
	cases := []struct {
		dialect uint16
		want    string
	}{
		{smb2Dialect002, "SMB 2.0.2"},
		{smb2Dialect21, "SMB 2.1"},
		{smb2Dialect30, "SMB 3.0"},
		{smb2Dialect302, "SMB 3.0.2"},
		{smb2Dialect311, "SMB 3.1.1"},
		{0x9999, "0x9999"},
	}
	for _, c := range cases {
		if got := smbDialectString(c.dialect); got != c.want {
			t.Errorf("smbDialectString(0x%04x) = %q, want %q", c.dialect, got, c.want)
		}
	}
}

func TestParseSMB2NegotiateResponse(t *testing.T) {
	// 64-byte SMB2 header + 65-byte negotiate response body.
	buf := make([]byte, 64+65)
	binary.LittleEndian.PutUint16(buf[66:68], 0x0003)         // securityMode: enabled|required
	binary.LittleEndian.PutUint16(buf[68:70], smb2Dialect311) // dialect

	dialect, secMode, err := parseSMB2NegotiateResponse(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if dialect != smb2Dialect311 {
		t.Errorf("dialect = 0x%04x, want 0x0311", dialect)
	}
	if secMode != 0x0003 {
		t.Errorf("securityMode = 0x%04x, want 0x0003", secMode)
	}

	// Short buffer must error, not panic.
	for _, n := range []int{0, 63, 64, 100, 128} {
		if _, _, err := parseSMB2NegotiateResponse(buf[:n]); err == nil {
			t.Errorf("short buffer (%d bytes): expected error", n)
		}
	}
}

func TestParseSMB1SecurityMode(t *testing.T) {
	buf := make([]byte, 39)
	buf[32] = 17   // wordCount
	buf[35] = 0x08 // params[2] = security mode: signatures required

	mode, err := parseSMB1SecurityMode(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if mode != 0x08 {
		t.Errorf("mode = 0x%02x, want 0x08", mode)
	}

	if _, err := parseSMB1SecurityMode(buf[:20]); err == nil {
		t.Error("short buffer: expected error")
	}

	bad := make([]byte, 39)
	bad[32] = 4 // wordCount < 17
	if _, err := parseSMB1SecurityMode(bad); err == nil {
		t.Error("low wordCount: expected error")
	}
}

// utf16ASCII encodes a string as UTF-16LE (test fixture helper; ASCII only).
func utf16ASCII(s string) []byte {
	out := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		out[i*2] = s[i]
	}
	return out
}

// buildNTLMType2 hand-crafts an NTLM Type 2 message with the given AV pairs
// and OS version bytes, matching the layout parseNTLMChallenge expects.
func buildNTLMType2(pairs map[uint16]string, major, minor byte, build uint16) []byte {
	var ti []byte
	ids := []uint16{ntlm.MsvAvNbDomainName, ntlm.MsvAvNbComputerName,
		ntlm.MsvAvDnsComputerName, ntlm.MsvAvDnsDomainName}
	for _, id := range ids {
		v, ok := pairs[id]
		if !ok {
			continue
		}
		data := utf16ASCII(v)
		ti = binary.LittleEndian.AppendUint16(ti, id)
		ti = binary.LittleEndian.AppendUint16(ti, uint16(len(data)))
		ti = append(ti, data...)
	}
	ti = binary.LittleEndian.AppendUint16(ti, ntlm.MsvAvEOL)
	ti = binary.LittleEndian.AppendUint16(ti, 0)

	msg := make([]byte, 56+len(ti))
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(ti)))
	binary.LittleEndian.PutUint32(msg[44:48], 56)
	msg[48] = major
	msg[49] = minor
	binary.LittleEndian.PutUint16(msg[50:52], build)
	copy(msg[56:], ti)
	return msg
}

func TestParseNTLMChallenge(t *testing.T) {
	msg := buildNTLMType2(map[uint16]string{
		ntlm.MsvAvNbDomainName:    "LAB",
		ntlm.MsvAvNbComputerName:  "DC01",
		ntlm.MsvAvDnsComputerName: "dc01.lab.local",
		ntlm.MsvAvDnsDomainName:   "lab.local",
	}, 10, 0, 19041)

	var info SMBInfo
	parseNTLMChallenge(msg, &info)

	if info.OSVersion != "Windows NT 10.0 Build 19041" {
		t.Errorf("OSVersion = %q, want Windows NT 10.0 Build 19041", info.OSVersion)
	}
	if info.NBDomain != "LAB" {
		t.Errorf("NBDomain = %q, want LAB", info.NBDomain)
	}
	if info.NBComputer != "DC01" {
		t.Errorf("NBComputer = %q, want DC01", info.NBComputer)
	}
	if info.DNSComputer != "dc01.lab.local" {
		t.Errorf("DNSComputer = %q, want dc01.lab.local", info.DNSComputer)
	}
	if info.DNSDomain != "lab.local" {
		t.Errorf("DNSDomain = %q, want lab.local", info.DNSDomain)
	}
}

func TestParseNTLMChallengeShort(t *testing.T) {
	// Must not panic on truncated messages.
	var info SMBInfo
	parseNTLMChallenge([]byte("NTLMSSP\x00short"), &info)
	if info.OSVersion != "" || info.NBDomain != "" {
		t.Error("short message should yield no fields")
	}
}

func TestFiletimeToUnix(t *testing.T) {
	cases := []struct {
		name string
		ft   uint64
		want int64
	}{
		// FILETIME epoch (1601-01-01) maps to the negative Unix offset.
		{"zero FILETIME", 0, -11644473600},
		// Exact Unix epoch boundary: 11644473600 seconds of 100-ns ticks.
		{"unix epoch boundary", 116444736000000000, 0},
		// 2026-01-01T00:00:00Z = unix 1767225600.
		{"known 2026 date", 134116992000000000, 1767225600},
		// Sub-second ticks are truncated, not rounded.
		{"sub-second ticks dropped", 116444736000000000 + 9999999, 0},
	}
	for _, c := range cases {
		if got := filetimeToUnix(c.ft); got != c.want {
			t.Errorf("%s: filetimeToUnix(%d) = %d, want %d", c.name, c.ft, got, c.want)
		}
	}
}

func TestSMB2NegotiateSystemTime(t *testing.T) {
	// 64-byte SMB2 header + 65-byte negotiate response body; SystemTime is
	// the FILETIME at body offset 40 (absolute offset 104), after
	// MaxReadSize (body 32) and MaxWriteSize (body 36). The Max* sizes get
	// sentinel values so reading SystemTime from the wrong offset fails.
	buf := make([]byte, 64+65)
	binary.LittleEndian.PutUint32(buf[64+32:64+36], 0x00800000)
	binary.LittleEndian.PutUint32(buf[64+36:64+40], 0x00800000)
	binary.LittleEndian.PutUint64(buf[104:112], 134116992000000000)

	ft, err := smb2NegotiateSystemTime(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ft != 134116992000000000 {
		t.Errorf("SystemTime = %d, want 134116992000000000", ft)
	}

	// Short buffers must error, not panic.
	for _, n := range []int{0, 63, 64, 96, 104, 111} {
		if _, err := smb2NegotiateSystemTime(buf[:n]); err == nil {
			t.Errorf("short buffer (%d bytes): expected error", n)
		}
	}
}
