package smbclient

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/srvsvc"

	"anvil/internal/ui"
)

// Server clock retrieval (NetrRemoteTOD over srvsvc) and NTP offset
// measurement (for --sync-clock). NetrRemoteTOD rides the existing SMB
// session; NTP is one transient UDP exchange, announced on screen like
// every other extra channel anvil opens.

// opNetrRemoteTOD is the SRVSVC opnum for NetrRemoteTOD ([MS-SRVS]
// 3.1.4.7). gopacket's pkg/dcerpc/srvsvc wraps only NetrSessionEnum and
// NetrServerGetInfo, so the call is marshaled here directly — the same
// approach services.go takes for REnumServicesStatusW.
const opNetrRemoteTOD = 28

// timeOfDayInfo mirrors MS-DTYP TIME_OF_DAY_INFO: twelve little-endian
// dwords in wire order. elapsedt is the server's clock as seconds since
// 1970-01-01 GMT; msecs counts milliseconds since boot (uptime); timezone
// is the minutes to ADD to local time to get GMT (positive west of
// Greenwich, -1 = unknown); tinterval is the clock tick in 100ns units.
type timeOfDayInfo struct {
	elapsedt  uint32
	msecs     uint32
	hours     uint32
	mins      uint32
	secs      uint32
	hunds     uint32
	timezone  int32
	tinterval uint32
	day       uint32
	month     uint32
	year      uint32
	weekday   uint32
}

// ServerTimeInfo is the server's clock as NetrRemoteTOD reports it.
type ServerTimeInfo struct {
	Time      time.Time     // server wall clock, in the server's own time zone
	UTCOffset time.Duration // offset of Time's zone east of UTC (from tod_timezone)
	Uptime    time.Duration // time since the server booted (tod_msecs)
}

// ServerTime returns the server's current wall clock in its own time zone.
func (s *Session) ServerTime() (time.Time, error) {
	info, err := s.ServerTimeInfo()
	if err != nil {
		return time.Time{}, err
	}
	return info.Time, nil
}

// ServerTimeInfo queries the server's clock, time zone, and uptime via
// NetrRemoteTOD (SRVSVC opnum 28) on the session's IPC$ srvsvc pipe — the
// RPC `net time \\host` has used since LAN Manager. It rides the existing
// SMB session, so no extra channel is opened and any authenticated user
// (not just admins) can call it.
func (s *Session) ServerTimeInfo() (ServerTimeInfo, error) {
	pipe, err := s.client.OpenPipe("srvsvc")
	if err != nil {
		return ServerTimeInfo{}, fmt.Errorf("open srvsvc pipe: %v", err)
	}
	defer pipe.Close()

	// Plain bind + plain call: over an authenticated SMB pipe srvsvc needs
	// no RPC-level auth (same reasoning as services.go's SVCCTL traffic).
	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(srvsvc.UUID, srvsvc.MajorVersion, srvsvc.MinorVersion); err != nil {
		return ServerTimeInfo{}, fmt.Errorf("bind srvsvc: %v", err)
	}

	// ServerName is a [unique, string] SRVSVC_HANDLE; NULL selects the
	// pipe's own server (accepted by Windows and Samba alike), so the
	// request stub is a bare 4-byte NULL pointer with no string payload.
	resp, err := rpc.Call(opNetrRemoteTOD, []byte{0, 0, 0, 0})
	if err != nil {
		return ServerTimeInfo{}, mapServerTimeError(err)
	}
	tod, err := parseRemoteTOD(resp)
	if err != nil {
		return ServerTimeInfo{}, err
	}
	return tod.serverTimeInfo(), nil
}

// parseRemoteTOD parses a NetrRemoteTOD response: a 4-byte pointer
// referent, the 48-byte TIME_OF_DAY_INFO, and the trailing 4-byte
// NET_API_STATUS return value.
func parseRemoteTOD(resp []byte) (timeOfDayInfo, error) {
	var tod timeOfDayInfo
	if len(resp) < 56 {
		return tod, fmt.Errorf("NetrRemoteTOD response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 {
		return tod, mapServerTimeError(fmt.Errorf("NTSTATUS 0x%08x", ret))
	}
	if binary.LittleEndian.Uint32(resp[0:4]) == 0 {
		return tod, fmt.Errorf("NetrRemoteTOD returned no time-of-day data")
	}
	b := resp[4:52]
	tod = timeOfDayInfo{
		elapsedt:  binary.LittleEndian.Uint32(b[0:4]),
		msecs:     binary.LittleEndian.Uint32(b[4:8]),
		hours:     binary.LittleEndian.Uint32(b[8:12]),
		mins:      binary.LittleEndian.Uint32(b[12:16]),
		secs:      binary.LittleEndian.Uint32(b[16:20]),
		hunds:     binary.LittleEndian.Uint32(b[20:24]),
		timezone:  int32(binary.LittleEndian.Uint32(b[24:28])),
		tinterval: binary.LittleEndian.Uint32(b[28:32]),
		day:       binary.LittleEndian.Uint32(b[32:36]),
		month:     binary.LittleEndian.Uint32(b[36:40]),
		year:      binary.LittleEndian.Uint32(b[40:44]),
		weekday:   binary.LittleEndian.Uint32(b[44:48]),
	}
	return tod, nil
}

// serverTimeInfo converts the wire fields to Go time values. The wall clock
// is built from elapsedt (authoritative UTC) rendered in the server's zone
// rather than from the broken-down fields, so date/time and zone can never
// disagree; Windows folds the current DST bias into tod_timezone, so the
// derived zone matches the server's displayed local time. An unknown zone
// (timezone == -1) falls back to UTC.
func (t timeOfDayInfo) serverTimeInfo() ServerTimeInfo {
	utc := time.Unix(int64(t.elapsedt), 0).UTC()
	if t.timezone == -1 {
		return ServerTimeInfo{Time: utc, UTCOffset: 0, Uptime: t.uptime()}
	}
	offset := -time.Duration(t.timezone) * time.Minute
	return ServerTimeInfo{
		Time:      utc.In(time.FixedZone("", int(offset.Seconds()))),
		UTCOffset: offset,
		Uptime:    t.uptime(),
	}
}

// uptime renders msecs (milliseconds since boot) as a Duration.
func (t timeOfDayInfo) uptime() time.Duration {
	return time.Duration(t.msecs) * time.Millisecond
}

// mapServerTimeError renders NetrRemoteTOD failures as short themed
// one-liners (feature-local mapping; raw RPC/Win32 codes stay out of the
// UI). Code strings match the renderings Describe() already relies on.
func mapServerTimeError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x00000005"):
		return fmt.Errorf("access denied")
	case strings.Contains(msg, "0x1c010002"):
		// DCE/RPC nca_s_op_rng_error — interface bound but opnum not
		// implemented (e.g. a stub-only srvsvc).
		return fmt.Errorf("not supported on this server (unknown RPC opnum)")
	case strings.Contains(msg, "0x000006f7"):
		// EPT_S_NOT_REGISTERED — bound, but the backend op isn't functional.
		return fmt.Errorf("not supported on this server (RPC op not registered)")
	}
	return err
}

// --- NTP clock sync (backs the --sync-clock connect flag) ---

const (
	// ntpEpoch is the seconds between the NTP epoch (1900-01-01) and the
	// Unix epoch (1970-01-01) — RFC 5905 §7.3 timestamp arithmetic.
	ntpEpoch      = 2208988800
	ntpPacketSize = 48
)

// NTPOffset measures the clock offset between this machine and server
// (normally the DC: --dc-ip when given, else --host) with a single NTPv3
// client query to UDP 123. The return value is server-minus-local: adding
// it to the local clock yields the server's clock. One transient UDP
// exchange, announced on screen per anvil's extra-channel discipline. DCs
// serve NTP by default (w32time), so no target-side setup is needed.
func NTPOffset(server string, timeout time.Duration) (time.Duration, error) {
	ui.Faint.Printf("  querying NTP time from %s (UDP 123)\n", server)
	// NTP on a reachable LAN answers in milliseconds; cap the wait so a
	// cranked-up --timeout doesn't stall the connect on a filtered port.
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	offset, _, err := ntpExchange(server, timeout)
	return offset, err
}

// ntpExchange performs the UDP round trip and hands the response to the
// pure parser (kept separate so the packet math is unit-testable).
func ntpExchange(server string, timeout time.Duration) (offset, rtt time.Duration, err error) {
	addr := net.JoinHostPort(server, "123")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot reach NTP server %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	t1 := time.Now()
	if _, err := conn.Write(buildNTPRequest(t1)); err != nil {
		return 0, 0, fmt.Errorf("NTP query to %s failed: %v", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, 0, mapNTPError(err, server)
	}
	return parseNTPResponse(buf[:n], t1, time.Now())
}

// buildNTPRequest marshals a 48-byte NTPv3 client request (RFC 5905 §7.3):
// LI=0/VN=3/Mode=3 in the first byte and the local clock in the transmit
// timestamp; everything else zero.
func buildNTPRequest(t1 time.Time) []byte {
	req := make([]byte, ntpPacketSize)
	req[0] = 0x1b // 00 011 011
	sec, frac := toNTPTimestamp(t1)
	binary.BigEndian.PutUint32(req[40:44], sec)
	binary.BigEndian.PutUint32(req[44:48], frac)
	return req
}

// parseNTPResponse computes the clock offset and round-trip delay from a
// server response (RFC 5905 §8):
//
//	theta = ((t2 - t1) + (t3 - t4)) / 2
//	delta = (t4 - t1) - (t3 - t2)
//
// t1/t4 are the local send/receive times, t2/t3 the server's receive and
// transmit timestamps. The offset is server-minus-local.
func parseNTPResponse(resp []byte, t1, t4 time.Time) (offset, rtt time.Duration, err error) {
	if len(resp) < ntpPacketSize {
		return 0, 0, fmt.Errorf("NTP response too short (%d bytes)", len(resp))
	}
	if mode := resp[0] & 0x7; mode != 4 && mode != 5 { // 4 = server, 5 = broadcast
		return 0, 0, fmt.Errorf("not an NTP server response (mode %d)", mode)
	}
	if resp[1] == 0 {
		// Stratum 0 is a Kiss-o'-Death; the refid says why (RATE, DENY, ...).
		refid := strings.TrimRight(string(resp[12:16]), "\x00")
		return 0, 0, fmt.Errorf("NTP server refused the query (kiss-o'-death %q)", refid)
	}
	rsec, rfrac := binary.BigEndian.Uint32(resp[32:36]), binary.BigEndian.Uint32(resp[36:40])
	tsec, tfrac := binary.BigEndian.Uint32(resp[40:44]), binary.BigEndian.Uint32(resp[44:48])
	if tsec == 0 && tfrac == 0 {
		return 0, 0, fmt.Errorf("NTP response carries no transmit timestamp")
	}
	t2 := fromNTPTimestamp(rsec, rfrac)
	t3 := fromNTPTimestamp(tsec, tfrac)
	offset = (t2.Sub(t1) + t3.Sub(t4)) / 2
	rtt = t4.Sub(t1) - t3.Sub(t2)
	return offset, rtt, nil
}

// toNTPTimestamp converts a Go time to the NTP 64-bit timestamp format:
// seconds since 1900-01-01 in the high word, 1/2^32-second fractions below.
func toNTPTimestamp(t time.Time) (sec, frac uint32) {
	u := t.UnixNano()
	sec = uint32(u/int64(time.Second) + ntpEpoch)
	frac = uint32((u % int64(time.Second)) * (1 << 32) / int64(time.Second))
	return sec, frac
}

// fromNTPTimestamp is the inverse of toNTPTimestamp.
func fromNTPTimestamp(sec, frac uint32) time.Time {
	s := int64(sec) - ntpEpoch
	ns := int64(frac) * int64(time.Second) >> 32
	return time.Unix(s, ns).UTC()
}

// mapNTPError renders NTP transport failures as short themed one-liners.
func mapNTPError(err error, server string) error {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return fmt.Errorf("no NTP answer from %s (UDP 123 filtered, or w32time not serving)", server)
	}
	return fmt.Errorf("NTP query to %s failed: %v", server, err)
}
