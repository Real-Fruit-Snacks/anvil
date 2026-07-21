package smbclient

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// buildTODResponse marshals a synthetic NetrRemoteTOD response: pointer
// referent + 48-byte TIME_OF_DAY_INFO + NET_API_STATUS trailer.
func buildTODResponse(t *testing.T, tod timeOfDayInfo, retVal uint32) []byte {
	t.Helper()
	resp := make([]byte, 56)
	binary.LittleEndian.PutUint32(resp[0:4], 0x00020000) // non-NULL referent
	b := resp[4:52]
	binary.LittleEndian.PutUint32(b[0:4], tod.elapsedt)
	binary.LittleEndian.PutUint32(b[4:8], tod.msecs)
	binary.LittleEndian.PutUint32(b[8:12], tod.hours)
	binary.LittleEndian.PutUint32(b[12:16], tod.mins)
	binary.LittleEndian.PutUint32(b[16:20], tod.secs)
	binary.LittleEndian.PutUint32(b[20:24], tod.hunds)
	binary.LittleEndian.PutUint32(b[24:28], uint32(tod.timezone))
	binary.LittleEndian.PutUint32(b[28:32], tod.tinterval)
	binary.LittleEndian.PutUint32(b[32:36], tod.day)
	binary.LittleEndian.PutUint32(b[36:40], tod.month)
	binary.LittleEndian.PutUint32(b[40:44], tod.year)
	binary.LittleEndian.PutUint32(b[44:48], tod.weekday)
	binary.LittleEndian.PutUint32(resp[52:56], retVal)
	return resp
}

func TestParseRemoteTOD(t *testing.T) {
	// 2026-07-20 12:00:00 UTC on a server in UTC-5 (e.g. US Eastern in
	// standard time): tod_timezone = 300 minutes to add for GMT.
	utc := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	base := timeOfDayInfo{
		elapsedt: uint32(utc.Unix()),
		msecs:    42_123_456, // ~11.7h uptime
		hours:    7, mins: 0, secs: 0, hunds: 0,
		timezone:  300,
		tinterval: 156_250,
		day:       20, month: 7, year: 2026, weekday: 0,
	}

	t.Run("parses fields and derives zone", func(t *testing.T) {
		tod, err := parseRemoteTOD(buildTODResponse(t, base, 0))
		if err != nil {
			t.Fatalf("parseRemoteTOD: %v", err)
		}
		if tod.elapsedt != uint32(utc.Unix()) || tod.timezone != 300 || tod.year != 2026 {
			t.Fatalf("wrong fields: %+v", tod)
		}

		info := tod.serverTimeInfo()
		// UTC-5 → wall clock is 07:00, offset rendered as -5h.
		want := time.Date(2026, 7, 20, 7, 0, 0, 0, time.FixedZone("", -5*3600))
		if !info.Time.Equal(want) || info.Time.Format("15:04") != "07:00" {
			t.Errorf("Time = %v, want %v", info.Time, want)
		}
		if info.UTCOffset != -5*time.Hour {
			t.Errorf("UTCOffset = %v, want -5h0m0s", info.UTCOffset)
		}
		if info.Uptime != 42123456*time.Millisecond {
			t.Errorf("Uptime = %v, want %v", info.Uptime, 42123456*time.Millisecond)
		}
	})

	t.Run("negative timezone (east of Greenwich)", func(t *testing.T) {
		// UTC+1 (e.g. Berlin winter): GMT = local + (-60) minutes.
		tod := base
		tod.timezone = -60
		info := tod.serverTimeInfo()
		if info.UTCOffset != time.Hour || info.Time.Format("15:04") != "13:00" {
			t.Errorf("Time = %v offset %v, want 13:00 +1h", info.Time, info.UTCOffset)
		}
	})

	t.Run("unknown timezone falls back to UTC", func(t *testing.T) {
		tod := base
		tod.timezone = -1
		info := tod.serverTimeInfo()
		if info.UTCOffset != 0 || info.Time.Format("15:04") != "12:00" {
			t.Errorf("Time = %v offset %v, want 12:00 UTC", info.Time, info.UTCOffset)
		}
	})

	t.Run("error cases", func(t *testing.T) {
		cases := []struct {
			name    string
			resp    []byte
			wantErr string
		}{
			{"short response", make([]byte, 40), "too short"},
			{"access denied (0x00000005)", buildTODResponse(t, base, 0x00000005), "access denied"},
			{"null info pointer", func() []byte {
				r := buildTODResponse(t, base, 0)
				binary.LittleEndian.PutUint32(r[0:4], 0)
				return r
			}(), "no time-of-day data"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := parseRemoteTOD(tc.resp)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %v, want substring %q", err, tc.wantErr)
				}
			})
		}
	})
}

// buildNTPReply marshals a synthetic 48-byte server response with the given
// first byte, stratum, refid, and receive/transmit timestamps.
func buildNTPReply(firstByte, stratum byte, refid string, t2, t3 time.Time) []byte {
	resp := make([]byte, ntpPacketSize)
	resp[0] = firstByte
	resp[1] = stratum
	copy(resp[12:16], refid)
	rs, rf := toNTPTimestamp(t2)
	ts, tf := toNTPTimestamp(t3)
	binary.BigEndian.PutUint32(resp[32:36], rs)
	binary.BigEndian.PutUint32(resp[36:40], rf)
	binary.BigEndian.PutUint32(resp[40:44], ts)
	binary.BigEndian.PutUint32(resp[44:48], tf)
	return resp
}

func TestNTPTimestampConversion(t *testing.T) {
	cases := []struct {
		name string
		time time.Time
		sec  uint32
	}{
		{"unix epoch maps to NTP epoch", time.Unix(0, 0).UTC(), ntpEpoch},
		{"known instant", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), 3786825600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sec, frac := toNTPTimestamp(tc.time)
			if sec != tc.sec || frac != 0 {
				t.Errorf("toNTPTimestamp = (%d, %d), want (%d, 0)", sec, frac, tc.sec)
			}
			if got := fromNTPTimestamp(sec, frac); !got.Equal(tc.time) {
				t.Errorf("round trip = %v, want %v", got, tc.time)
			}
		})
	}

	t.Run("sub-second precision survives", func(t *testing.T) {
		now := time.Unix(1784300000, 123456789).UTC()
		sec, frac := toNTPTimestamp(now)
		got := fromNTPTimestamp(sec, frac)
		// 2^-32 s resolution: tolerate 1ns of quantization error.
		if d := got.Sub(now); d < -1 || d > 1 {
			t.Errorf("round trip off by %v", d)
		}
	})
}

func TestNTPOffsetMath(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	// mkResponse lays out one full exchange: server clock is serverOffset
	// ahead of local, each network leg costs delay, the server thinks for
	// think time. It returns the local send/recv times and the reply packet.
	mkResponse := func(serverOffset, delay, think time.Duration) (time.Time, time.Time, []byte) {
		t1 := base
		t2 := t1.Add(delay).Add(serverOffset)
		t3 := t2.Add(think)
		t4 := t3.Add(delay).Add(-serverOffset)
		return t1, t4, buildNTPReply(0x1c, 2, "LOCL", t2, t3) // LI=0 VN=3 Mode=4
	}

	cases := []struct {
		name         string
		serverOffset time.Duration
		delay        time.Duration
		think        time.Duration
	}{
		{"server ahead by 2 minutes", 2 * time.Minute, 40 * time.Millisecond, 20 * time.Millisecond},
		{"server behind by 90 seconds", -90 * time.Second, 15 * time.Millisecond, 5 * time.Millisecond},
		{"clocks agree", 0, 25 * time.Millisecond, 10 * time.Millisecond},
		{"large positive skew", 47*time.Hour + 3*time.Minute, 50 * time.Millisecond, 0},
		{"large negative skew", -26 * time.Hour, 50 * time.Millisecond, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t1, t4, resp := mkResponse(tc.serverOffset, tc.delay, tc.think)
			offset, rtt, err := parseNTPResponse(resp, t1, t4)
			if err != nil {
				t.Fatalf("parseNTPResponse: %v", err)
			}
			// Timestamps quantize to 2^-32 s; allow a millisecond of slack.
			if d := offset - tc.serverOffset; d < -time.Millisecond || d > time.Millisecond {
				t.Errorf("offset = %v, want %v", offset, tc.serverOffset)
			}
			// delta = (t4-t1) - (t3-t2) = (2*delay + think) - think.
			wantRTT := 2 * tc.delay
			if d := rtt - wantRTT; d < -time.Millisecond || d > time.Millisecond {
				t.Errorf("rtt = %v, want %v", rtt, wantRTT)
			}
		})
	}
}

func TestParseNTPResponseErrors(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		resp    []byte
		wantErr string
	}{
		{"short packet", make([]byte, 20), "too short"},
		{"client mode is not a server answer", buildNTPReply(0x1b, 2, "LOCL", base, base), "mode 3"},
		{"kiss-o'-death names the refid", buildNTPReply(0x1c, 0, "RATE", base, base), `kiss-o'-death "RATE"`},
		{"missing transmit timestamp", func() []byte {
			r := buildNTPReply(0x1c, 2, "LOCL", base, base)
			for i := 40; i < 48; i++ {
				r[i] = 0
			}
			return r
		}(), "no transmit timestamp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseNTPResponse(tc.resp, base, base.Add(50*time.Millisecond))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildNTPRequest(t *testing.T) {
	t1 := time.Date(2026, 7, 20, 12, 0, 0, 500000000, time.UTC)
	req := buildNTPRequest(t1)
	if len(req) != ntpPacketSize {
		t.Fatalf("len = %d, want %d", len(req), ntpPacketSize)
	}
	if req[0] != 0x1b {
		t.Errorf("first byte = %#x, want 0x1b (LI=0 VN=3 Mode=3)", req[0])
	}
	// The transmit timestamp must carry t1; originate/receive stay zero.
	sec := binary.BigEndian.Uint32(req[40:44])
	frac := binary.BigEndian.Uint32(req[44:48])
	if got := fromNTPTimestamp(sec, frac); !got.Equal(t1) {
		t.Errorf("transmit timestamp = %v, want %v", got, t1)
	}
	for i := 24; i < 40; i++ {
		if req[i] != 0 {
			t.Errorf("byte %d = %#x, originate/receive timestamps must be zero", i, req[i])
		}
	}
}
