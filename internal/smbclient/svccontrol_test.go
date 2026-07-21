package smbclient

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
)

func TestParseServiceStartType(t *testing.T) {
	cases := []struct {
		in      string
		want    ServiceStartType
		wantErr bool
	}{
		{"disabled", ServiceStartDisabled, false},
		{"DISABLED", ServiceStartDisabled, false},
		{"demand", ServiceStartDemand, false},
		{"manual", ServiceStartDemand, false},
		{"auto", ServiceStartAuto, false},
		{"automatic", ServiceStartAuto, false},
		{" demand ", ServiceStartDemand, false}, // surrounding space tolerated
		{"", 0, true},
		{"boot", 0, true},   // readable, not settable
		{"system", 0, true}, // readable, not settable
		{"demanded", 0, true},
	}
	for _, c := range cases {
		got, err := ParseServiceStartType(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseServiceStartType(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseServiceStartType(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseServiceStartType(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestServiceStartTypeString(t *testing.T) {
	cases := []struct {
		in   ServiceStartType
		want string
	}{
		{ServiceStartBoot, "boot"},
		{ServiceStartSystem, "system"},
		{ServiceStartAuto, "auto"},
		{ServiceStartDemand, "demand"},
		{ServiceStartDisabled, "disabled"},
		{ServiceStartType(0x7), "unknown(0x7)"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("ServiceStartType(%d).String() = %q, want %q", uint32(c.in), got, c.want)
		}
	}
}

func TestServiceConfigStateString(t *testing.T) {
	cases := []struct {
		state uint32
		want  string
	}{
		{svcctl.SERVICE_RUNNING, "RUNNING"},
		{svcctl.SERVICE_STOPPED, "STOPPED"},
		{svcctl.SERVICE_START_PENDING, "START PENDING"},
		{svcctl.SERVICE_PAUSED, "PAUSED"},
		{0xdead, "UNKNOWN"},
	}
	for _, c := range cases {
		cfg := ServiceConfig{Name: "x", State: c.state}
		if got := cfg.StateString(); got != c.want {
			t.Errorf("StateString(%d) = %q, want %q", c.state, got, c.want)
		}
	}
}

// svcStatusResponse builds a synthetic RQueryServiceStatus response:
// SERVICE_STATUS (28 bytes, dwCurrentState at offset 4) + ReturnValue.
func svcStatusResponse(state, ret uint32) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:4], svcctl.SERVICE_WIN32_OWN_PROCESS)
	binary.LittleEndian.PutUint32(b[4:8], state)
	binary.LittleEndian.PutUint32(b[28:32], ret)
	return b
}

func TestParseServiceStatusState(t *testing.T) {
	cases := []struct {
		name    string
		resp    []byte
		want    uint32
		wantErr string // substring; "" means no error
	}{
		{"running", svcStatusResponse(svcctl.SERVICE_RUNNING, 0), svcctl.SERVICE_RUNNING, ""},
		{"stopped", svcStatusResponse(svcctl.SERVICE_STOPPED, 0), svcctl.SERVICE_STOPPED, ""},
		{"access denied", svcStatusResponse(0, svcctl.ERROR_ACCESS_DENIED), 0, "0x00000005"},
		{"too short", make([]byte, 31), 0, "too short"},
		{"empty", nil, 0, "too short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseServiceStatusState(c.resp)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("expected error containing %q, got state=%d err=%v", c.wantErr, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("state = %d, want %d", got, c.want)
			}
		})
	}
}

// svcConfigFixed builds the 36-byte QUERY_SERVICE_CONFIGW fixed part.
func svcConfigFixed(svcType, startType uint32) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint32(b[0:4], svcType)
	binary.LittleEndian.PutUint32(b[4:8], startType)
	binary.LittleEndian.PutUint32(b[8:12], 1) // dwErrorControl
	return b
}

// svcConfigResponse builds a synthetic RQueryServiceConfigW response:
// framing prefix + fixed part + trailer (referent + pcbBytesNeeded + ret).
// Deferred NDR strings are omitted — the parser never reads them.
func svcConfigResponse(prefix []byte, svcType, startType, ret uint32) []byte {
	b := append([]byte{}, prefix...)
	b = append(b, svcConfigFixed(svcType, startType)...)
	trailer := make([]byte, 12)
	binary.LittleEndian.PutUint32(trailer[0:4], 0x00020000) // pcb referent
	binary.LittleEndian.PutUint32(trailer[8:12], ret)
	return append(b, trailer...)
}

func TestParseServiceConfigStartType(t *testing.T) {
	referent := []byte{0x00, 0x00, 0x02, 0x00}              // NDR pointer referent
	refAndCount := append(referent, 0xc8, 0x00, 0x00, 0x00) // referent + maxCount=200
	const ownInteractive = svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_INTERACTIVE_PROCESS

	cases := []struct {
		name    string
		resp    []byte
		want    uint32
		wantErr string // substring; "" means no error
	}{
		{"bare fixed part", svcConfigResponse(nil, ownInteractive, svcctl.SERVICE_DEMAND_START, 0), svcctl.SERVICE_DEMAND_START, ""},
		{"referent prefix", svcConfigResponse(referent, svcctl.SERVICE_WIN32_SHARE_PROCESS, svcctl.SERVICE_AUTO_START, 0), svcctl.SERVICE_AUTO_START, ""},
		{"referent + maxCount prefix", svcConfigResponse(refAndCount, svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DISABLED, 0), svcctl.SERVICE_DISABLED, ""},
		{"error return", svcConfigResponse(nil, ownInteractive, 0, svcctl.ERROR_ACCESS_DENIED), 0, "0x00000005"},
		{"garbage", svcConfigResponse(nil, 0xdeadbeef, 9, 0), 0, "no QUERY_SERVICE_CONFIGW fixed part"},
		{"short of fixed part", make([]byte, 20), 0, "no QUERY_SERVICE_CONFIGW fixed part"},
		{"too short", make([]byte, 11), 0, "too short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseServiceConfigStartType(c.resp)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("expected error containing %q, got startType=%d err=%v", c.wantErr, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("startType = %d, want %d", got, c.want)
			}
		})
	}
}

func TestParseServiceConfigTrailer(t *testing.T) {
	resp := svcConfigResponse(nil, svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_AUTO_START, 0)
	binary.LittleEndian.PutUint32(resp[len(resp)-8:len(resp)-4], 174) // pcbBytesNeeded
	needed, ret, err := parseServiceConfigTrailer(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needed != 174 || ret != 0 {
		t.Errorf("needed=%d ret=%d, want 174/0", needed, ret)
	}
	if _, _, err := parseServiceConfigTrailer(make([]byte, 11)); err == nil {
		t.Error("expected error for short response")
	}
}

func TestPlausibleServiceType(t *testing.T) {
	cases := []struct {
		in   uint32
		want bool
	}{
		{svcctl.SERVICE_WIN32_OWN_PROCESS, true},
		{svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_INTERACTIVE_PROCESS, true},
		{svcctl.SERVICE_KERNEL_DRIVER, true},
		{0, false},
		{0x00020000, false}, // NDR referent ID
		{0xc8, false},       // conformant maxCount
		{0xdeadbeef, false},
	}
	for _, c := range cases {
		if got := plausibleServiceType(c.in); got != c.want {
			t.Errorf("plausibleServiceType(0x%x) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMapSCMError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // exact result message
	}{
		{"nil", nil, ""},
		{"access denied", fmt.Errorf("ROpenServiceW: 0x00000005"), "access denied (admin required)"},
		{"no such service", fmt.Errorf("ROpenServiceW: 0x00000424"), "no such service"},
		{"disabled", fmt.Errorf("RStartServiceW: 0x00000422"), "the service is disabled — set its start type first"},
		{"invalid control", fmt.Errorf("RControlService: 0x0000041c"), "the service does not accept stop/control requests"},
		{"cannot accept ctrl", fmt.Errorf("RControlService: 0x00000425"), "the service does not accept stop/control requests"},
		{"dependents running", fmt.Errorf("RControlService: 0x0000041b"), "other running services depend on this service"},
		{"passthrough", fmt.Errorf("RStartServiceW: 0x0000042e"), "RStartServiceW: 0x0000042e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapSCMError(c.err)
			if c.err == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if got == nil || got.Error() != c.want {
				t.Fatalf("mapSCMError(%v) = %v, want %q", c.err, got, c.want)
			}
		})
	}
}
