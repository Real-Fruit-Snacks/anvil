package smbclient

import (
	"os"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
)

// TestParseEnumResponse drives anvil's production parseEnumResponse against
// a real REnumServicesStatusW response captured from a live Windows Server
// 2022 DC (testdata/enum-resp.bin, 131096 bytes, 244 services).
//
// Windows hand-packs lpServiceBuf as: [referent(4)] then 36-byte records
// [nameOff(4)][displayOff(4)][SERVICE_STATUS(28)] — string offsets are
// relative to the array start (resp+4). There is NO maxCount/actualCount
// header; an earlier version of this parser assumed one and read every
// record shifted by 8 bytes, attributing each service the PREVIOUS
// record's state (and asserting the shifted values here). The fixture's
// first record is ADWS, which that parser dropped entirely.
//
// Note: gopacket's svcctl.EnumServicesStatus is NOT what anvil ships — its
// request marshaling is rejected by real Windows and its trailer parse reads
// a bogus error code, which is why anvil carries its own implementation.
func TestParseEnumResponse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/enum-resp.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	entries, moreData, err := parseEnumResponse(fixture)
	if err != nil {
		t.Fatalf("parseEnumResponse: %v", err)
	}
	if moreData {
		t.Fatal("moreData = true, want false for a complete capture")
	}

	// 244 named services; the buffer's trailing null-name sentinel is not
	// counted among them.
	if len(entries) != 244 {
		t.Fatalf("entry count = %d, want 244", len(entries))
	}

	// Record 0 (offsets verified byte-by-byte against the capture):
	// ADWS — Active Directory Web Services, RUNNING on the DC.
	first := entries[0]
	if first.name != "ADWS" {
		t.Errorf("entry[0].name = %q, want ADWS", first.name)
	}
	if first.displayName != "Active Directory Web Services" {
		t.Errorf("entry[0].displayName = %q, want Active Directory Web Services", first.displayName)
	}
	if first.state != svcctl.SERVICE_RUNNING {
		t.Errorf("entry[0].state = %d, want RUNNING (%d)", first.state, svcctl.SERVICE_RUNNING)
	}

	// Record 1 carries its OWN status: AJRouter, STOPPED/never-started
	// (exit 1077) in this capture — the shifted parser showed it RUNNING.
	second := entries[1]
	if second.name != "AJRouter" {
		t.Errorf("entry[1].name = %q, want AJRouter", second.name)
	}
	if second.displayName != "AllJoyn Router Service" {
		t.Errorf("entry[1].displayName = %q, want AllJoyn Router Service", second.displayName)
	}
	if second.state != svcctl.SERVICE_STOPPED {
		t.Errorf("entry[1].state = %d, want STOPPED (%d)", second.state, svcctl.SERVICE_STOPPED)
	}

	// Known services by name.
	wantNames := map[string]bool{"Netlogon": false, "WinRM": false}
	for _, e := range entries {
		if _, ok := wantNames[e.name]; ok {
			wantNames[e.name] = true
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("service %q not found in parsed entries", name)
		}
	}

	// No null-named artifact among the returned entries.
	last := entries[len(entries)-1]
	if last.name == "" {
		t.Errorf("last entry has empty name — trailing sentinel leaked")
	}
}

// TestParseEnumResponseShort verifies truncated responses error out instead
// of panicking or returning garbage.
func TestParseEnumResponseShort(t *testing.T) {
	if _, _, err := parseEnumResponse([]byte{0, 1, 2}); err == nil {
		t.Fatal("expected error for 3-byte response")
	}

	fixture, err := os.ReadFile("testdata/enum-resp.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Cut inside the array data: must error, not panic.
	if _, _, err := parseEnumResponse(fixture[:100]); err == nil {
		t.Fatal("expected error for truncated response")
	}
}
