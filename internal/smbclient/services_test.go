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
// Note: gopacket's svcctl.EnumServicesStatus is NOT what anvil ships — its
// request marshaling is rejected by real Windows and its trailer parse reads
// a bogus error code, which is why anvil carries its own implementation.
// (As a curiosity, the library parses this replayed capture without error,
// but yields garbage rows — e.g. entry 0 as "ADWS" — because it assumes the
// wrong entry layout. Do not "simplify" back to the library.)
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

	if len(entries) != 244 {
		t.Fatalf("entry count = %d, want 244", len(entries))
	}

	// Entry 0 (verified byte-by-byte against the capture).
	first := entries[0]
	if first.name != "AJRouter" {
		t.Errorf("entry[0].name = %q, want AJRouter", first.name)
	}
	if first.displayName != "AllJoyn Router Service" {
		t.Errorf("entry[0].displayName = %q, want AllJoyn Router Service", first.displayName)
	}
	if first.state != svcctl.SERVICE_RUNNING {
		t.Errorf("entry[0].state = %d, want RUNNING (%d)", first.state, svcctl.SERVICE_RUNNING)
	}

	// Known services by name. (ADWS appears in this capture's string pool
	// but is referenced by no entry — don't assert it.)
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

	// The final entry is the server's trailing artifact with null
	// name/display pointers (EnumServices filters it out upstream).
	last := entries[len(entries)-1]
	if last.name != "" || last.displayName != "" {
		t.Errorf("last entry = %q/%q, want null-named artifact", last.name, last.displayName)
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
