package smbclient

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/security"
)

// testSID returns a parseable domain-style SID for ACE construction.
func testSID(t *testing.T, s string) *security.SID {
	t.Helper()
	sid, err := security.ParseSID(s)
	if err != nil {
		t.Fatalf("ParseSID(%s): %v", s, err)
	}
	return sid
}

func TestLookupRightsPresets(t *testing.T) {
	tests := []struct {
		name      string
		rights    string
		wantMasks []uint32 // one per ACE template, "" rights → nil
		wantErr   bool
	}{
		{name: "genericall", rights: "genericall", wantMasks: []uint32{security.GENERIC_ALL}},
		{name: "fullcontrol", rights: "fullcontrol", wantMasks: []uint32{security.FULL_CONTROL}},
		{name: "writedacl", rights: "writedacl", wantMasks: []uint32{security.WRITE_DAC}},
		{name: "writeowner", rights: "writeowner", wantMasks: []uint32{security.WRITE_OWNER}},
		{name: "dcsync is two ACEs", rights: "dcsync", wantMasks: []uint32{security.DS_CONTROL_ACCESS, security.DS_CONTROL_ACCESS}},
		{name: "case insensitive", rights: "GenericAll", wantMasks: []uint32{security.GENERIC_ALL}},
		{name: "upper case", rights: "WRITEDACL", wantMasks: []uint32{security.WRITE_DAC}},
		{name: "unknown", rights: "takeownership", wantErr: true},
		{name: "empty", rights: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presets, err := lookupRightsPresets(tt.rights)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("lookupRightsPresets(%q) = nil error, want error", tt.rights)
				}
				if !strings.Contains(err.Error(), tt.rights) {
					t.Errorf("error %q should name the bad rights value %q", err, tt.rights)
				}
				return
			}
			if err != nil {
				t.Fatalf("lookupRightsPresets(%q): %v", tt.rights, err)
			}
			if len(presets) != len(tt.wantMasks) {
				t.Fatalf("lookupRightsPresets(%q) = %d presets, want %d", tt.rights, len(presets), len(tt.wantMasks))
			}
			for i, want := range tt.wantMasks {
				if presets[i].mask != want {
					t.Errorf("preset %d mask = 0x%x, want 0x%x", i, presets[i].mask, want)
				}
			}
		})
	}
}

func TestRightsPresetNames(t *testing.T) {
	names := RightsPresetNames()
	for _, want := range []string{"dcsync", "fullcontrol", "genericall", "resetpassword", "writedacl", "writemembers", "writeowner"} {
		if !strings.Contains(names, want) {
			t.Errorf("RightsPresetNames() = %q, missing %q", names, want)
		}
	}
	// Sorted output keeps help text and error messages stable.
	if parts := strings.Split(names, ", "); !sort.StringsAreSorted(parts) {
		t.Errorf("RightsPresetNames() = %q, want sorted", names)
	}
}

func TestBuildRightACEs(t *testing.T) {
	sid := testSID(t, "S-1-5-21-100-200-300-1105")

	tests := []struct {
		name        string
		rights      string
		denied      bool
		inheritance bool
		wantType    uint8 // type every built ACE must have
		wantFlags   uint8
	}{
		{name: "allowed standard", rights: "genericall", wantType: security.ACCESS_ALLOWED_ACE_TYPE},
		{name: "denied standard", rights: "writedacl", denied: true, wantType: security.ACCESS_DENIED_ACE_TYPE},
		{name: "allowed object", rights: "resetpassword", wantType: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE},
		{name: "denied object", rights: "resetpassword", denied: true, wantType: security.ACCESS_DENIED_OBJECT_ACE_TYPE},
		{
			name:        "inheritance sets container+object inherit",
			rights:      "genericall",
			inheritance: true,
			wantType:    security.ACCESS_ALLOWED_ACE_TYPE,
			wantFlags:   security.CONTAINER_INHERIT_ACE | security.OBJECT_INHERIT_ACE,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presets, err := lookupRightsPresets(tt.rights)
			if err != nil {
				t.Fatal(err)
			}
			aces := buildRightACEs(sid, presets, tt.denied, tt.inheritance)
			if len(aces) != len(presets) {
				t.Fatalf("buildRightACEs = %d ACEs, want %d", len(aces), len(presets))
			}
			for i, ace := range aces {
				if ace.Type != tt.wantType {
					t.Errorf("ACE %d type = 0x%02x, want 0x%02x", i, ace.Type, tt.wantType)
				}
				if ace.Flags != tt.wantFlags {
					t.Errorf("ACE %d flags = 0x%02x, want 0x%02x", i, ace.Flags, tt.wantFlags)
				}
				if ace.Mask != presets[i].mask {
					t.Errorf("ACE %d mask = 0x%x, want 0x%x", i, ace.Mask, presets[i].mask)
				}
				if !ace.SID.Equal(sid) {
					t.Errorf("ACE %d SID = %s, want %s", i, ace.SID, sid)
				}
				if presets[i].objectType != nil {
					if ace.ObjectType != *presets[i].objectType {
						t.Errorf("ACE %d object type = %s, want %s", i, ace.ObjectType, *presets[i].objectType)
					}
				} else if !ace.ObjectType.IsZero() {
					t.Errorf("ACE %d unexpected object type %s", i, ace.ObjectType)
				}
			}
		})
	}

	t.Run("dcsync carries both replication GUIDs", func(t *testing.T) {
		presets, _ := lookupRightsPresets("dcsync")
		aces := buildRightACEs(sid, presets, false, false)
		if len(aces) != 2 {
			t.Fatalf("dcsync = %d ACEs, want 2", len(aces))
		}
		if aces[0].ObjectType != security.GUID_DS_REPLICATION_GET_CHANGES {
			t.Errorf("first GUID = %s, want DS-Replication-Get-Changes", aces[0].ObjectType)
		}
		if aces[1].ObjectType != security.GUID_DS_REPLICATION_GET_CHANGES_ALL {
			t.Errorf("second GUID = %s, want DS-Replication-Get-Changes-All", aces[1].ObjectType)
		}
	})
}

func TestACEMatchesAnyPreset(t *testing.T) {
	sid := testSID(t, "S-1-5-21-100-200-300-1105")

	tests := []struct {
		name   string
		ace    *security.ACE
		rights string
		want   bool
	}{
		{
			name:   "exact mask match",
			ace:    &security.ACE{Mask: security.GENERIC_ALL, SID: sid},
			rights: "genericall",
			want:   true,
		},
		{
			// impacket semantics: a FullControl ACE covers WriteDACL, so a
			// "writedacl" removal takes it out.
			name:   "fullcontrol superset matches writedacl",
			ace:    &security.ACE{Mask: security.FULL_CONTROL, SID: sid},
			rights: "writedacl",
			want:   true,
		},
		{
			name:   "disjoint mask does not match",
			ace:    &security.ACE{Mask: security.GENERIC_ALL, SID: sid},
			rights: "writedacl",
			want:   false,
		},
		{
			name:   "denied ACE matches on mask alone",
			ace:    &security.ACE{Type: security.ACCESS_DENIED_ACE_TYPE, Mask: security.WRITE_DAC, SID: sid},
			rights: "writedacl",
			want:   true,
		},
		{
			// Server 2022 stores a granted GENERIC_ALL ACE as FULL_CONTROL
			// (canonicalization on write) — "genericall" removal must still
			// match it.
			name:   "canonicalized fullcontrol matches genericall removal",
			ace:    &security.ACE{Mask: security.FULL_CONTROL, SID: sid},
			rights: "genericall",
			want:   true,
		},
		{
			name:   "raw genericall matches fullcontrol removal",
			ace:    &security.ACE{Mask: security.GENERIC_ALL, SID: sid},
			rights: "fullcontrol",
			want:   true,
		},
		{
			name: "object preset matches same GUID",
			ace: &security.ACE{
				Type:       security.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
				Mask:       security.DS_CONTROL_ACCESS,
				ObjectType: security.GUID_RESET_PASSWORD,
				SID:        sid,
			},
			rights: "resetpassword",
			want:   true,
		},
		{
			name: "object preset rejects wrong GUID",
			ace: &security.ACE{
				Type:       security.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
				Mask:       security.DS_CONTROL_ACCESS,
				ObjectType: security.GUID_WRITE_MEMBERS,
				SID:        sid,
			},
			rights: "resetpassword",
			want:   false,
		},
		{
			// A standard ACE has a zero ObjectType and must never satisfy an
			// object preset, even with the right mask.
			name:   "standard ACE never matches object preset",
			ace:    &security.ACE{Mask: security.DS_CONTROL_ACCESS, SID: sid},
			rights: "resetpassword",
			want:   false,
		},
		{
			name:   "dcsync matches either replication GUID",
			ace:    &security.ACE{Type: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: security.DS_CONTROL_ACCESS, ObjectType: security.GUID_DS_REPLICATION_GET_CHANGES_ALL, SID: sid},
			rights: "dcsync",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presets, err := lookupRightsPresets(tt.rights)
			if err != nil {
				t.Fatal(err)
			}
			if got := aceMatchesAnyPreset(tt.ace, presets); got != tt.want {
				t.Errorf("aceMatchesAnyPreset(mask 0x%x, %s) = %v, want %v", tt.ace.Mask, tt.rights, got, tt.want)
			}
		})
	}
}

func TestMaskCovers(t *testing.T) {
	tests := []struct {
		name       string
		aceMask    uint32
		presetMask uint32
		want       bool
	}{
		{name: "identical", aceMask: security.WRITE_DAC, presetMask: security.WRITE_DAC, want: true},
		{name: "superset covers", aceMask: security.FULL_CONTROL, presetMask: security.WRITE_DAC, want: true},
		{name: "subset does not cover", aceMask: security.WRITE_DAC, presetMask: security.FULL_CONTROL, want: false},
		{name: "generic_all covers full_control", aceMask: security.GENERIC_ALL, presetMask: security.FULL_CONTROL, want: true},
		{name: "full_control covers generic_all", aceMask: security.FULL_CONTROL, presetMask: security.GENERIC_ALL, want: true},
		{name: "generic_all alone does not cover writedac", aceMask: security.GENERIC_ALL, presetMask: security.WRITE_DAC, want: false},
		{name: "writedac does not cover generic_all", aceMask: security.WRITE_DAC, presetMask: security.GENERIC_ALL, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskCovers(tt.aceMask, tt.presetMask); got != tt.want {
				t.Errorf("maskCovers(0x%x, 0x%x) = %v, want %v", tt.aceMask, tt.presetMask, got, tt.want)
			}
		})
	}
}

// TestSecurityDescriptorRoundTrip builds a descriptor with ACEs from
// buildRightACEs, marshals it, and re-parses — the same wire format the DC
// receives, so object GUIDs, masks, and SIDs must survive intact.
func TestSecurityDescriptorRoundTrip(t *testing.T) {
	sid := testSID(t, "S-1-5-21-100-200-300-1105")
	owner := testSID(t, "S-1-5-32-544")

	dcsync, _ := lookupRightsPresets("dcsync")
	ga, _ := lookupRightsPresets("genericall")
	aces := buildRightACEs(sid, dcsync, false, false)
	aces = append(aces, buildRightACEs(sid, ga, false, false)...)

	sd := &security.SecurityDescriptor{
		Revision: 1,
		Control:  security.SE_DACL_PRESENT,
		Owner:    owner,
		DACL:     &security.ACL{AclRevision: 4},
	}
	for _, ace := range aces {
		sd.DACL.AddACE(ace)
	}

	parsed, err := security.ParseSecurityDescriptor(sd.Marshal())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.Owner == nil || !parsed.Owner.Equal(owner) {
		t.Errorf("owner = %v, want %s", parsed.Owner, owner)
	}
	if parsed.DACL == nil {
		t.Fatal("re-parsed descriptor has no DACL")
	}
	if len(parsed.DACL.ACEs) != 3 {
		t.Fatalf("DACL ACEs = %d, want 3", len(parsed.DACL.ACEs))
	}
	if got := parsed.DACL.ACEs[0]; got.ObjectType != security.GUID_DS_REPLICATION_GET_CHANGES ||
		got.Mask != security.DS_CONTROL_ACCESS || !got.SID.Equal(sid) {
		t.Errorf("ACE 0 = %+v, want dcsync get-changes ACE for %s", got, sid)
	}
	if got := parsed.DACL.ACEs[2]; got.Mask != security.GENERIC_ALL || got.IsObjectACE() {
		t.Errorf("ACE 2 = %+v, want standard GENERIC_ALL ACE", got)
	}

	// The removal predicate must select exactly the two dcsync ACEs.
	matched := 0
	for _, ace := range parsed.DACL.ACEs {
		if aceMatchesAnyPreset(ace, dcsync) {
			matched++
		}
	}
	if matched != 2 {
		t.Errorf("dcsync removal matched %d ACEs, want 2", matched)
	}
}

func TestSIDSearchFilter(t *testing.T) {
	// S-1-5-32-544 marshals to: revision 1, 2 subauthorities, authority 5
	// (6-byte big-endian), then 32 and 544 as little-endian uint32s.
	got, err := sidSearchFilter("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	want := "(objectSid=\\01\\02\\00\\00\\00\\00\\00\\05\\20\\00\\00\\00\\20\\02\\00\\00)"
	if got != want {
		t.Errorf("sidSearchFilter = %q, want %q", got, want)
	}

	if _, err := sidSearchFilter("not-a-sid"); err == nil {
		t.Errorf("sidSearchFilter(not-a-sid) = nil error, want error")
	}
}

func TestACETypeName(t *testing.T) {
	if got := aceTypeName(security.ACCESS_ALLOWED_ACE_TYPE); got != "ACCESS_ALLOWED" {
		t.Errorf("aceTypeName(allowed) = %q", got)
	}
	if got := aceTypeName(0x11); got != "0x11" { // SYSTEM_MANDATORY_LABEL — not in gopacket's table
		t.Errorf("aceTypeName(0x11) = %q, want hex fallback", got)
	}
}

func TestGUIDDisplay(t *testing.T) {
	got := guidDisplay(security.GUID_RESET_PASSWORD)
	if !strings.Contains(got, "User-Force-Change-Password") || !strings.Contains(got, "00299570-246d-11d0-a768-00aa006e0529") {
		t.Errorf("guidDisplay(reset-password) = %q, want name + GUID", got)
	}

	unknown, err := security.ParseGUID("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	if got := guidDisplay(unknown); got != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("guidDisplay(unknown) = %q, want bare GUID", got)
	}
}

func TestMapSDError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "insufficient access rights by name",
			err:  errors.New(`LDAP Result Code 50 "Insufficient Access Rights": 00000005: SecErr: DSID-03152E13`),
			want: "access denied",
		},
		{
			name: "passthrough",
			err:  errors.New("connection refused"),
			want: "connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSDError(tt.err)
			if !strings.Contains(got.Error(), tt.want) {
				t.Errorf("mapSDError(%v) = %q, want substring %q", tt.err, got, tt.want)
			}
			if !strings.Contains(got.Error(), tt.err.Error()) {
				t.Errorf("mapSDError(%v) = %q, want original text preserved", tt.err, got)
			}
		})
	}
}
