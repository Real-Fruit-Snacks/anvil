package scan

import "testing"

// TestUUIDAnnotation exercises the well-known RPC interface dictionary:
// every interface the scan output annotates, plus lookup hygiene (case
// insensitivity, unknown UUIDs).
func TestUUIDAnnotation(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want string
		ok   bool
	}{
		{
			name: "SAMR lowercase",
			uuid: "12345778-1234-abcd-ef00-0123456789ac",
			want: "Security Account Manager (MS-SAMR)",
			ok:   true,
		},
		{
			name: "SAMR uppercase as rendered by gopacket epmapper",
			uuid: "12345778-1234-ABCD-EF00-0123456789AC",
			want: "Security Account Manager (MS-SAMR)",
			ok:   true,
		},
		{
			name: "LSARPC",
			uuid: "12345778-1234-abcd-ef00-0123456789ab",
			want: "Local Security Authority (MS-LSARPC)",
			ok:   true,
		},
		{
			name: "DRSUAPI",
			uuid: "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
			want: "Directory Replication Service (MS-DRSUAPI)",
			ok:   true,
		},
		{
			name: "DRSUAPI mixed case",
			uuid: "E3514235-4B06-11d1-AB04-00c04fc2dcd2",
			want: "Directory Replication Service (MS-DRSUAPI)",
			ok:   true,
		},
		{
			name: "SVCCTL",
			uuid: "367abb81-9844-35f1-ad32-98f038001003",
			want: "Service Control Manager (MS-SCMR)",
			ok:   true,
		},
		{
			name: "SRVSVC",
			uuid: "4b324fc8-1670-01d3-1278-5a47bf6ee188",
			want: "Server Service (MS-SRVS)",
			ok:   true,
		},
		{
			name: "WKSSVC",
			uuid: "6bffd098-a112-3610-9833-46c3f87e345a",
			want: "Workstation Service (MS-WKST)",
			ok:   true,
		},
		{
			name: "NETLOGON",
			uuid: "12345678-1234-abcd-ef00-01234567cffb",
			want: "Netlogon Remote (MS-NRPC)",
			ok:   true,
		},
		{
			name: "winreg",
			uuid: "338cd001-2244-31f1-aaaa-900038001003",
			want: "Windows Remote Registry (MS-RRP)",
			ok:   true,
		},
		{
			name: "eventlog",
			uuid: "82273fdc-e32a-18c3-3f78-827929dc23ea",
			want: "EventLog Remoting (MS-EVEN)",
			ok:   true,
		},
		{
			name: "TSCH",
			uuid: "86d35949-83c9-4044-b424-db363231fd0c",
			want: "Task Scheduler (MS-TSCH)",
			ok:   true,
		},
		{
			name: "epmapper",
			uuid: "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
			want: "RPC Endpoint Mapper",
			ok:   true,
		},
		{
			name: "MS-RPRN PrinterBug",
			uuid: "12345678-1234-abcd-ef00-0123456789ab",
			want: "Print System Remote (MS-RPRN)",
			ok:   true,
		},
		{
			name: "MS-EFSR on lsarpc pipe",
			uuid: "c681d488-d850-11d0-8c52-00c04fd90f7e",
			want: "Encrypting File System Remote (MS-EFSR)",
			ok:   true,
		},
		{
			name: "MS-EFSR on efsrpc pipe",
			uuid: "df1941c5-fe89-4e79-bf10-463657acf44d",
			want: "Encrypting File System Remote (MS-EFSR)",
			ok:   true,
		},
		{
			name: "MS-FSRVP ShadowCoerce",
			uuid: "a8e0653c-2744-4389-a61d-7373df8b2292",
			want: "File Server Remote VSS (MS-FSRVP)",
			ok:   true,
		},
		{
			name: "MS-DFSNM DFSCoerce",
			uuid: "4fc742e0-4a10-11cf-8273-00aa004ae673",
			want: "DFS Namespace Management (MS-DFSNM)",
			ok:   true,
		},
		{
			name: "MS-PAR IRemoteWinspool PrintNightmare",
			uuid: "ae33069b-a2a8-46ee-a235-ddfd339be281",
			want: "Print System Asynchronous Remote (MS-PAR)",
			ok:   true,
		},
		{
			name: "MS-PAR impacket par.py UUID",
			uuid: "76f03f96-cdfd-44fc-a22c-64950a001209",
			want: "Print System Asynchronous Remote (MS-PAR)",
			ok:   true,
		},
		{
			name: "unknown UUID",
			uuid: "00000000-0000-0000-0000-000000000000",
			want: "",
			ok:   false,
		},
		{
			name: "empty string",
			uuid: "",
			want: "",
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := UUIDAnnotation(tt.uuid)
			if ok != tt.ok {
				t.Fatalf("UUIDAnnotation(%q) ok = %v, want %v", tt.uuid, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("UUIDAnnotation(%q) = %q, want %q", tt.uuid, got, tt.want)
			}
		})
	}
}

// TestCoercionNote checks that exactly the coercion-relevant interfaces carry
// an attack-family note and everything else returns "".
func TestCoercionNote(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want string
	}{
		{
			name: "MS-RPRN is the PrinterBug target",
			uuid: "12345678-1234-abcd-ef00-0123456789ab",
			want: "PrinterBug coercion target",
		},
		{
			name: "MS-RPRN uppercase lookup",
			uuid: "12345678-1234-ABCD-EF00-0123456789AB",
			want: "PrinterBug coercion target",
		},
		{
			name: "MS-EFSR lsarpc-pipe UUID is PetitPotam",
			uuid: "c681d488-d850-11d0-8c52-00c04fd90f7e",
			want: "PetitPotam coercion target",
		},
		{
			name: "MS-EFSR efsrpc-pipe UUID is PetitPotam",
			uuid: "df1941c5-fe89-4e79-bf10-463657acf44d",
			want: "PetitPotam coercion target",
		},
		{
			name: "MS-FSRVP is ShadowCoerce",
			uuid: "a8e0653c-2744-4389-a61d-7373df8b2292",
			want: "ShadowCoerce coercion target",
		},
		{
			name: "MS-DFSNM is DFSCoerce",
			uuid: "4fc742e0-4a10-11cf-8273-00aa004ae673",
			want: "DFSCoerce coercion target",
		},
		{
			name: "MS-PAR IRemoteWinspool is PrintNightmare",
			uuid: "ae33069b-a2a8-46ee-a235-ddfd339be281",
			want: "PrintNightmare coercion target",
		},
		{
			name: "MS-PAR impacket UUID is PrintNightmare",
			uuid: "76f03f96-cdfd-44fc-a22c-64950a001209",
			want: "PrintNightmare coercion target",
		},
		{
			name: "known non-coercion interface returns empty",
			uuid: "12345778-1234-abcd-ef00-0123456789ac",
			want: "",
		},
		{
			name: "unknown UUID returns empty",
			uuid: "11111111-2222-3333-4444-555555555555",
			want: "",
		},
		{
			name: "empty string returns empty",
			uuid: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CoercionNote(tt.uuid); got != tt.want {
				t.Errorf("CoercionNote(%q) = %q, want %q", tt.uuid, got, tt.want)
			}
		})
	}
}

// TestWellKnownRPCKeysNormalized guards the table invariant the lookups rely
// on: keys must already be in normalizeUUID form (lowercase, no padding),
// otherwise UUIDAnnotation/CoercionNote would silently never match them.
func TestWellKnownRPCKeysNormalized(t *testing.T) {
	for key, e := range wellKnownRPC {
		if normalizeUUID(key) != key {
			t.Errorf("key %q (%s) is not in normalized lowercase form", key, e.name)
		}
		if e.name == "" {
			t.Errorf("key %q has an empty annotation", key)
		}
	}
}
