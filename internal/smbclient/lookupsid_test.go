package smbclient

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc/lsarpc"
)

func TestSIDForRID(t *testing.T) {
	cases := []struct {
		name      string
		domainSID string
		rid       uint32
		want      string
	}{
		{"administrator", "S-1-5-21-633962655-485248531-2707014454", 500, "S-1-5-21-633962655-485248531-2707014454-500"},
		{"machine account", "S-1-5-21-633962655-485248531-2707014454", 1000, "S-1-5-21-633962655-485248531-2707014454-1000"},
		{"rid zero", "S-1-5-21-1-2-3", 0, "S-1-5-21-1-2-3-0"},
		{"builtin domain", "S-1-5-32", 544, "S-1-5-32-544"},
		{"max rid", "S-1-5-21-1-2-3", math.MaxUint32, "S-1-5-21-1-2-3-4294967295"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sidForRID(c.domainSID, c.rid); got != c.want {
				t.Errorf("sidForRID(%q, %d) = %q, want %q", c.domainSID, c.rid, got, c.want)
			}
		})
	}
}

func TestRIDBatches(t *testing.T) {
	cases := []struct {
		name       string
		start, end uint32
		size       uint32
		want       [][2]uint32
	}{
		{"exact multiple", 0, 127, 64, [][2]uint32{{0, 63}, {64, 127}}},
		{"remainder", 500, 600, 64, [][2]uint32{{500, 563}, {564, 600}}},
		{"single batch", 500, 512, 64, [][2]uint32{{500, 512}}},
		{"single rid", 500, 500, 64, [][2]uint32{{500, 500}}},
		{"size one", 10, 12, 1, [][2]uint32{{10, 10}, {11, 11}, {12, 12}}},
		{"size larger than range", 500, 4000, 10000, [][2]uint32{{500, 4000}}},
		{"start after end", 501, 500, 64, nil},
		{"zero size", 500, 4000, 0, nil},
		{"end at maxuint32", math.MaxUint32 - 2, math.MaxUint32, 2, [][2]uint32{{math.MaxUint32 - 2, math.MaxUint32 - 1}, {math.MaxUint32, math.MaxUint32}}},
		{"size wraps", 0, math.MaxUint32, math.MaxUint32, [][2]uint32{{0, math.MaxUint32 - 1}, {math.MaxUint32, math.MaxUint32}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ridBatches(c.start, c.end, c.size)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ridBatches(%d, %d, %d) = %v, want %v", c.start, c.end, c.size, got, c.want)
			}
		})
	}
}

func TestRIDBatchesDefaultSweep(t *testing.T) {
	// The default 500-4000 sweep at batch size 64: 55 batches, no gaps, no
	// overlaps, ends exactly at 4000.
	batches := ridBatches(500, 4000, lookupBatchSize)
	if len(batches) != 55 {
		t.Fatalf("got %d batches, want 55", len(batches))
	}
	if batches[0][0] != 500 {
		t.Errorf("first batch starts at %d, want 500", batches[0][0])
	}
	if batches[len(batches)-1][1] != 4000 {
		t.Errorf("last batch ends at %d, want 4000", batches[len(batches)-1][1])
	}
	for i := 1; i < len(batches); i++ {
		if batches[i][0] != batches[i-1][1]+1 {
			t.Errorf("gap/overlap between batch %d (%v) and %d (%v)", i-1, batches[i-1], i, batches[i])
		}
		if batches[i][1]-batches[i][0]+1 > lookupBatchSize {
			t.Errorf("batch %d %v exceeds size %d", i, batches[i], lookupBatchSize)
		}
	}
}

func TestToSidEntries(t *testing.T) {
	cases := []struct {
		name     string
		results  []lsarpc.LookupResult
		startRID uint32
		want     []SidEntry
	}{
		{
			name: "mixed mapped and unknown",
			results: []lsarpc.LookupResult{
				{SID: "S-1-5-21-1-2-3-500", Domain: "CORP", Name: "Administrator", SidType: lsarpc.SidTypeUser, SidTypeStr: "SidTypeUser"},
				{SID: "S-1-5-21-1-2-3-501", SidType: lsarpc.SidTypeUnknown, SidTypeStr: "SidTypeUnknown"},
				{SID: "S-1-5-21-1-2-3-502", Domain: "CORP", Name: "krbtgt", SidType: lsarpc.SidTypeUser, SidTypeStr: "SidTypeUser"},
				{SID: "S-1-5-21-1-2-3-503", Domain: "CORP", Name: "Domain Admins", SidType: lsarpc.SidTypeAlias, SidTypeStr: "SidTypeAlias"},
			},
			startRID: 500,
			want: []SidEntry{
				{RID: 500, Domain: "CORP", Name: "Administrator", Type: "SidTypeUser"},
				{RID: 502, Domain: "CORP", Name: "krbtgt", Type: "SidTypeUser"},
				{RID: 503, Domain: "CORP", Name: "Domain Admins", Type: "SidTypeAlias"},
			},
		},
		{
			name: "all unknown",
			results: []lsarpc.LookupResult{
				{SidType: lsarpc.SidTypeUnknown},
				{SidType: lsarpc.SidTypeUnknown},
			},
			startRID: 1000,
			want:     nil,
		},
		{
			name:     "empty batch",
			results:  nil,
			startRID: 0,
			want:     nil,
		},
		{
			name: "rid stamping offset",
			results: []lsarpc.LookupResult{
				{Domain: "CORP", Name: "svc-kerb", SidType: lsarpc.SidTypeUser, SidTypeStr: "SidTypeUser"},
			},
			startRID: 3101,
			want: []SidEntry{
				{RID: 3101, Domain: "CORP", Name: "svc-kerb", Type: "SidTypeUser"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := toSidEntries(c.results, c.startRID)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("toSidEntries(...) = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMapLSAError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"access denied", errors.New("OpenPolicy2 failed: 0xc0000022"), "access denied"},
		{"denied mid-sweep", errors.New("LookupSids failed: 0xc0000022"), "access denied"},
		{"unknown passthrough", errors.New("LookupSids failed: 0xdeadbeef"), "LookupSids failed: 0xdeadbeef"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapLSAError(c.err)
			if c.want == "" {
				if got != nil {
					t.Errorf("mapLSAError(%v) = %v, want nil", c.err, got)
				}
				return
			}
			if got == nil || got.Error() != c.want {
				t.Errorf("mapLSAError(%v) = %v, want %q", c.err, got, c.want)
			}
		})
	}
}
