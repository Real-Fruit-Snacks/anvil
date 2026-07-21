package perf

import (
	"encoding/binary"
	"os"
	"testing"
)

// testdata/perf-process-230.bin is a live capture of the BaseRegQueryValue
// "230" (Process object family) response from HKEY_PERFORMANCE_DATA on the
// lab's Windows Server 2022 DC (x64). Note the 32-bit wire layout it
// proves: object HeaderLength 64, counter-def ByteLength 40 — the registry
// perf interface is layout-stable across architectures, which is what the
// length-field walk in perf.go relies on.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestParseDataBlockProcessFixture(t *testing.T) {
	objects, err := ParseDataBlock(readFixture(t, "perf-process-230.bin"))
	if err != nil {
		t.Fatalf("ParseDataBlock: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("objects = %d, want 1 (a single-family query)", len(objects))
	}
	obj := objects[0]
	if obj.NameTitleIndex != 230 {
		t.Errorf("object NameTitleIndex = %d, want 230 (Process)", obj.NameTitleIndex)
	}
	if len(obj.Counters) != 28 {
		t.Fatalf("counters = %d, want 28", len(obj.Counters))
	}

	// The four counters anvil extracts, with the exact schema the capture
	// carries (all 32-bit values).
	wantCounters := map[uint32]Counter{
		784:  {NameTitleIndex: 784, Size: 4, Offset: 104},  // ID Process
		1410: {NameTitleIndex: 1410, Size: 4, Offset: 108}, // Creating Process ID
		680:  {NameTitleIndex: 680, Size: 4, Offset: 88},   // Thread Count
		952:  {NameTitleIndex: 952, Size: 4, Offset: 120},  // Handle Count
	}
	byIndex := map[uint32]Counter{}
	for _, c := range obj.Counters {
		byIndex[c.NameTitleIndex] = c
	}
	for idx, want := range wantCounters {
		got, ok := byIndex[idx]
		if !ok {
			t.Errorf("counter %d missing from schema", idx)
			continue
		}
		if got != want {
			t.Errorf("counter %d = %+v, want %+v", idx, got, want)
		}
	}

	// 120 instances in the capture; _Total is the last one (perflib's
	// synthetic aggregate row).
	if len(obj.Instances) != 120 {
		t.Fatalf("instances = %d, want 120", len(obj.Instances))
	}
	if last := obj.Instances[len(obj.Instances)-1]; last.Name != "_Total" {
		t.Errorf("last instance = %q, want _Total", last.Name)
	}

	// Every instance carries a full 28-counter value set.
	for i, inst := range obj.Instances {
		if len(inst.Values) != 28 {
			t.Errorf("instance %d (%q) has %d values, want 28", i, inst.Name, len(inst.Values))
		}
	}

	// Exact values from the capture for well-known processes.
	byName := map[string]Instance{}
	for _, inst := range obj.Instances {
		if _, seen := byName[inst.Name]; !seen {
			byName[inst.Name] = inst
		}
	}
	checks := []struct {
		name             string
		pid, ppid        uint64
		handles, threads uint64
	}{
		{"Idle", 0, 0, 0, 4},
		{"System", 4, 0, 2540, 128},
		{"smss", 292, 4, 60, 2},
		{"lsass", 672, 520, 2477, 31},
	}
	for _, c := range checks {
		inst, ok := byName[c.name]
		if !ok {
			t.Errorf("instance %q not found", c.name)
			continue
		}
		if got := inst.Values[784]; got != c.pid {
			t.Errorf("%s: ID Process = %d, want %d", c.name, got, c.pid)
		}
		if got := inst.Values[1410]; got != c.ppid {
			t.Errorf("%s: Creating Process ID = %d, want %d", c.name, got, c.ppid)
		}
		if got := inst.Values[952]; got != c.handles {
			t.Errorf("%s: Handle Count = %d, want %d", c.name, got, c.handles)
		}
		if got := inst.Values[680]; got != c.threads {
			t.Errorf("%s: Thread Count = %d, want %d", c.name, got, c.threads)
		}
	}
}

// testdata/perf-titles-009.bin is the "Counter 009" REG_MULTI_SZ (318208
// bytes) from HKEY_PERFORMANCE_NLSTEXT on the same Server 2022 DC.
func TestParseTitlesFixture(t *testing.T) {
	titles := ParseTitles(readFixture(t, "perf-titles-009.bin"))
	if len(titles) != 3716 {
		t.Errorf("unique names = %d, want 3716", len(titles))
	}

	// The Process family and its four counters resolve to the classic
	// perflib indexes; the duplicates belong to the Job Object families
	// and must sort AFTER the kernel's (first-candidate resolution).
	want := map[string][]uint32{
		"Process":             {230},
		"ID Process":          {784},
		"Creating Process ID": {1410, 5438},
		"Handle Count":        {952, 5444},
		"Thread Count":        {680, 5430},
	}
	for name, wantIdx := range want {
		got := titles[name]
		if len(got) != len(wantIdx) {
			t.Errorf("%q indexes = %v, want %v", name, got, wantIdx)
			continue
		}
		for i := range wantIdx {
			if got[i] != wantIdx[i] {
				t.Errorf("%q indexes = %v, want %v", name, got, wantIdx)
				break
			}
		}
	}
}

func TestParseTitlesSynthetic(t *testing.T) {
	multiSZ := func(pairs ...string) []byte {
		var b []byte
		for _, s := range pairs {
			for _, r := range s {
				b = append(b, byte(r), 0)
			}
			b = append(b, 0, 0)
		}
		return append(b, 0, 0) // terminating empty string
	}

	t.Run("pairs and duplicates", func(t *testing.T) {
		titles := ParseTitles(multiSZ("230", "Process", "784", "ID Process", "680", "Thread Count", "5430", "Thread Count"))
		if got := titles["Process"]; len(got) != 1 || got[0] != 230 {
			t.Errorf("Process = %v, want [230]", got)
		}
		if got := titles["Thread Count"]; len(got) != 2 || got[0] != 680 || got[1] != 5430 {
			t.Errorf("Thread Count = %v, want [680 5430]", got)
		}
	})

	t.Run("malformed pairs skipped", func(t *testing.T) {
		titles := ParseTitles(multiSZ("notanumber", "Bogus", "784", "ID Process", "12", ""))
		if _, ok := titles["Bogus"]; ok {
			t.Error("non-numeric index should be skipped")
		}
		if _, ok := titles[""]; ok {
			t.Error("empty name should be skipped")
		}
		if got := titles["ID Process"]; len(got) != 1 || got[0] != 784 {
			t.Errorf("ID Process = %v, want [784]", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if titles := ParseTitles(nil); len(titles) != 0 {
			t.Errorf("nil input: got %d names, want 0", len(titles))
		}
	})
}

func TestParseDataBlockCorrupt(t *testing.T) {
	fixture := readFixture(t, "perf-process-230.bin")

	mutate := func(off int, v uint32) []byte {
		b := make([]byte, len(fixture))
		copy(b, fixture)
		binary.LittleEndian.PutUint32(b[off:], v)
		return b
	}

	tests := []struct {
		name    string
		blob    []byte
		wantErr bool
	}{
		{"empty", nil, true},
		{"short header", fixture[:40], true},
		{"bad signature", append([]byte("XXXX"), fixture[4:]...), true},
		{"big endian flag", mutate(8, 0), true},
		{"truncated to header", fixture[:104], true},
		{"truncated mid-instances", fixture[:20000], true},
		{"bad data header length", mutate(24, 8), true},
		// Object chain corruptions (object starts at HeaderLength=104).
		{"object total beyond blob", mutate(104, 99999999), true},
		{"counter def chain overshoot", mutate(168, 9999), true}, // first def ByteLength
		{"counter def too small", mutate(168, 4), true},
		// First instance (at 104+1184=1288) failing sanity: tolerated as an
		// instance-less object (PERF_NO_INSTANCES), NOT an error.
		{"first instance implausible", mutate(1288, 4), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects, err := ParseDataBlock(tt.blob)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got none")
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.name == "first instance implausible" {
					if len(objects) != 1 || len(objects[0].Instances) != 0 {
						t.Errorf("want 1 object with 0 instances, got %+v", objects)
					}
				}
			}
		})
	}
}
