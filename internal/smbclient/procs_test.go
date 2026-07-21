package smbclient

import (
	"errors"
	"os"
	"testing"

	"anvil/internal/perf"
)

// The fixtures live in internal/perf/testdata (the perf package owns the
// parser they exercise); they are live Server 2022 DC captures, reused here
// to drive the smbclient-side resolution/mapping logic end to end.
const (
	procBlobFixture   = "../perf/testdata/perf-process-230.bin"
	procTitlesFixture = "../perf/testdata/perf-titles-009.bin"
)

func TestResolveProcIndexes(t *testing.T) {
	t.Run("nil titles falls back to builtin", func(t *testing.T) {
		if got := resolveProcIndexes(nil); got != builtinProcIndexes {
			t.Errorf("resolveProcIndexes(nil) = %+v, want builtin %+v", got, builtinProcIndexes)
		}
	})

	t.Run("resolves from titles, first candidate wins", func(t *testing.T) {
		// Mirrors the real Server 2022 database: the Job Object families
		// re-use the counter names with later (higher) indexes.
		titles := map[string][]uint32{
			"Process":             {230},
			"ID Process":          {784},
			"Creating Process ID": {1410, 5438},
			"Handle Count":        {952, 5444},
			"Thread Count":        {680, 5430},
		}
		want := procIndexes{object: 230, pid: 784, ppid: 1410, handles: 952, threads: 680}
		if got := resolveProcIndexes(titles); got != want {
			t.Errorf("resolveProcIndexes = %+v, want %+v", got, want)
		}
	})

	t.Run("any missing name falls back to the whole builtin set", func(t *testing.T) {
		titles := map[string][]uint32{
			"Process":    {999},
			"ID Process": {888},
			// "Creating Process ID", "Handle Count", "Thread Count" absent.
		}
		if got := resolveProcIndexes(titles); got != builtinProcIndexes {
			t.Errorf("resolveProcIndexes(partial) = %+v, want builtin %+v", got, builtinProcIndexes)
		}
	})

	t.Run("real Server 2022 title database", func(t *testing.T) {
		data, err := os.ReadFile(procTitlesFixture)
		if err != nil {
			t.Fatalf("read titles fixture: %v", err)
		}
		want := procIndexes{object: 230, pid: 784, ppid: 1410, handles: 952, threads: 680}
		if got := resolveProcIndexes(perf.ParseTitles(data)); got != want {
			t.Errorf("resolveProcIndexes(real DB) = %+v, want %+v", got, want)
		}
	})
}

func TestProcsFromObjectFixture(t *testing.T) {
	blob, err := os.ReadFile(procBlobFixture)
	if err != nil {
		t.Fatalf("read blob fixture: %v", err)
	}
	objects, err := perf.ParseDataBlock(blob)
	if err != nil {
		t.Fatalf("ParseDataBlock: %v", err)
	}

	procs := procsFromObject(objects[0], builtinProcIndexes)

	// 120 captured instances minus the synthetic _Total row.
	if len(procs) != 119 {
		t.Fatalf("procs = %d, want 119 (_Total skipped)", len(procs))
	}
	for _, p := range procs {
		if p.Name == "_Total" {
			t.Fatal("_Total leaked into process list")
		}
	}

	// Sorted by PID ascending.
	for i := 1; i < len(procs); i++ {
		if procs[i].PID < procs[i-1].PID {
			t.Fatalf("not sorted by PID: [%d]=%d after [%d]=%d", i-1, procs[i-1].PID, i, procs[i].PID)
		}
	}

	byPID := map[uint32]ProcInfo{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	// Exact values from the capture.
	if p, ok := byPID[4]; !ok || p.Name != "System" || p.PPID != 0 || p.Handles != 2540 || p.Threads != 128 {
		t.Errorf("PID 4 = %+v (present %v), want System ppid=0 handles=2540 threads=128", p, ok)
	}
	if p, ok := byPID[672]; !ok || p.Name != "lsass" || p.PPID != 520 || p.Threads != 31 {
		t.Errorf("PID 672 = %+v (present %v), want lsass ppid=520 threads=31", p, ok)
	}
	if p, ok := byPID[0]; !ok || p.Name != "Idle" {
		t.Errorf("PID 0 = %+v (present %v), want Idle", p, ok)
	}
}

func TestProcsFromObjectSynthetic(t *testing.T) {
	idx := builtinProcIndexes
	mk := func(name string, pid, ppid, handles, threads uint64) perf.Instance {
		return perf.Instance{Name: name, Values: map[uint32]uint64{
			idx.pid: pid, idx.ppid: ppid, idx.handles: handles, idx.threads: threads,
		}}
	}
	obj := &perf.Object{Instances: []perf.Instance{
		mk("_Total", 0, 0, 999, 999),
		mk("bravo", 20, 4, 10, 2),
		// Missing counters must read as zero (racy perflib snapshot).
		{Name: "alpha", Values: map[uint32]uint64{idx.pid: 10, idx.ppid: 4}},
		mk("charlie", 30, 4, 5, 1),
	}}

	procs := procsFromObject(obj, idx)
	if len(procs) != 3 {
		t.Fatalf("procs = %d, want 3 (_Total skipped)", len(procs))
	}
	if procs[0].PID != 10 || procs[1].PID != 20 || procs[2].PID != 30 {
		t.Errorf("order = %d,%d,%d, want sorted 10,20,30", procs[0].PID, procs[1].PID, procs[2].PID)
	}
	alpha := procs[0]
	if alpha.Name != "alpha" || alpha.Handles != 0 || alpha.Threads != 0 {
		t.Errorf("alpha = %+v, want missing counters as zero", alpha)
	}
}

func TestMapProcError(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"open HKEY_PERFORMANCE_DATA: 0x00000005", "access denied"},
		{"BaseRegQueryValue(230) failed: 0x00000002", "server has no such performance data (value not found)"},
		{"bind: 0x1c010002", "performance counters not supported on this server"},
		{"perf: data block too small (0 bytes)", "performance counters not supported on this server"}, // Samba empty blob
		{"open winreg pipe: An instance of a named pipe cannot be found in the listening state.", "RemoteRegistry service is not running on the target"},
		{"some other failure", "some other failure"}, // pass-through
	}
	for _, tt := range tests {
		if got := mapProcError(errors.New(tt.in)).Error(); got != tt.want {
			t.Errorf("mapProcError(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
