package track

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// pinned returns a Tracker whose clock is frozen, so entry and envelope
// timestamps are deterministic for golden comparisons.
func pinned() *Tracker {
	fixed := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	tr := New()
	tr.now = func() time.Time { return fixed }
	tr.started = fixed
	return tr
}

func TestRecordEntriesCount(t *testing.T) {
	tr := New()
	if got := tr.Count(); got != 0 {
		t.Fatalf("new tracker Count = %d, want 0", got)
	}
	if got := tr.Entries(); len(got) != 0 {
		t.Fatalf("new tracker Entries len = %d, want 0", len(got))
	}

	type rec struct {
		cat            Category
		action, target string
		detail         string
		status         Status
	}
	records := []rec{
		{CategoryFile, "put", `\\DC01\SYSVOL\evil.dll`, "from /tmp/evil.dll", StatusSuccess},
		{CategoryRegistry, "add", `HKLM\SOFTWARE\Acme`, `value "Run"`, StatusSuccess},
		{CategoryAD, "changepasswd", `HACKERBLUEPRINT\chg-victim`, "", StatusFailed},
	}
	before := time.Now().UTC()
	for _, r := range records {
		tr.Record(r.cat, r.action, r.target, r.detail, r.status)
	}
	after := time.Now().UTC()

	if got := tr.Count(); got != len(records) {
		t.Fatalf("Count = %d, want %d", got, len(records))
	}
	got := tr.Entries()
	if len(got) != len(records) {
		t.Fatalf("Entries len = %d, want %d", len(got), len(records))
	}
	for i, r := range records {
		e := got[i]
		if e.Category != r.cat || e.Action != r.action || e.Target != r.target ||
			e.Detail != r.detail || e.Status != r.status {
			t.Errorf("entry %d = %+v, want fields of %+v", i, e, r)
		}
		if e.Time.Before(before) || e.Time.After(after) {
			t.Errorf("entry %d time %v outside [%v, %v]", i, e.Time, before, after)
		}
		if e.Time.Location() != time.UTC {
			t.Errorf("entry %d time not UTC: %v", i, e.Time.Location())
		}
	}
}

func TestEntriesReturnsCopy(t *testing.T) {
	tr := New()
	tr.Record(CategoryFile, "rm", `\\DC01\C$\tmp\a.txt`, "", StatusSuccess)

	got := tr.Entries()
	got[0].Action = "MUTATED"
	got = append(got, Entry{Action: "EXTRA"})

	again := tr.Entries()
	if len(again) != 1 || again[0].Action != "rm" {
		t.Fatalf("tracker state leaked through Entries copy: %+v", again)
	}
}

func TestClear(t *testing.T) {
	tr := pinned()
	tr.Record(CategoryTask, "create", `\svcctl job`, "", StatusSuccess)
	tr.Record(CategoryFile, "mkdir", `\\DC01\C$\anv`, "", StatusSuccess)
	if tr.Count() != 2 {
		t.Fatalf("Count before Clear = %d, want 2", tr.Count())
	}
	tr.Clear()
	if tr.Count() != 0 {
		t.Fatalf("Count after Clear = %d, want 0", tr.Count())
	}
	if got := tr.Summary(); got != "no changes recorded" {
		t.Fatalf("Summary after Clear = %q", got)
	}
	// Start time survives Clear: the saved envelope still reflects the session.
	if !tr.started.Equal(time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)) {
		t.Fatalf("Clear reset started to %v", tr.started)
	}
}

func TestSummary(t *testing.T) {
	cases := []struct {
		name    string
		records []Entry
		want    string
	}{
		{
			name:    "empty",
			records: nil,
			want:    "no changes recorded",
		},
		{
			name: "single success",
			records: []Entry{
				{Category: CategoryFile, Action: "put", Target: `\\DC01\SYSVOL\x`, Status: StatusSuccess},
			},
			want: "1 change recorded (1 succeeded, 0 failed)\n  FILE     1",
		},
		{
			name: "mixed categories with failure and unknown category",
			records: []Entry{
				{Category: CategoryAD, Action: "changepasswd", Target: "u1", Status: StatusFailed},
				{Category: CategoryFile, Action: "put", Target: "a", Status: StatusSuccess},
				{Category: CategoryFile, Action: "rm", Target: "b", Status: StatusSuccess},
				{Category: CategoryTask, Action: "create", Target: `\At1`, Status: StatusSuccess},
				{Category: Category("WMI"), Action: "invoke", Target: "host", Status: StatusSuccess},
			},
			want: "5 changes recorded (4 succeeded, 1 failed)" +
				"\n  FILE     2" +
				"\n  TASK     1" +
				"\n  AD       1" +
				"\n  WMI      1",
		},
		{
			name: "all failed",
			records: []Entry{
				{Category: CategoryService, Action: "create", Target: "svc", Status: StatusFailed},
				{Category: CategoryRegistry, Action: "add", Target: `HKLM\X`, Status: StatusFailed},
			},
			want: "2 changes recorded (0 succeeded, 2 failed)" +
				"\n  SERVICE  1" +
				"\n  REGISTRY 1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := pinned()
			for _, e := range tc.records {
				tr.Record(e.Category, e.Action, e.Target, e.Detail, e.Status)
			}
			if got := tr.Summary(); got != tc.want {
				t.Errorf("Summary():\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestSaveJSONRoundTrip(t *testing.T) {
	tr := pinned()
	tr.Record(CategoryFile, "put", `\\DC01\SYSVOL\evil.dll`, "from /tmp/evil.dll", StatusSuccess)
	tr.Record(CategoryAD, "changepasswd", `HACKERBLUEPRINT\chg-victim`, "", StatusFailed)

	path := filepath.Join(t.TempDir(), "nested", "changes.json")
	if err := tr.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved log: %v", err)
	}
	var env fileEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("saved log is not valid JSON: %v", err)
	}
	if env.Tool != "anvil" || env.Version != schemaVersion || env.Count != 2 {
		t.Errorf("envelope header = tool %q version %d count %d, want anvil/%d/2",
			env.Tool, env.Version, env.Count, schemaVersion)
	}
	if len(env.Entries) != 2 {
		t.Fatalf("envelope entries len = %d, want 2", len(env.Entries))
	}
	want := tr.Entries()
	for i := range want {
		if env.Entries[i] != want[i] {
			t.Errorf("entry %d round-trip = %+v, want %+v", i, env.Entries[i], want[i])
		}
	}

	// Atomicity: the directory holds exactly the renamed log, no temp debris.
	dirEntries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirEntries) != 1 || dirEntries[0].Name() != "changes.json" {
		names := []string{}
		for _, de := range dirEntries {
			names = append(names, de.Name())
		}
		t.Errorf("leftover files in log dir: %v", names)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("log mode = %o, want 600", perm)
		}
	}

	// Saving over an existing log must succeed (Windows rename fallback).
	tr.Record(CategoryExec, "run", "DC01", "whoami /all", StatusSuccess)
	if err := tr.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON over existing: %v", err)
	}
	raw, _ = os.ReadFile(path)
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.Count != 3 {
		t.Errorf("overwritten log count = %d, want 3", env.Count)
	}
}

func TestSaveJSONEmptyTrackerEntriesArray(t *testing.T) {
	tr := pinned()
	path := filepath.Join(t.TempDir(), "changes.json")
	if err := tr.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Schema stability: entries must serialize as an empty array, not null.
	if !strings.Contains(string(raw), `"entries": []`) {
		t.Errorf("empty tracker log missing `\"entries\": []\":\n%s", raw)
	}
}

func TestSaveJSONEmptyPath(t *testing.T) {
	tr := New()
	if err := tr.SaveJSON(""); err == nil {
		t.Fatal("SaveJSON(\"\") = nil error, want error")
	}
}

// TestSchemaStability pins the exact byte layout of the saved log. If this
// test breaks, the JSON schema changed — bump schemaVersion and think
// about log consumers before accepting the new golden.
func TestSchemaStability(t *testing.T) {
	cases := []struct {
		name    string
		records []Entry
		want    string
	}{
		{
			name:    "empty",
			records: nil,
			want: `{
  "tool": "anvil",
  "version": 1,
  "started": "2026-07-20T18:00:00Z",
  "saved": "2026-07-20T18:00:00Z",
  "count": 0,
  "entries": []
}
`,
		},
		{
			name: "two entries",
			records: []Entry{
				{
					Category: CategoryFile,
					Action:   "put",
					Target:   `\\DC01\SYSVOL\evil.dll`,
					Detail:   "from /tmp/evil.dll",
					Status:   StatusSuccess,
				},
				{
					Category: CategoryAD,
					Action:   "changepasswd",
					Target:   `HACKERBLUEPRINT\chg-victim`,
					Detail:   "",
					Status:   StatusFailed,
				},
			},
			want: `{
  "tool": "anvil",
  "version": 1,
  "started": "2026-07-20T18:00:00Z",
  "saved": "2026-07-20T18:00:00Z",
  "count": 2,
  "entries": [
    {
      "time": "2026-07-20T18:00:00Z",
      "category": "FILE",
      "action": "put",
      "target": "\\\\DC01\\SYSVOL\\evil.dll",
      "detail": "from /tmp/evil.dll",
      "status": "success"
    },
    {
      "time": "2026-07-20T18:00:00Z",
      "category": "AD",
      "action": "changepasswd",
      "target": "HACKERBLUEPRINT\\chg-victim",
      "detail": "",
      "status": "failed"
    }
  ]
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := pinned()
			for _, e := range tc.records {
				tr.Record(e.Category, e.Action, e.Target, e.Detail, e.Status)
			}
			path := filepath.Join(t.TempDir(), "changes.json")
			if err := tr.SaveJSON(path); err != nil {
				t.Fatalf("SaveJSON: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tc.want {
				t.Errorf("saved log bytes changed:\n--- got ---\n%s\n--- want ---\n%s", raw, tc.want)
			}
		})
	}
}

func TestDirAndDefaultPath(t *testing.T) {
	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	for _, part := range []string{".anvil", "logs", "changes"} {
		if !strings.Contains(dir, part) {
			t.Errorf("Dir %q missing component %q", dir, part)
		}
	}

	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if filepath.Dir(p) != dir {
		t.Errorf("DefaultPath %q not under Dir %q", p, dir)
	}
	base := filepath.Base(p)
	if !strings.HasPrefix(base, "changes-") || !strings.HasSuffix(base, ".json") {
		t.Errorf("DefaultPath base %q, want changes-<timestamp>.json", base)
	}
}

// TestConcurrentUse exercises the mutex from multiple goroutines. The
// shell is single-goroutine, but the tracker must not corrupt state if a
// background helper ever records out of band. Run with -race for the
// full benefit.
func TestConcurrentUse(t *testing.T) {
	tr := New()
	const workers = 8
	const perWorker = 100

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				tr.Record(CategoryFile, "put", "target", "", StatusSuccess)
				_ = tr.Count()
				_ = tr.Entries()
				_ = tr.Summary()
			}
		}(w)
	}
	wg.Wait()

	if got := tr.Count(); got != workers*perWorker {
		t.Fatalf("Count = %d, want %d", got, workers*perWorker)
	}
}
