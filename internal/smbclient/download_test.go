package smbclient

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// useTempHome points the anvil state dir convention (~/.anvil) at a temp
// home for the duration of the test. Both HOME (linux) and USERPROFILE
// (windows) are set so the tests exercise the same code path on either CI
// runner.
func useTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestNumChunks(t *testing.T) {
	cases := []struct {
		name        string
		size, chunk int64
		want        int64
	}{
		{"empty file", 0, 65536, 0},
		{"one byte", 1, 65536, 1},
		{"exactly one chunk", 65536, 65536, 1},
		{"chunk plus one byte", 65537, 65536, 2},
		{"aligned multi-chunk", 5 * 65536, 65536, 5},
		{"unaligned multi-chunk", 5*65536 + 123, 65536, 6},
		{"chunk bigger than file", 100, 65536, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := numChunks(c.size, c.chunk); got != c.want {
				t.Errorf("numChunks(%d, %d) = %d, want %d", c.size, c.chunk, got, c.want)
			}
		})
	}
}

func TestChunkRange(t *testing.T) {
	cases := []struct {
		name             string
		idx, size, chunk int64
		wantOff, wantLen int64
	}{
		{"first chunk", 0, 200000, 65536, 0, 65536},
		{"middle chunk", 2, 200000, 65536, 131072, 65536},
		{"last short chunk", 3, 200000, 65536, 196608, 3392},
		{"aligned last chunk", 1, 131072, 65536, 65536, 65536},
		{"tiny file", 0, 10, 65536, 0, 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			off, length := chunkRange(c.idx, c.size, c.chunk)
			if off != c.wantOff || length != c.wantLen {
				t.Errorf("chunkRange(%d, %d, %d) = (%d, %d), want (%d, %d)",
					c.idx, c.size, c.chunk, off, length, c.wantOff, c.wantLen)
			}
		})
	}
}

func TestDownloadStatePath(t *testing.T) {
	home := useTempHome(t)

	p1, err := downloadStatePath("out.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}
	// Deterministic for the same destination (same cwd → same abs path).
	p2, err := downloadStatePath("out.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}
	if p1 != p2 {
		t.Errorf("state path not deterministic: %q vs %q", p1, p2)
	}
	// Distinct destinations get distinct state files.
	p3, err := downloadStatePath("other.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}
	if p1 == p3 {
		t.Errorf("distinct local paths share a state file: %q", p1)
	}
	// Naming convention: download_<32 hex chars>.json under ~/.anvil/downloads.
	base := filepath.Base(p1)
	if !strings.HasPrefix(base, "download_") || !strings.HasSuffix(base, ".json") || len(base) != len("download_")+32+len(".json") {
		t.Errorf("state file name %q does not match download_<md5>.json", base)
	}
	wantDir := filepath.Join(home, ".anvil", "downloads")
	if filepath.Dir(p1) != wantDir {
		t.Errorf("state dir = %q, want %q", filepath.Dir(p1), wantDir)
	}
}

func TestDownloadStateDirPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are advisory on Windows (NTFS ACLs govern access)")
	}
	home := useTempHome(t)
	if _, err := downloadStatePath("x.bin"); err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}
	fi, err := os.Stat(filepath.Join(home, ".anvil", "downloads"))
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0700 {
		t.Errorf("state dir mode = %o, want 700", got)
	}
}

func TestDownloadStateRoundTrip(t *testing.T) {
	useTempHome(t)
	sp, err := downloadStatePath("round.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}

	want := &downloadState{
		Version:     downloadStateVersion,
		RemotePath:  "Windows/Temp/big.bin",
		LocalPath:   "round.bin",
		Size:        5*65536 + 123,
		ModTimeUnix: 133998877665544332,
		ChunkSize:   65536,
		BytesDone:   2 * 65536,
		Chunks:      map[int64]int64{0: 65536, 1: 65536},
	}
	if err := writeDownloadState(sp, want); err != nil {
		t.Fatalf("writeDownloadState: %v", err)
	}

	got, err := loadDownloadState(sp)
	if err != nil {
		t.Fatalf("loadDownloadState: %v", err)
	}
	if got == nil {
		t.Fatal("loadDownloadState returned nil state for an existing file")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}

	// State file is 0600 (unix; Windows ACLs make mode bits moot).
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(sp)
		if err != nil {
			t.Fatalf("stat state file: %v", err)
		}
		if got := fi.Mode().Perm(); got != 0600 {
			t.Errorf("state file mode = %o, want 600", got)
		}
	}
}

func TestWriteDownloadStateAtomicOverwrite(t *testing.T) {
	useTempHome(t)
	sp, err := downloadStatePath("over.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}

	st := &downloadState{Version: downloadStateVersion, Size: 10, ChunkSize: 4, Chunks: map[int64]int64{}}
	for i := int64(0); i < 3; i++ {
		st.BytesDone += 4
		st.Chunks[i] = 4
		if err := writeDownloadState(sp, st); err != nil {
			t.Fatalf("writeDownloadState iteration %d: %v", i, err)
		}
	}
	// Rename-over-existing must leave no temp file behind.
	if _, err := os.Stat(sp + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp state file %s left behind", sp+".tmp")
	}
	got, err := loadDownloadState(sp)
	if err != nil {
		t.Fatalf("loadDownloadState: %v", err)
	}
	if got.BytesDone != 12 || len(got.Chunks) != 3 {
		t.Errorf("state after overwrites = %+v, want 12 bytes over 3 chunks", got)
	}
}

func TestLoadDownloadStateErrors(t *testing.T) {
	useTempHome(t)
	sp, err := downloadStatePath("bad.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}

	// Missing file → (nil, nil): no prior progress, not an error.
	st, err := loadDownloadState(sp)
	if err != nil || st != nil {
		t.Errorf("missing state = (%v, %v), want (nil, nil)", st, err)
	}

	// Corrupt JSON → error.
	if err := os.WriteFile(sp, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDownloadState(sp); err == nil {
		t.Error("corrupt JSON: expected error, got nil")
	}

	// Wrong schema version → error.
	if err := os.WriteFile(sp, []byte(`{"version":99,"chunks":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDownloadState(sp); err == nil {
		t.Error("wrong version: expected error, got nil")
	}
}

// TestCheckResumeState drives the resume-offset/mismatch rules: a run may
// only continue when remote size, remote mtime, chunk size, and the local
// partial all match the saved state; every mismatch names --restart.
func TestCheckResumeState(t *testing.T) {
	tmp := t.TempDir()
	local := filepath.Join(tmp, "partial.bin")

	base := &downloadState{
		Size:        200000,
		ModTimeUnix: 133998877665544332,
		ChunkSize:   65536,
		Chunks:      map[int64]int64{0: 65536},
	}

	// Local partial exists at the full pre-sized length.
	if err := os.WriteFile(local, make([]byte, base.Size), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mutate  func(st *downloadState) (size, modTime int64, chunkSize int, path string)
		wantErr bool
	}{
		{
			name: "everything matches",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				return st.Size, st.ModTimeUnix, st.ChunkSize, local
			},
		},
		{
			name: "remote size changed",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				return st.Size + 1, st.ModTimeUnix, st.ChunkSize, local
			},
			wantErr: true,
		},
		{
			name: "remote mtime changed",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				return st.Size, st.ModTimeUnix + 1, st.ChunkSize, local
			},
			wantErr: true,
		},
		{
			name: "chunk size changed",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				return st.Size, st.ModTimeUnix, st.ChunkSize * 2, local
			},
			wantErr: true,
		},
		{
			name: "local partial deleted",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				return st.Size, st.ModTimeUnix, st.ChunkSize, filepath.Join(tmp, "gone.bin")
			},
			wantErr: true,
		},
		{
			name: "local partial resized",
			mutate: func(st *downloadState) (int64, int64, int, string) {
				other := filepath.Join(tmp, "resized.bin")
				if err := os.WriteFile(other, make([]byte, 123), 0644); err != nil {
					t.Fatal(err)
				}
				return st.Size, st.ModTimeUnix, st.ChunkSize, other
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			size, modTime, chunkSize, path := c.mutate(base)
			err := checkResumeState(base, size, modTime, chunkSize, path)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "--restart") {
					t.Errorf("error %q does not direct the user to --restart", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDownloadStateRecount(t *testing.T) {
	st := &downloadState{
		Size:      3*65536 + 100,
		ChunkSize: 65536,
		Chunks: map[int64]int64{
			0: 65536,
			1: 65536,
			2: 12345, // torn record: length mismatch → pending again
			3: 100,   // last short chunk, complete
			9: 65536, // out-of-range index (hand-edited) → ignored
		},
	}
	st.recount()
	want := int64(2*65536 + 100)
	if st.BytesDone != want {
		t.Errorf("BytesDone = %d, want %d (only complete in-range chunks count)", st.BytesDone, want)
	}
}

// TestPrepareDownloadState covers the state-policy matrix without a
// session: restart/plain discard, resume validation, fresh fallback.
func TestPrepareDownloadState(t *testing.T) {
	const (
		size    = int64(200000)
		modTime = int64(133998877665544332)
		chunkSz = 65536
	)

	setup := func(t *testing.T) (sp, local string) {
		t.Helper()
		useTempHome(t)
		tmp := t.TempDir()
		local = filepath.Join(tmp, "file.bin")
		var err error
		sp, err = downloadStatePath(local)
		if err != nil {
			t.Fatalf("downloadStatePath: %v", err)
		}
		return sp, local
	}
	writePartial := func(t *testing.T, local string) {
		t.Helper()
		if err := os.WriteFile(local, make([]byte, size), 0644); err != nil {
			t.Fatal(err)
		}
	}
	savedState := func() *downloadState {
		return &downloadState{
			Version:     downloadStateVersion,
			RemotePath:  "share/file.bin",
			LocalPath:   "unused",
			Size:        size,
			ModTimeUnix: modTime,
			ChunkSize:   chunkSz,
			BytesDone:   65536,
			Chunks:      map[int64]int64{0: 65536},
		}
	}

	t.Run("plain download discards stale state", func(t *testing.T) {
		sp, local := setup(t)
		if err := writeDownloadState(sp, savedState()); err != nil {
			t.Fatal(err)
		}
		st, resumed, err := prepareDownloadState(sp, "r", local, size, modTime, chunkSz, DownloadOptions{})
		if err != nil {
			t.Fatalf("prepareDownloadState: %v", err)
		}
		if resumed {
			t.Error("resumed = true, want false for a plain download")
		}
		if len(st.Chunks) != 0 || st.BytesDone != 0 {
			t.Errorf("fresh state carries progress: %+v", st)
		}
		if _, err := os.Stat(sp); !os.IsNotExist(err) {
			t.Error("stale state file not discarded")
		}
	})

	t.Run("restart discards state", func(t *testing.T) {
		sp, local := setup(t)
		if err := writeDownloadState(sp, savedState()); err != nil {
			t.Fatal(err)
		}
		_, resumed, err := prepareDownloadState(sp, "r", local, size, modTime, chunkSz, DownloadOptions{Restart: true})
		if err != nil {
			t.Fatalf("prepareDownloadState: %v", err)
		}
		if resumed {
			t.Error("resumed = true under --restart")
		}
		if _, err := os.Stat(sp); !os.IsNotExist(err) {
			t.Error("state file survived --restart")
		}
	})

	t.Run("resume without state starts fresh", func(t *testing.T) {
		sp, local := setup(t)
		_, resumed, err := prepareDownloadState(sp, "r", local, size, modTime, chunkSz, DownloadOptions{Resume: true})
		if err != nil {
			t.Fatalf("prepareDownloadState: %v", err)
		}
		if resumed {
			t.Error("resumed = true with no state on disk")
		}
	})

	t.Run("resume with corrupt state errors", func(t *testing.T) {
		sp, local := setup(t)
		if err := os.MkdirAll(filepath.Dir(sp), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sp, []byte("{junk"), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := prepareDownloadState(sp, "r", local, size, modTime, chunkSz, DownloadOptions{Resume: true})
		if err == nil {
			t.Fatal("expected error for corrupt state under --resume")
		}
		if !strings.Contains(err.Error(), "--restart") {
			t.Errorf("error %q does not direct the user to --restart", err)
		}
	})

	t.Run("resume with matching state continues", func(t *testing.T) {
		sp, local := setup(t)
		writePartial(t, local)
		if err := writeDownloadState(sp, savedState()); err != nil {
			t.Fatal(err)
		}
		st, resumed, err := prepareDownloadState(sp, "r", local, size, modTime, chunkSz, DownloadOptions{Resume: true})
		if err != nil {
			t.Fatalf("prepareDownloadState: %v", err)
		}
		if !resumed {
			t.Error("resumed = false, want true")
		}
		if st.Chunks[0] != 65536 || st.BytesDone != 65536 {
			t.Errorf("resumed state lost progress: %+v", st)
		}
	})

	t.Run("resume with changed remote errors", func(t *testing.T) {
		sp, local := setup(t)
		writePartial(t, local)
		if err := writeDownloadState(sp, savedState()); err != nil {
			t.Fatal(err)
		}
		_, _, err := prepareDownloadState(sp, "r", local, size+4096, modTime, chunkSz, DownloadOptions{Resume: true})
		if err == nil {
			t.Fatal("expected error for changed remote size under --resume")
		}
		if !strings.Contains(err.Error(), "--restart") {
			t.Errorf("error %q does not direct the user to --restart", err)
		}
	})
}

// TestPrepareDownloadStateFreshFields pins the fresh-state shape a first
// run starts from.
func TestPrepareDownloadStateFreshFields(t *testing.T) {
	useTempHome(t)
	sp, err := downloadStatePath("fresh.bin")
	if err != nil {
		t.Fatalf("downloadStatePath: %v", err)
	}
	st, resumed, err := prepareDownloadState(sp, "Windows/big.bin", "fresh.bin", 12345, 6789, 4096, DownloadOptions{})
	if err != nil {
		t.Fatalf("prepareDownloadState: %v", err)
	}
	if resumed {
		t.Error("resumed = true for a first run")
	}
	want := &downloadState{
		Version:     downloadStateVersion,
		RemotePath:  "Windows/big.bin",
		LocalPath:   "fresh.bin",
		Size:        12345,
		ModTimeUnix: 6789,
		ChunkSize:   4096,
		BytesDone:   0,
		Chunks:      map[int64]int64{},
	}
	if fmt.Sprintf("%+v", st) != fmt.Sprintf("%+v", want) {
		t.Errorf("fresh state = %+v, want %+v", st, want)
	}
}
