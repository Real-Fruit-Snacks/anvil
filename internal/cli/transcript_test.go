package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"anvil/internal/ui"
)

func TestStartTranscript(t *testing.T) {
	// Parent directories of the transcript path are created on demand.
	path := filepath.Join(t.TempDir(), "nested", "transcript.txt")
	real := os.Stdout

	restore, err := startTranscript(path, "dc01.corp.local")
	if err != nil {
		t.Fatalf("startTranscript: %v", err)
	}
	if os.Stdout == real {
		t.Error("os.Stdout was not swapped for the pipe")
	}
	fmt.Println("operator sees this")
	// The themed ui printers write through fatih/color's cached Output;
	// the transcript must capture those too.
	ui.Faint.Println("themed line")
	restore()

	if os.Stdout != real {
		t.Error("os.Stdout was not restored")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	content := string(data)

	// started marker, the captured lines, ended marker — in that order.
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("transcript = %d lines, want 4:\n%s", len(lines), content)
	}
	if !strings.HasPrefix(lines[0], "# anvil transcript dc01.corp.local started ") {
		t.Errorf("started marker malformed: %q", lines[0])
	}
	if lines[1] != "operator sees this" {
		t.Errorf("captured line = %q, want %q", lines[1], "operator sees this")
	}
	if !strings.Contains(lines[2], "themed line") {
		t.Errorf("themed ui output missing from transcript: %q", lines[2])
	}
	if !strings.HasPrefix(lines[3], "# ended ") {
		t.Errorf("ended marker malformed: %q", lines[3])
	}
	for i, prefix := range []string{
		"# anvil transcript dc01.corp.local started ",
		"# ended ",
	} {
		line := lines[0]
		if i == 1 {
			line = lines[3]
		}
		ts := strings.TrimPrefix(line, prefix)
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("marker timestamp %q is not RFC3339: %v", ts, err)
		}
	}
}

func TestStartTranscriptPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are advisory on Windows (NTFS ACLs govern access)")
	}
	path := filepath.Join(t.TempDir(), "transcript.txt")
	restore, err := startTranscript(path, "host")
	if err != nil {
		t.Fatalf("startTranscript: %v", err)
	}
	restore()
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("transcript mode = %o, want 600", got)
	}
}

func TestStartTranscriptBadPath(t *testing.T) {
	// A transcript path under a regular file cannot be created; the
	// failure must leave os.Stdout untouched.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	real := os.Stdout
	restore, err := startTranscript(filepath.Join(blocker, "t.txt"), "host")
	if err == nil {
		if restore != nil {
			restore()
		}
		t.Fatal("startTranscript under a regular file: want error, got nil")
	}
	if restore != nil {
		t.Error("restore closure should be nil on failure")
	}
	if os.Stdout != real {
		t.Error("os.Stdout swapped despite the failure")
	}
}
