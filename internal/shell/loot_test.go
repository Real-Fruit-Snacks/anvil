package shell

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// useTempHome points the anvil state dir convention (~/.anvil) at a temp
// home for the duration of the test (same trick as smbclient's tests):
// HOME for linux, USERPROFILE for windows.
func useTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

// captureStdout runs fn with stdout redirected to a pipe and returns
// everything written to it. Both os.Stdout (fmt.*) and fatih/color's
// cached Output (the ui.* printers) are redirected, mirroring how the
// connect --transcript capture works.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	real := os.Stdout
	realColor := color.Output
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	color.Output = w
	fn()
	w.Close()
	os.Stdout = real
	color.Output = realColor
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String()
}

func TestLootHost(t *testing.T) {
	cases := []struct {
		name, host, want string
	}{
		{"fqdn kept", "dc01.corp.local", "dc01.corp.local"},
		{"ipv4 kept", "10.0.0.5", "10.0.0.5"},
		{"ipv6 colons sanitized", "2001:db8::1", "2001_db8__1"},
		{"forward slash sanitized", "corp/dc01", "corp_dc01"},
		{"backslash sanitized", `corp\dc01`, "corp_dc01"},
		{"empty stays empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lootHost(c.host); got != c.want {
				t.Errorf("lootHost(%q) = %q, want %q", c.host, got, c.want)
			}
		})
	}
}

func TestDefaultLootDir(t *testing.T) {
	home := t.TempDir()
	cases := []struct {
		name, host, wantElem string
	}{
		{"fqdn element", "dc01.corp.local", "dc01.corp.local"},
		{"ipv4 element", "10.0.0.5", "10.0.0.5"},
		{"ipv6 element sanitized", "fe80::1", "fe80__1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := filepath.Join(home, ".anvil", "loot", c.wantElem)
			if got := defaultLootDir(home, c.host); got != want {
				t.Errorf("defaultLootDir(%q, %q) = %q, want %q", home, c.host, got, want)
			}
		})
	}
}

func TestLootDirResolution(t *testing.T) {
	home := useTempHome(t)
	s := &shell{}
	// Never set: the per-target default under ~/.anvil/loot. A sessionless
	// shell (tests) contributes an empty host element.
	if got, want := s.lootDir(), filepath.Join(home, ".anvil", "loot"); got != want {
		t.Errorf("lootDir() default = %q, want %q", got, want)
	}
	// Default is computed lazily, not created on read.
	if _, err := os.Stat(filepath.Join(home, ".anvil")); !os.IsNotExist(err) {
		t.Errorf("default loot dir was created on read: %v", err)
	}
	// Explicitly set: returned verbatim.
	dir := filepath.Join(home, "engagement")
	s.lootDirSet = dir
	if got := s.lootDir(); got != dir {
		t.Errorf("lootDir() set = %q, want %q", got, dir)
	}
}

func TestLootPath(t *testing.T) {
	dir := t.TempDir()
	s := &shell{}
	s.lootDirSet = dir

	cases := []struct {
		name, in, want string
	}{
		{"bare filename lands in loot dir", "hashes.txt", filepath.Join(dir, "hashes.txt")},
		{"dotted filename lands in loot dir", "dc01.kerb.txt", filepath.Join(dir, "dc01.kerb.txt")},
		{"forward-slash path used as-is", "out/hashes.txt", "out/hashes.txt"},
		{"backslash path used as-is", `out\hashes.txt`, `out\hashes.txt`},
		{"absolute path used as-is", filepath.Join(dir, "sub", "h.txt"), filepath.Join(dir, "sub", "h.txt")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.lootPath(c.in); got != c.want {
				t.Errorf("lootPath(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestWriteLootLines(t *testing.T) {
	cases := []struct {
		name   string
		subdir string
		header string
		lines  []string
		want   string
	}{
		{
			name:   "header plus one line per entry",
			header: "kerberoast corp.local",
			lines:  []string{"alice:$krb5tgs$...", "bob:$krb5tgs$..."},
			want:   "# kerberoast corp.local\nalice:$krb5tgs$...\nbob:$krb5tgs$...\n",
		},
		{
			name:   "empty lines writes header only",
			header: "asrep corp.local",
			lines:  nil,
			want:   "# asrep corp.local\n",
		},
		{
			name:   "parent directories auto-created",
			subdir: filepath.Join("nested", "deeper"),
			header: "dcsync",
			lines:  []string{"krbtgt:502:aad3b..."},
			want:   "# dcsync\nkrbtgt:502:aad3b...\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.subdir, "loot.txt")
			if err := WriteLootLines(path, c.header, c.lines); err != nil {
				t.Fatalf("WriteLootLines: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read loot file: %v", err)
			}
			if string(data) != c.want {
				t.Errorf("loot file = %q, want %q", string(data), c.want)
			}
		})
	}

	t.Run("empty path is an error", func(t *testing.T) {
		if err := WriteLootLines("", "h", nil); err == nil {
			t.Error("WriteLootLines with empty path: want error, got nil")
		}
	})

	t.Run("unwritable parent is an error", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := WriteLootLines(filepath.Join(blocker, "loot.txt"), "h", nil); err == nil {
			t.Error("WriteLootLines under a regular file: want error, got nil")
		}
	})
}

func TestWriteLootLinesPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are advisory on Windows (NTFS ACLs govern access)")
	}
	path := filepath.Join(t.TempDir(), "sub", "loot.txt")
	if err := WriteLootLines(path, "h", []string{"a"}); err != nil {
		t.Fatalf("WriteLootLines: %v", err)
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("loot file mode = %o, want 600", got)
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if got := di.Mode().Perm(); got != 0700 {
		t.Errorf("loot dir mode = %o, want 700", got)
	}
}

func TestCmdLoot(t *testing.T) {
	t.Run("set creates the dir 0700 and prints it", func(t *testing.T) {
		s := &shell{}
		dir := filepath.Join(t.TempDir(), "loot")
		out := captureStdout(t, func() { s.cmdLoot([]string{dir}) })

		if s.lootDirSet != dir {
			t.Errorf("s.lootDirSet = %q, want %q", s.lootDirSet, dir)
		}
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			t.Fatalf("loot dir not created: %v", err)
		}
		if runtime.GOOS != "windows" {
			if got := fi.Mode().Perm(); got != 0700 {
				t.Errorf("loot dir mode = %o, want 700", got)
			}
		}
		if !strings.Contains(out, dir) {
			t.Errorf("output %q does not name the dir %q", out, dir)
		}
	})

	t.Run("unquoted words join into one path", func(t *testing.T) {
		s := &shell{}
		t.Chdir(t.TempDir())
		captureStdout(t, func() { s.cmdLoot([]string{"my", "loot"}) })

		if s.lootDirSet != "my loot" {
			t.Errorf("s.lootDirSet = %q, want %q", s.lootDirSet, "my loot")
		}
		if fi, err := os.Stat("my loot"); err != nil || !fi.IsDir() {
			t.Errorf("joined dir not created: %v", err)
		}
	})

	t.Run("bare prints the current setting", func(t *testing.T) {
		s := &shell{}
		dir := t.TempDir()
		s.lootDirSet = dir
		out := captureStdout(t, func() { s.cmdLoot(nil) })
		if strings.TrimSpace(out) != dir {
			t.Errorf("bare loot printed %q, want %q", out, dir)
		}
	})

	t.Run("uncreatable dir reports error and keeps old setting", func(t *testing.T) {
		s := &shell{}
		old := t.TempDir()
		s.lootDirSet = old
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		out := captureStdout(t, func() { s.cmdLoot([]string{filepath.Join(blocker, "loot")}) })

		if s.lootDirSet != old {
			t.Errorf("setting changed on failure: %q, want %q", s.lootDirSet, old)
		}
		if !strings.Contains(out, "error:") {
			t.Errorf("output %q missing themed error label", out)
		}
	})
}
