package shell

// Session loot: a per-session directory where roast/dump output lands.
// `loot` shows or sets it, lootPath resolves bare filenames against it,
// and WriteLootLines is the writer the roast/dump handlers call. Mirrors
// the track package's ~/.anvil conventions (0700 dirs, 0600 files — mode
// bits are best-effort on Windows, where NTFS ACLs govern access).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"anvil/internal/ui"
)

// cmdLoot shows or sets the session loot directory. `loot <dir>` creates
// the directory (0700) and remembers it for the rest of the session; a
// bare `loot` prints the effective setting.
func (s *shell) cmdLoot(args []string) {
	if len(args) == 0 {
		fmt.Printf("  %s\n", s.lootDir())
		return
	}
	dir := strings.Join(args, " ")
	if err := os.MkdirAll(dir, 0700); err != nil {
		ui.PrintErr(fmt.Sprintf("could not create loot directory: %v", err))
		return
	}
	s.lootDirSet = dir
	ui.Faint.Printf("  loot directory: %s\n", dir)
}

// lootDir returns the session's loot directory: the one set via
// `loot <dir>`, else the per-target default ~/.anvil/loot/<host>/. The
// default is resolved lazily from the session host and — like track.Dir —
// is not created until a write needs it.
func (s *shell) lootDir() string {
	if s.lootDirSet != "" {
		return s.lootDirSet
	}
	// Tests construct shells without a session; there is no host then.
	host := ""
	if s.sess != nil {
		host = s.sess.Host()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "" // degenerate: falls back to a relative .anvil/loot
	}
	return defaultLootDir(home, host)
}

// defaultLootDir renders the per-target default, ~/.anvil/loot/<host>/,
// with the host sanitized to a single path element.
func defaultLootDir(home, host string) string {
	return filepath.Join(home, ".anvil", "loot", lootHost(host))
}

// lootHost maps a target host (IP or FQDN) to one safe path element:
// IPv6 colons and any path separator become '_'.
func lootHost(host string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '\\':
			return '_'
		}
		return r
	}, host)
}

// lootPath resolves an output filename against the session loot dir: a
// bare name lands inside it; anything carrying a path separator is used
// verbatim. Creating parents is the writer's job (WriteLootLines).
func (s *shell) lootPath(name string) string {
	if strings.ContainsAny(name, `/\`) {
		return name
	}
	return filepath.Join(s.lootDir(), name)
}

// WriteLootLines writes lines to path — a "# <header>" comment first, then
// one line per entry — creating parent directories (0700) as needed. Loot
// files hold engagement data (hashes, tickets), so the file is 0600.
func WriteLootLines(path, header string, lines []string) error {
	if path == "" {
		return errors.New("loot: empty output path")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create loot directory: %w", err)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", header)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write loot file: %w", err)
	}
	return nil
}
