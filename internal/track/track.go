// Package track implements anvil's change tracker: the in-memory audit
// trail of write operations a session performs against a target.
//
// The package is pure in the repo's usual sense: entries live in memory,
// rendering is a plain string, and the only I/O is SaveJSON persisting a
// local log under ~/.anvil/logs/changes/. It never touches the network,
// the target, or the screen.
//
// Call contract (the wiring lives centrally in internal/shell):
//
//   - Exactly one Record per attempted remote mutation, made after the
//     attempt completes: StatusSuccess when the remote change was applied,
//     StatusFailed when the server refused it or the operation errored.
//     Read-only commands (ls, get, enum, dump-parse) never record; a
//     command that creates a remote artifact while reading (reg save,
//     hive dumps) records under its feature category with the artifact
//     path as target.
//   - Category matches the command's feature area: FILE (put/rm/mkdir/
//     rmdir/rename), SERVICE (service create/start/stop/delete), TASK
//     (exec via TSCH — a scheduled task is created and deleted), REGISTRY
//     (reg add/delete), EXEC (non-TSCH remote execution), AD
//     (addcomputer/delcomputer/changepasswd/rbcd/dmsa).
//   - target names the remote object mutated (UNC path, service name,
//     registry key, DN); detail is short free-form context ("" when none).
//   - The exit banner prints Summary(); the `changes` command lists
//     Entries(), `--save` persists via SaveJSON(DefaultPath()), `--clear`
//     calls Clear().
package track

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Category identifies the feature area a recorded mutation belongs to.
// The values are the stable wire strings written to JSON logs; extend the
// set only alongside a schema-version bump consideration, since consumers
// of the log may switch on them.
type Category string

const (
	CategoryFile     Category = "FILE"
	CategoryService  Category = "SERVICE"
	CategoryTask     Category = "TASK"
	CategoryRegistry Category = "REGISTRY"
	CategoryExec     Category = "EXEC"
	CategoryAD       Category = "AD"
)

// categoryOrder is the canonical display order for Summary. Categories a
// caller invents outside this list still count toward the total and are
// rendered after the known ones, sorted by name.
var categoryOrder = []Category{
	CategoryFile,
	CategoryService,
	CategoryTask,
	CategoryRegistry,
	CategoryExec,
	CategoryAD,
}

// Status is the outcome of one recorded mutation attempt.
type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

// Entry is one recorded write operation. Field order here fixes the JSON
// key order of saved logs (encoding/json emits fields in declaration
// order), which TestSchemaStability pins.
type Entry struct {
	Time     time.Time `json:"time"` // UTC, when the attempt completed
	Category Category  `json:"category"`
	Action   string    `json:"action"` // verb, e.g. "put", "mkdir", "create-service"
	Target   string    `json:"target"` // remote object acted on
	Detail   string    `json:"detail"` // optional context, "" when none
	Status   Status    `json:"status"`
}

// schemaVersion is the JSON log format version. Bump it on any
// incompatible change to fileEnvelope or Entry's wire form.
const schemaVersion = 1

// fileEnvelope is the on-disk JSON document produced by SaveJSON.
type fileEnvelope struct {
	Tool    string    `json:"tool"` // always "anvil"
	Version int       `json:"version"`
	Started time.Time `json:"started"` // tracker creation time (session start)
	Saved   time.Time `json:"saved"`
	Count   int       `json:"count"`
	Entries []Entry   `json:"entries"` // always an array, never null
}

// Tracker records change entries in memory. The zero value is not ready
// for use; build one with New. Safe for concurrent use, though the shell
// drives it from a single goroutine — the mutex only guards against
// background helpers (e.g. a future async exec) recording out of band.
type Tracker struct {
	mu      sync.Mutex
	started time.Time
	entries []Entry
	now     func() time.Time // time source; tests pin it for golden output
}

// New returns an empty Tracker whose start time is now (UTC).
func New() *Tracker {
	return &Tracker{
		started: time.Now().UTC(),
		entries: make([]Entry, 0),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Record appends one mutation attempt. See the package doc for the call
// contract: exactly one call per attempted remote mutation, StatusSuccess
// only when the change was actually applied. Empty action/target are
// accepted (the shell is trusted to fill them); nothing here panics.
func (t *Tracker) Record(cat Category, action, target, detail string, status Status) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append(t.entries, Entry{
		Time:     t.now(),
		Category: cat,
		Action:   action,
		Target:   target,
		Detail:   detail,
		Status:   status,
	})
}

// Entries returns a copy of the recorded entries, oldest first. Mutating
// the returned slice does not affect the tracker.
func (t *Tracker) Entries() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Entry, len(t.entries))
	copy(out, t.entries)
	return out
}

// Count returns how many entries are currently recorded.
func (t *Tracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Clear drops all recorded entries. The start time is kept: a cleared
// tracker still belongs to the same session.
func (t *Tracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = make([]Entry, 0)
}

// Summary renders the exit-banner text: total and outcome counts, then a
// per-category breakdown in canonical order (unknown categories last,
// sorted). Plain text, no color — theming is the shell's job.
func (t *Tracker) Summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.entries) == 0 {
		return "no changes recorded"
	}

	per := make(map[Category]int)
	failed := 0
	for _, e := range t.entries {
		per[e.Category]++
		if e.Status == StatusFailed {
			failed++
		}
	}

	var b strings.Builder
	n := len(t.entries)
	word := "changes"
	if n == 1 {
		word = "change"
	}
	fmt.Fprintf(&b, "%d %s recorded (%d succeeded, %d failed)", n, word, n-failed, failed)

	printed := make(map[Category]bool)
	for _, c := range categoryOrder {
		if per[c] > 0 {
			fmt.Fprintf(&b, "\n  %-8s %d", c, per[c])
			printed[c] = true
		}
	}
	// Caller-invented categories still surface, deterministically.
	var extra []string
	for c := range per {
		if !printed[c] {
			extra = append(extra, string(c))
		}
	}
	sort.Strings(extra)
	for _, c := range extra {
		fmt.Fprintf(&b, "\n  %-8s %d", c, per[Category(c)])
	}
	return b.String()
}

// Dir returns the directory anvil's change logs live in:
// ~/.anvil/logs/changes. It is not created until a save needs it.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".anvil", "logs", "changes"), nil
}

// DefaultPath returns a timestamped log path under Dir, e.g.
// ~/.anvil/logs/changes/changes-20260720-184038.json. Saves within the
// same second share a filename; SaveJSON overwrites cleanly in that case.
func DefaultPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	name := "changes-" + time.Now().UTC().Format("20060102-150405") + ".json"
	return filepath.Join(dir, name), nil
}

// SaveJSON persists the recorded entries as a versioned JSON document.
// The write is atomic: the document goes to a temp file in the same
// directory (0600 — these logs can contain paths and account names from a
// sensitive engagement), is synced, then renamed over path. Parent
// directories are created 0700. On Windows the 0600 mode is best-effort
// (only the read-only bit maps), and rename-over-existing needs the
// fallback below since os.Rename refuses to clobber there.
func (t *Tracker) SaveJSON(path string) error {
	if path == "" {
		return errors.New("track: SaveJSON: empty path")
	}

	// Snapshot under the lock, marshal outside it.
	t.mu.Lock()
	env := fileEnvelope{
		Tool:    "anvil",
		Version: schemaVersion,
		Started: t.started,
		Saved:   t.now(),
		Count:   len(t.entries),
		Entries: make([]Entry, len(t.entries)),
	}
	copy(env.Entries, t.entries)
	t.mu.Unlock()

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("track: marshal change log: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("track: create log dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".anv-changes-*.tmp")
	if err != nil {
		return fmt.Errorf("track: create temp log: %w", err)
	}
	tmpName := tmp.Name()
	// Any exit past this point must not leave the temp file behind.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("track: write temp log: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("track: chmod temp log: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("track: sync temp log: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("track: close temp log: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		// Windows refuses to rename over an existing file; remove the
		// stale log and retry once. The window between remove and rename
		// is the same trade-off every portable tool makes here.
		if rmErr := os.Remove(path); rmErr != nil {
			return fmt.Errorf("track: replace existing log: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("track: rename log into place: %w", err)
		}
	}
	return nil
}
