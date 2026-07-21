package smbclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"anvil/internal/ui"
)

// ErrFindTimeout marks a Find walk cut short by FindOptions.Timeout. Find
// returns the partial results gathered so far alongside an error wrapping
// this sentinel, so callers can errors.Is it and still print what was found.
var ErrFindTimeout = errors.New("walk timeout exceeded")

// FindOptions is the filter set for one Find walk. The zero value matches
// every file and directory below the start path with no depth cap, no result
// cap, and no deadline.
//
//	Name  — wildcard matched against the base name ("*.log", "pass?rd.*");
//	        the whole base name must match (path.Match semantics).
//	Regex — RE2 matched against the base name; mutually exclusive with Name.
//	CaseInsensitive folds case for Name/Regex matching (Windows volumes are
//	        case-preserving but case-insensitive, so this is usually wanted).
//	Size  — [+|-|=]<int><B|KB|MB|GB> ("+1MB" larger than, "-500KB" smaller
//	        than, "=0B" exactly; units are binary, case-insensitive; the
//	        operator defaults to =). Applies to files only: when set,
//	        directories never match (their reported size is meaningless).
//	NewerDays — mtime strictly within the last N days (0 = unset).
//	OlderDays — mtime strictly more than N days ago (0 = unset). Both may
//	        combine into a window.
//	Type  — "file", "dir", or "any" ("" behaves as "any").
//	MaxDepth — 1 lists only the start directory's immediate children, 2
//	        their children too, ...; 0 = unlimited. The start directory
//	        itself is depth 0 and never appears in the results.
//	Limit — stop cleanly once this many results are collected (0 =
//	        unlimited). Not an error — the walk just ends early.
//	Timeout — deadline for the whole walk; on expiry Find returns the
//	        partial results plus an error wrapping ErrFindTimeout (0 = no
//	        deadline).
type FindOptions struct {
	Name            string
	Regex           string
	CaseInsensitive bool
	Size            string
	NewerDays       int
	OlderDays       int
	Type            string
	MaxDepth        int
	Limit           int
	Timeout         time.Duration
}

// FindResult is one matched entry. Path is relative to the share root and
// backslash-separated ("Windows\\Temp\\x.log") — display-ready and usable
// with get/cat after `cd \`.
type FindResult struct {
	Path    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

// Find walks the selected share below startPath (resolved against the
// session's current remote directory, exactly like ls) and returns every
// entry matching opts.
//
// It rides the existing SMB session: one extra TREE_CONNECT to the current
// share on the same connection (the Stat pattern), no new channels. The walk
// is one QUERY_DIRECTORY round trip per directory (smb2 pages large
// directories internally), so throughput is RTT-bound — keep Timeout and
// Limit set on big trees like C:\Windows.
//
// Timeout safety: the deadline rides the tree's context (smb2
// Share.WithContext). A cancelled QUERY_DIRECTORY pops its message ID from
// the connection's outstanding-request table and the late response is
// discarded by the receiver loop, so the persistent session stays aligned
// and usable after a timed-out walk.
//
// Subdirectories that cannot be listed (access denied is routine on C$ —
// "System Volume Information", junctions) are skipped, not fatal. Only the
// start path itself failing (missing, not a directory, unreadable) is a hard
// error. If startPath names a file, no walk happens: the file alone is
// tested against the filters.
func (s *Session) Find(startPath string, opts FindOptions) ([]FindResult, error) {
	if s.share == "" {
		return nil, fmt.Errorf("no share selected — use <share> first")
	}
	filter, err := compileFindFilter(opts, time.Now())
	if err != nil {
		return nil, err
	}

	// pkg/smb resolves ls/cd arguments with path.Join against its internal
	// currentPath ('/'-separated, "" at the share root); the smb2 layer then
	// normalizes '/' to '\'. Mirror that so find's start behaves like ls.
	startRel := path.Join(s.client.GetCurrentPath(), smbPath(startPath))

	sh, err := s.client.Session.Mount(s.share)
	if err != nil {
		return nil, mapFindError(err)
	}
	defer sh.Umount()

	// The deadline context rides the walk tree only; the mount itself (and
	// its deferred umount) stays on the background context so teardown isn't
	// cancelled along with the walk.
	ctx := context.Background()
	cancel := func() {}
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), opts.Timeout)
	}
	defer cancel()
	walk := sh.WithContext(ctx)

	var results []FindResult
	skipped := 0
	timeoutErr := func() error {
		return fmt.Errorf("%w after %s — %d partial matches, %d unreadable dirs skipped",
			ErrFindTimeout, opts.Timeout, len(results), skipped)
	}

	// Stat the start first: it distinguishes "walk this directory" from
	// "test this single file", and surfaces a bad start path immediately
	// instead of as a silent skip inside the loop.
	fi, err := walk.Stat(startRel)
	if err != nil {
		if ctx.Err() != nil {
			return results, timeoutErr()
		}
		return nil, mapFindError(err)
	}
	if !fi.IsDir() {
		e := findEntry{Name: path.Base(startRel), Size: fi.Size(), ModTime: fi.ModTime(), IsDir: false}
		if !filter.match(e) {
			return nil, nil
		}
		return []FindResult{{Path: displayFindPath(startRel), Size: fi.Size(), ModTime: fi.ModTime()}}, nil
	}

	// Iterative DFS with an explicit stack: smb2 directory handles are
	// request/response, so recursion depth costs nothing here, but a stack
	// keeps the timeout/limit exits single-pointed and avoids unbounded Go
	// recursion on pathological trees.
	type frame struct {
		dir   string // share-relative, '/'-separated ("" = share root)
		depth int    // depth of dir itself; its children are depth+1
	}
	stack := []frame{{dir: startRel}}

	for len(stack) > 0 {
		if ctx.Err() != nil {
			return results, timeoutErr()
		}
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := walk.ReadDir(fr.dir)
		if err != nil {
			if ctx.Err() != nil {
				return results, timeoutErr()
			}
			if fr.depth == 0 {
				// The start directory listed fine at Stat but won't list
				// (e.g. attribute-readable but not listable) — that's a hard
				// error, not a skippable subdir.
				return nil, mapFindError(err)
			}
			skipped++
			ui.Debugf("find: skipping %s: %v", displayFindPath(fr.dir), err)
			continue
		}

		// ReadDir sorts by name; pushing subdirs in reverse keeps the
		// overall traversal alphabetical depth-first.
		var subdirs []frame
		for _, e := range entries {
			childDepth := fr.depth + 1
			if filter.match(findEntry{
				Name:    e.Name(),
				Size:    e.Size(),
				ModTime: e.ModTime(),
				IsDir:   e.IsDir(),
			}) {
				results = append(results, FindResult{
					Path:    displayFindPath(joinFindPath(fr.dir, e.Name())),
					Size:    e.Size(),
					ModTime: e.ModTime(),
					IsDir:   e.IsDir(),
				})
				if opts.Limit > 0 && len(results) >= opts.Limit {
					return results, nil
				}
			}
			// Descend only while children would still be within MaxDepth.
			if e.IsDir() && (opts.MaxDepth == 0 || childDepth < opts.MaxDepth) {
				subdirs = append(subdirs, frame{dir: joinFindPath(fr.dir, e.Name()), depth: childDepth})
			}
		}
		for i := len(subdirs) - 1; i >= 0; i-- {
			stack = append(stack, subdirs[i])
		}
	}
	return results, nil
}

// joinFindPath joins a walk dir ('/'-separated, "" = share root) and a base
// name for the next ReadDir call.
func joinFindPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// displayFindPath renders a '/'-separated walk path as the backslash form
// shown to the user.
func displayFindPath(p string) string { return strings.ReplaceAll(p, "/", `\`) }

// ---------------------------------------------------------------------------
// Pure filter engine — no I/O, no SMB. Everything below operates on
// caller-supplied values and is unit-tested hermetically; now is injected so
// mtime windows are deterministic in tests.
// ---------------------------------------------------------------------------

// findEntry is the engine's view of one directory entry (decoupled from
// os.FileInfo so tests construct it directly).
type findEntry struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

// sizeOp is the comparison a Size spec applies.
type sizeOp int

const (
	sizeEq sizeOp = iota // = (also the default when no operator is given)
	sizeGT               // +
	sizeLT               // -
)

// findType narrows matches by entry kind.
type findType int

const (
	typeAny findType = iota
	typeFile
	typeDir
)

// findFilter is FindOptions compiled into an executable matcher.
type findFilter struct {
	glob    string         // wildcard pattern (empty = no name filter), from Name
	nameRe  *regexp.Regexp // regex name filter (nil unless Regex was set)
	ci      bool           // fold case for glob matching (regex gets (?i) instead)
	hasSize bool
	sop     sizeOp
	sbytes  int64
	newer   time.Duration // >0: mtime must be after now-newer
	older   time.Duration // >0: mtime must be before now-older
	typ     findType
	now     time.Time
}

// compileFindFilter validates opts and compiles it into a findFilter. Pure:
// every user-facing error (bad glob, bad regex, bad size grammar, negative
// numbers, conflicting name filters) is produced here, before any SMB
// traffic.
func compileFindFilter(opts FindOptions, now time.Time) (*findFilter, error) {
	f := &findFilter{ci: opts.CaseInsensitive, typ: typeAny, now: now}

	if opts.Name != "" && opts.Regex != "" {
		return nil, fmt.Errorf("name pattern and regex are mutually exclusive — pick one")
	}
	if opts.Regex != "" {
		pat := opts.Regex
		if opts.CaseInsensitive {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %v", opts.Regex, err)
		}
		f.nameRe = re
	} else if opts.Name != "" {
		// Probe-compile the glob so a bad pattern fails here, not mid-walk.
		// path.Match treats '\' as an escape, which base names never
		// contain, so only genuinely malformed patterns error.
		if _, err := path.Match(opts.Name, ""); err != nil {
			return nil, fmt.Errorf("invalid name pattern %q: %v", opts.Name, err)
		}
		f.glob = opts.Name
	}

	if opts.Size != "" {
		op, n, err := parseSizeSpec(opts.Size)
		if err != nil {
			return nil, err
		}
		f.hasSize, f.sop, f.sbytes = true, op, n
	}

	if opts.NewerDays < 0 || opts.OlderDays < 0 {
		return nil, fmt.Errorf("newer/older days must be >= 0")
	}
	if opts.NewerDays > 0 {
		f.newer = time.Duration(opts.NewerDays) * 24 * time.Hour
	}
	if opts.OlderDays > 0 {
		f.older = time.Duration(opts.OlderDays) * 24 * time.Hour
	}

	switch strings.ToLower(opts.Type) {
	case "", "any":
	case "file":
		f.typ = typeFile
	case "dir":
		f.typ = typeDir
	default:
		return nil, fmt.Errorf("invalid type %q — want file, dir, or any", opts.Type)
	}

	if opts.MaxDepth < 0 {
		return nil, fmt.Errorf("maxdepth must be >= 0")
	}
	if opts.Limit < 0 {
		return nil, fmt.Errorf("limit must be >= 0")
	}
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("timeout must be >= 0")
	}
	return f, nil
}

// match reports whether one entry passes every active filter.
func (f *findFilter) match(e findEntry) bool {
	switch f.typ {
	case typeFile:
		if e.IsDir {
			return false
		}
	case typeDir:
		if !e.IsDir {
			return false
		}
	}

	// Size is a file property; with a size filter active, directories are
	// excluded rather than matched on their (meaningless) reported size.
	if f.hasSize {
		if e.IsDir {
			return false
		}
		switch f.sop {
		case sizeGT:
			if e.Size <= f.sbytes {
				return false
			}
		case sizeLT:
			if e.Size >= f.sbytes {
				return false
			}
		default: // sizeEq
			if e.Size != f.sbytes {
				return false
			}
		}
	}

	if f.newer > 0 && !e.ModTime.After(f.now.Add(-f.newer)) {
		return false
	}
	if f.older > 0 && !e.ModTime.Before(f.now.Add(-f.older)) {
		return false
	}

	if f.nameRe != nil {
		return f.nameRe.MatchString(e.Name)
	}
	if f.glob != "" {
		pat, name := f.glob, e.Name
		if f.ci {
			pat, name = strings.ToLower(pat), strings.ToLower(name)
		}
		ok, _ := path.Match(pat, name) // pattern pre-validated at compile
		return ok
	}
	return true
}

// sizeUnits maps the uppercase unit suffix to its binary multiplier.
var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	{"KB", 1 << 10},
	{"MB", 1 << 20},
	{"GB", 1 << 30},
	{"B", 1},
}

// parseSizeSpec parses the size grammar: optional operator (+ larger than,
// - smaller than, = exactly; default =), integer, unit (B|KB|MB|GB,
// case-insensitive, binary multiples). e.g. "+1MB", "-500KB", "=0B".
func parseSizeSpec(spec string) (sizeOp, int64, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return sizeEq, 0, fmt.Errorf("empty size spec — want [+|-|=]<int><B|KB|MB|GB>")
	}

	op := sizeEq
	switch s[0] {
	case '+':
		op = sizeGT
		s = s[1:]
	case '-':
		op = sizeLT
		s = s[1:]
	case '=':
		s = s[1:]
	}

	// Split digits from the unit suffix.
	i := 0
	for i < len(s) && unicode.IsDigit(rune(s[i])) {
		i++
	}
	numPart, unitPart := s[:i], strings.ToUpper(s[i:])
	if numPart == "" {
		return sizeEq, 0, fmt.Errorf("invalid size %q — want [+|-|=]<int><B|KB|MB|GB>", spec)
	}

	var mult int64
	for _, u := range sizeUnits {
		if unitPart == u.suffix {
			mult = u.mult
			break
		}
	}
	if mult == 0 {
		return sizeEq, 0, fmt.Errorf("invalid size unit in %q — want B, KB, MB, or GB", spec)
	}

	var n int64
	if _, err := fmt.Sscanf(numPart, "%d", &n); err != nil {
		return sizeEq, 0, fmt.Errorf("invalid size %q: %v", spec, err)
	}
	if n > math.MaxInt64/mult {
		return sizeEq, 0, fmt.Errorf("invalid size %q — value overflows int64", spec)
	}
	return op, n * mult, nil
}

// mapFindError translates smb2 walk failures into plain-language messages
// (feature-local themed errors). smb2's ResponseError renders the NTSTATUS
// description text from erref's table, which these substrings match.
func mapFindError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "The object name is not found"), // STATUS_OBJECT_NAME_NOT_FOUND
		strings.Contains(msg, "does not exist"): // STATUS_NO_SUCH_FILE / _OBJECT_PATH_NOT_FOUND
		return fmt.Errorf("no such file or directory")
	case strings.Contains(msg, "Access Denied"): // STATUS_ACCESS_DENIED
		return fmt.Errorf("access denied")
	case strings.Contains(msg, "not a directory"): // STATUS_NOT_A_DIRECTORY
		return fmt.Errorf("not a directory")
	case strings.Contains(msg, "Network Name Not Found"): // STATUS_BAD_NETWORK_NAME
		return fmt.Errorf("network name not found on the server")
	}
	return err
}
