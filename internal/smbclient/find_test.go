package smbclient

import (
	"strings"
	"testing"
	"time"
)

// TestParseSizeSpec drives the size grammar: [+|-|=]<int><B|KB|MB|GB>,
// binary multipliers, case-insensitive units, operator defaulting to =.
func TestParseSizeSpec(t *testing.T) {
	tests := []struct {
		spec    string
		wantOp  sizeOp
		wantN   int64
		wantErr string // substring; empty = success expected
	}{
		{spec: "0B", wantOp: sizeEq, wantN: 0},
		{spec: "=0B", wantOp: sizeEq, wantN: 0},
		{spec: "512B", wantOp: sizeEq, wantN: 512},
		{spec: "+1KB", wantOp: sizeGT, wantN: 1024},
		{spec: "-500KB", wantOp: sizeLT, wantN: 500 * 1024},
		{spec: "+1MB", wantOp: sizeGT, wantN: 1 << 20},
		{spec: "10GB", wantOp: sizeEq, wantN: 10 << 30},
		{spec: "2mb", wantOp: sizeEq, wantN: 2 << 20},   // case-insensitive unit
		{spec: "  +3KB  ", wantOp: sizeGT, wantN: 3072}, // surrounding space tolerated
		{spec: "", wantErr: "empty size spec"},
		{spec: "10", wantErr: "invalid size unit"},    // unit is mandatory
		{spec: "1XB", wantErr: "invalid size unit"},   // unknown unit
		{spec: "1.5MB", wantErr: "invalid size unit"}, // no decimals
		{spec: "+KB", wantErr: "invalid size"},        // missing number
		{spec: "KB", wantErr: "invalid size"},         // missing number
		{spec: "+-1KB", wantErr: "invalid size"},      // double operator
		{spec: "99999999999999999999GB", wantErr: ""}, // Sscanf fails or overflow; checked below
		{spec: "8589934592GB", wantErr: "overflows"},  // 2^63 bytes: must overflow
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			op, n, err := parseSizeSpec(tt.spec)
			if tt.spec == "99999999999999999999GB" {
				// Over int64 range: any error is correct, success is not.
				if err == nil {
					t.Fatalf("parseSizeSpec(%q) = (%v, %d), want error", tt.spec, op, n)
				}
				return
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseSizeSpec(%q) err = %v, want substring %q", tt.spec, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSizeSpec(%q) unexpected error: %v", tt.spec, err)
			}
			if op != tt.wantOp || n != tt.wantN {
				t.Fatalf("parseSizeSpec(%q) = (%v, %d), want (%v, %d)", tt.spec, op, n, tt.wantOp, tt.wantN)
			}
		})
	}
}

// TestCompileFindFilter exercises option validation: every user-facing error
// must surface at compile time, before any SMB traffic.
func TestCompileFindFilter(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		opts    FindOptions
		wantErr string // substring; empty = success expected
	}{
		{name: "zero options", opts: FindOptions{}},
		{name: "glob", opts: FindOptions{Name: "*.log"}},
		{name: "regex", opts: FindOptions{Regex: `(?i)^pass(wd|word)`}},
		{name: "name and regex conflict", opts: FindOptions{Name: "*.log", Regex: "x"}, wantErr: "mutually exclusive"},
		{name: "bad regex", opts: FindOptions{Regex: "(unclosed"}, wantErr: "invalid regex"},
		{name: "bad glob", opts: FindOptions{Name: "[unclosed"}, wantErr: "invalid name pattern"},
		{name: "bad size", opts: FindOptions{Size: "12 parsecs"}, wantErr: "invalid size"},
		{name: "negative newer", opts: FindOptions{NewerDays: -1}, wantErr: ">= 0"},
		{name: "negative older", opts: FindOptions{OlderDays: -3}, wantErr: ">= 0"},
		{name: "bad type", opts: FindOptions{Type: "symlink"}, wantErr: "invalid type"},
		{name: "type file", opts: FindOptions{Type: "file"}},
		{name: "type dir upper", opts: FindOptions{Type: "DIR"}},
		{name: "negative maxdepth", opts: FindOptions{MaxDepth: -1}, wantErr: "maxdepth"},
		{name: "negative limit", opts: FindOptions{Limit: -1}, wantErr: "limit"},
		{name: "negative timeout", opts: FindOptions{Timeout: -time.Second}, wantErr: "timeout"},
		{name: "kitchen sink", opts: FindOptions{
			Name: "*.txt", Size: "+1KB", NewerDays: 7, OlderDays: 1,
			Type: "file", MaxDepth: 3, Limit: 50, Timeout: time.Minute,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := compileFindFilter(tt.opts, now)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("compileFindFilter(%+v) err = %v, want substring %q", tt.opts, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("compileFindFilter(%+v) unexpected error: %v", tt.opts, err)
			}
			if f == nil {
				t.Fatal("compileFindFilter returned nil filter without error")
			}
		})
	}
}

// TestFindFilterMatch is the engine's truth table: wildcard vs regex,
// case folding, size operators, mtime windows (against an injected fixed
// clock), and type filters — singly and combined.
func TestFindFilterMatch(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	file := func(name string, size int64, age time.Duration) findEntry {
		return findEntry{Name: name, Size: size, ModTime: now.Add(-age)}
	}
	dir := func(name string, age time.Duration) findEntry {
		return findEntry{Name: name, ModTime: now.Add(-age), IsDir: true}
	}

	tests := []struct {
		name string
		opts FindOptions
		ent  findEntry
		want bool
	}{
		// Name: wildcard, whole-base-name path.Match semantics.
		{name: "glob match", opts: FindOptions{Name: "*.log"}, ent: file("setup.log", 1, 0), want: true},
		{name: "glob no match", opts: FindOptions{Name: "*.log"}, ent: file("setup.txt", 1, 0), want: false},
		{name: "glob whole name", opts: FindOptions{Name: "pass"}, ent: file("passwords.txt", 1, 0), want: false},
		{name: "glob question mark", opts: FindOptions{Name: "file?.txt"}, ent: file("file1.txt", 1, 0), want: true},
		{name: "glob star middle", opts: FindOptions{Name: "unattend*.*"}, ent: file("unattend.xml.bak", 1, 0), want: true},
		{name: "glob case sensitive default", opts: FindOptions{Name: "*.LOG"}, ent: file("setup.log", 1, 0), want: false},
		{name: "glob case insensitive", opts: FindOptions{Name: "*.LOG", CaseInsensitive: true}, ent: file("Setup.Log", 1, 0), want: true},

		// Name: regex, substring semantics (user anchors explicitly).
		{name: "regex substring", opts: FindOptions{Regex: "pass"}, ent: file("passwords.txt", 1, 0), want: true},
		{name: "regex anchored", opts: FindOptions{Regex: `^ntds\.dit$`}, ent: file("ntds.dit", 1, 0), want: true},
		{name: "regex anchored miss", opts: FindOptions{Regex: `^ntds\.dit$`}, ent: file("ntds.dit.bak", 1, 0), want: false},
		{name: "regex case sensitive default", opts: FindOptions{Regex: "^SAM$"}, ent: file("sam", 1, 0), want: false},
		{name: "regex case insensitive", opts: FindOptions{Regex: "^sam$", CaseInsensitive: true}, ent: file("SAM", 1, 0), want: true},

		// Size: operators, boundaries, and the files-only rule.
		{name: "size gt inside", opts: FindOptions{Size: "+1KB"}, ent: file("a", 1025, 0), want: true},
		{name: "size gt boundary", opts: FindOptions{Size: "+1KB"}, ent: file("a", 1024, 0), want: false},
		{name: "size lt inside", opts: FindOptions{Size: "-1KB"}, ent: file("a", 1023, 0), want: true},
		{name: "size lt boundary", opts: FindOptions{Size: "-1KB"}, ent: file("a", 1024, 0), want: false},
		{name: "size eq", opts: FindOptions{Size: "=0B"}, ent: file("empty", 0, 0), want: true},
		{name: "size eq miss", opts: FindOptions{Size: "=1B"}, ent: file("a", 2, 0), want: false},
		{name: "size excludes dirs", opts: FindOptions{Size: "-1KB"}, ent: dir("tiny", 0), want: false},

		// Mtime windows: strictly newer/older than N days from now.
		{name: "newer inside", opts: FindOptions{NewerDays: 7}, ent: file("a", 1, 3*day), want: true},
		{name: "newer outside", opts: FindOptions{NewerDays: 7}, ent: file("a", 1, 30*day), want: false},
		{name: "newer boundary", opts: FindOptions{NewerDays: 7}, ent: file("a", 1, 7*day), want: false},
		{name: "older inside", opts: FindOptions{OlderDays: 30}, ent: file("a", 1, 90*day), want: true},
		{name: "older outside", opts: FindOptions{OlderDays: 30}, ent: file("a", 1, 3*day), want: false},
		{name: "window inside", opts: FindOptions{NewerDays: 90, OlderDays: 7}, ent: file("a", 1, 30*day), want: true},
		{name: "window below", opts: FindOptions{NewerDays: 90, OlderDays: 7}, ent: file("a", 1, 2*day), want: false},
		{name: "window above", opts: FindOptions{NewerDays: 90, OlderDays: 7}, ent: file("a", 1, 365*day), want: false},

		// Type.
		{name: "type file accepts file", opts: FindOptions{Type: "file"}, ent: file("a", 1, 0), want: true},
		{name: "type file rejects dir", opts: FindOptions{Type: "file"}, ent: dir("d", 0), want: false},
		{name: "type dir accepts dir", opts: FindOptions{Type: "dir"}, ent: dir("d", 0), want: true},
		{name: "type dir rejects file", opts: FindOptions{Type: "dir"}, ent: file("a", 1, 0), want: false},
		{name: "type any accepts both", opts: FindOptions{Type: "any"}, ent: dir("d", 0), want: true},
		{name: "empty matches everything", opts: FindOptions{}, ent: file("anything", 99, 500*day), want: true},

		// Combinations.
		{name: "glob+size both pass", opts: FindOptions{Name: "*.vmdk", Size: "+1GB"}, ent: file("disk.vmdk", 2<<30, 0), want: true},
		{name: "glob+size size fails", opts: FindOptions{Name: "*.vmdk", Size: "+1GB"}, ent: file("disk.vmdk", 1, 0), want: false},
		{name: "regex+type+older", opts: FindOptions{Regex: `\.(log|txt)$`, Type: "file", OlderDays: 10}, ent: file("old.log", 1, 20*day), want: true},
		{name: "regex+type+older type fails", opts: FindOptions{Regex: `\.(log|txt)$`, Type: "file", OlderDays: 10}, ent: dir("old.log", 20*day), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := compileFindFilter(tt.opts, now)
			if err != nil {
				t.Fatalf("compileFindFilter(%+v): %v", tt.opts, err)
			}
			if got := f.match(tt.ent); got != tt.want {
				t.Errorf("match(%+v) = %v, want %v (opts %+v)", tt.ent, got, tt.want, tt.opts)
			}
		})
	}
}
