package ui

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

// rgbEscape renders "x" with color forced on so the exact 24-bit escape
// sequence can be asserted. fatih/color v1.19 bakes NO_COLOR into each
// Color at construction time (New → noColorIsSet), so overriding the
// NoColor global is not enough — a per-instance EnableColor is required.
// The instance is disabled again afterwards to leave shared palette state
// as found.
func rgbEscape(c *color.Color) string {
	c.EnableColor()
	defer c.DisableColor()
	return c.Sprint("x")
}

func TestResolveModeSelection(t *testing.T) {
	cases := []struct {
		name      string
		themeEnv  string
		colorfgbg string
		wantLight bool
	}{
		{"default dark when both unset", "", "", false},
		{"explicit light", "light", "", true},
		{"explicit dark", "dark", "", false},
		{"explicit dark beats light COLORFGBG", "dark", "0;15", false},
		{"explicit light beats dark COLORFGBG", "light", "15;0", true},
		{"case-insensitive LIGHT", "LIGHT", "", true},
		{"whitespace-padded value", " light ", "", true},
		{"auto with light bg 15", "auto", "0;15", true},
		{"auto with light bg 7", "auto", "11;7", true},
		{"auto with dark bg 0", "auto", "15;0", false},
		{"auto with dark bg 8", "auto", "7;8", false},
		{"auto with unset COLORFGBG", "auto", "", false},
		{"auto with unparseable COLORFGBG", "auto", "garbage", false},
		{"auto with three-field COLORFGBG light", "auto", "default;0;15", true},
		{"empty theme falls through to auto", "", "0;15", true},
		{"garbage theme falls through to auto", "banana", "0;15", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolve(tc.themeEnv, tc.colorfgbg)
			if isLight := got.accent == light.accent; isLight != tc.wantLight {
				t.Errorf("resolve(%q, %q): got light=%v, want light=%v",
					tc.themeEnv, tc.colorfgbg, isLight, tc.wantLight)
			}
		})
	}
}

func TestPaletteValues(t *testing.T) {
	// Assert the SGR prefix (the actual RGB values) only — fatih/color's
	// reset suffix is the library's business and changes between versions.
	cases := []struct {
		name       string
		c          *color.Color
		wantPrefix string
	}{
		{"dark accent #63f2ab", dark.accent, "\x1b[38;2;99;242;171m"},
		{"dark accentAlt #6bdcff", dark.accentAlt, "\x1b[38;2;107;220;255m"},
		{"dark warm #f0c674", dark.warm, "\x1b[38;2;240;198;116m"},
		{"dark red #ff6e7a", dark.red, "\x1b[38;2;255;110;122m"},
		{"dark muted #879994", dark.muted, "\x1b[38;2;135;153;148m"},
		{"dark faint #63736f", dark.faint, "\x1b[38;2;99;115;111m"},
		{"light accent #007a4d", light.accent, "\x1b[38;2;0;122;77m"},
		{"light accentAlt #006f9e", light.accentAlt, "\x1b[38;2;0;111;158m"},
		{"light warm #a46600", light.warm, "\x1b[38;2;164;102;0m"},
		{"light red #c8324c", light.red, "\x1b[38;2;200;50;76m"},
		{"light muted #60706a", light.muted, "\x1b[38;2;96;112;106m"},
		{"light faint #81918a", light.faint, "\x1b[38;2;129;145;138m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rgbEscape(tc.c); !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("got %q, want prefix %q", got, tc.wantPrefix)
			}
		})
	}
}

// TestExportedVarsAssigned guards against the init() assignment being
// dropped: every exported palette var must be non-nil after package load.
func TestExportedVarsAssigned(t *testing.T) {
	vars := map[string]*color.Color{
		"Accent": Accent, "AccentAlt": AccentAlt, "Warm": Warm,
		"Red": Red, "Muted": Muted, "Faint": Faint,
	}
	for name, c := range vars {
		if c == nil {
			t.Errorf("%s is nil", name)
		}
	}
}
