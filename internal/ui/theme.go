// Package ui renders scan results in the Terminal Workbench design system:
// quiet chrome, color only on signal. Both spec modes are supported
// (THEME-SPEC §6): the dark ramp is the default, the light ramp is selected
// by ANVIL_THEME=light, by a COLORFGBG light background (7/15), or forced
// off with ANVIL_THEME=dark. fatih/color auto-disables color when NO_COLOR
// is set or output is not a TTY.
package ui

import (
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// Terminal Workbench palette, assigned by init from resolve(); see the
// package doc for the dark/light selection rules.
var (
	Accent    *color.Color // open ports, positive signal
	AccentAlt *color.Color // secondary values (hosts, domains)
	Warm      *color.Color // warnings
	Red       *color.Color // errors
	Muted     *color.Color // labels
	Faint     *color.Color // separators, closed/skip notes
)

// palette is one mode's worth of Terminal Workbench colors.
type palette struct {
	accent, accentAlt, warm, red, muted, faint *color.Color
}

// dark is the Terminal Workbench dark ramp (THEME-SPEC §2.1/§2.3).
var dark = palette{
	accent:    color.RGB(0x63, 0xf2, 0xab), // #63f2ab
	accentAlt: color.RGB(0x6b, 0xdc, 0xff), // #6bdcff
	warm:      color.RGB(0xf0, 0xc6, 0x74), // #f0c674
	red:       color.RGB(0xff, 0x6e, 0x7a), // #ff6e7a
	muted:     color.RGB(0x87, 0x99, 0x94), // #879994
	faint:     color.RGB(0x63, 0x73, 0x6f), // #63736f
}

// light is the Terminal Workbench light ramp. The accents darken (not
// lighten) so colored text keeps WCAG AA contrast on light surfaces.
var light = palette{
	accent:    color.RGB(0x00, 0x7a, 0x4d), // #007a4d
	accentAlt: color.RGB(0x00, 0x6f, 0x9e), // #006f9e
	warm:      color.RGB(0xa4, 0x66, 0x00), // #a46600
	red:       color.RGB(0xc8, 0x32, 0x4c), // #c8324c
	muted:     color.RGB(0x60, 0x70, 0x6a), // #60706a
	faint:     color.RGB(0x81, 0x91, 0x8a), // #81918a
}

func init() {
	p := resolve(os.Getenv("ANVIL_THEME"), os.Getenv("COLORFGBG"))
	Accent, AccentAlt, Warm, Red, Muted, Faint =
		p.accent, p.accentAlt, p.warm, p.red, p.muted, p.faint
}

// resolve picks the dark or light ramp. themeEnv is ANVIL_THEME's value
// ("light"|"dark"|"auto", case-insensitive; empty or unrecognized falls
// through to auto). colorfgbg is COLORFGBG's value ("fg;bg", sometimes
// "default;fg;bg"); auto treats its last field as the background color and
// picks light only when it is 7 (white) or 15 (bright white).
func resolve(themeEnv, colorfgbg string) palette {
	switch strings.ToLower(strings.TrimSpace(themeEnv)) {
	case "light":
		return light
	case "dark":
		return dark
	}
	fields := strings.Split(colorfgbg, ";")
	bg, err := strconv.Atoi(strings.TrimSpace(fields[len(fields)-1]))
	if err == nil && (bg == 7 || bg == 15) {
		return light
	}
	return dark
}
