package ui

import (
	"fmt"
	"os"
)

// debugEnabled gates Debugf output. Set by the persistent --debug flag.
var debugEnabled bool

// SetDebug enables verbose debug logging to stderr (faint, theme-consistent).
func SetDebug(on bool) { debugEnabled = on }

// Debugf writes one faint debug line to stderr when --debug is active.
// Output stays off stdout so themed/JSON output is never polluted.
func Debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "%s\n", Faint.Sprintf("debug: "+format, args...))
}
