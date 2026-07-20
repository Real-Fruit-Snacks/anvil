package smbclient

import (
	"errors"
	"testing"
)

// TestSvcBatchLine verifies the service binary path is built exactly the way
// the SMBExec batch pattern needs it: the command echoed (escaped) into a
// batch in %windir%\Temp, the batch run, then deleted. The redirect inside
// the echoed text must be ^-escaped so the outer cmd writes it into the
// batch instead of honoring it.
func TestSvcBatchLine(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		tmpFile string
		batFile string
		want    string
	}{
		{
			name:    "simple command",
			cmd:     "whoami",
			tmpFile: "anv-1234abcd.tmp",
			batFile: "anv-1234abcd.bat",
			want: `cmd.exe /Q /C echo ( whoami ) ^> %windir%\Temp\anv-1234abcd.tmp 2^>^&1 > %windir%\Temp\anv-1234abcd.bat` +
				` & cmd.exe /Q /C %windir%\Temp\anv-1234abcd.bat & del %windir%\Temp\anv-1234abcd.bat`,
		},
		{
			name:    "chained command is escaped for echo and parens keep the redirect over both segments",
			cmd:     "ipconfig /all & netstat -an",
			tmpFile: "anv-deadbeef.tmp",
			batFile: "anv-deadbeef.bat",
			want: `cmd.exe /Q /C echo ( ipconfig /all ^& netstat -an ) ^> %windir%\Temp\anv-deadbeef.tmp 2^>^&1 > %windir%\Temp\anv-deadbeef.bat` +
				` & cmd.exe /Q /C %windir%\Temp\anv-deadbeef.bat & del %windir%\Temp\anv-deadbeef.bat`,
		},
		{
			name:    "redirect inside the command is escaped",
			cmd:     `echo done > C:\flag.txt`,
			tmpFile: "anv-00000000.tmp",
			batFile: "anv-00000000.bat",
			want: `cmd.exe /Q /C echo ( echo done ^> C:\flag.txt ) ^> %windir%\Temp\anv-00000000.tmp 2^>^&1 > %windir%\Temp\anv-00000000.bat` +
				` & cmd.exe /Q /C %windir%\Temp\anv-00000000.bat & del %windir%\Temp\anv-00000000.bat`,
		},
		{
			name:    "percent signs pass through for service-side expansion",
			cmd:     "echo %USERPROFILE%",
			tmpFile: "anv-ffffffff.tmp",
			batFile: "anv-ffffffff.bat",
			want: `cmd.exe /Q /C echo ( echo %USERPROFILE% ) ^> %windir%\Temp\anv-ffffffff.tmp 2^>^&1 > %windir%\Temp\anv-ffffffff.bat` +
				` & cmd.exe /Q /C %windir%\Temp\anv-ffffffff.bat & del %windir%\Temp\anv-ffffffff.bat`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svcBatchLine(tc.cmd, tc.tmpFile, tc.batFile); got != tc.want {
				t.Errorf("svcBatchLine(%q, %q, %q)\n got: %q\nwant: %q", tc.cmd, tc.tmpFile, tc.batFile, got, tc.want)
			}
		})
	}
}

// TestEscapeForEcho verifies cmd.exe metacharacters are ^-escaped so an echo
// of the result writes the original text literally.
func TestEscapeForEcho(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text unchanged", "whoami /all", "whoami /all"},
		{"ampersand", "a & b", "a ^& b"},
		{"pipe", "a | findstr x", "a ^| findstr x"},
		{"redirects", "a > b < c", "a ^> b ^< c"},
		{"parens", "(a)", "^(a^)"},
		{"caret doubled first", "a^b", "a^^b"},
		{"caret does not re-escape added escapes", "^&", "^^^&"},
		{"percent untouched", "%PATH%", "%PATH%"},
		{"quotes untouched", `dir "C:\Program Files"`, `dir "C:\Program Files"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeForEcho(tc.in); got != tc.want {
				t.Errorf("escapeForEcho(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestScmHint verifies Win32 codes embedded in gopacket svcctl's flattened
// error strings map to the themed hints.
func TestScmHint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "access denied is an admin problem",
			err:  errors.New("OpenSCManager failed: 0x00000005"),
			want: " (admin required)",
		},
		{
			name: "access denied from CreateService is themed the same",
			err:  errors.New("CreateService failed: 0x00000005"),
			want: " (admin required)",
		},
		{
			name: "service exists suggests a retry",
			err:  errors.New("CreateService failed: 0x00000431"),
			want: " (service name already in use — retry)",
		},
		{
			name: "unknown code gets no hint",
			err:  errors.New("CreateService failed: 0x0000041d"),
			want: "",
		},
		{
			name: "non-hex error gets no hint",
			err:  errors.New("bind svcctl: connection reset"),
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scmHint(tc.err); got != tc.want {
				t.Errorf("scmHint(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsServiceGoneErr verifies the two Win32 codes that mean "the service
// is gone" are recognized and everything else is not.
func TestIsServiceGoneErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "does not exist is gone",
			err:  errors.New("OpenService(anv-1234abcd) failed: 0x00000424"),
			want: true,
		},
		{
			name: "marked for delete counts as gone",
			err:  errors.New("OpenService(anv-1234abcd) failed: 0x00000430"),
			want: true,
		},
		{
			name: "access denied means it is still there",
			err:  errors.New("OpenService(anv-1234abcd) failed: 0x00000005"),
			want: false,
		},
		{
			name: "unrelated RPC error means unknown state",
			err:  errors.New("dcerpc: fault 0x1c010002"),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isServiceGoneErr(tc.err); got != tc.want {
				t.Errorf("isServiceGoneErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
