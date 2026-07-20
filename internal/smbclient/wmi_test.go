package smbclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
)

// TestBuildWMICmdLine verifies the Win32_Process.Create command line: cmd.exe
// wrapper, paren grouping (so & chains redirect as one), and the
// %windir%\Temp output target.
func TestBuildWMICmdLine(t *testing.T) {
	got := buildWMICmdLine("whoami /all", "anv-deadbeef.tmp")
	want := `cmd.exe /C ( whoami /all ) > %windir%\Temp\anv-deadbeef.tmp 2>&1`
	if got != want {
		t.Errorf("buildWMICmdLine = %q, want %q", got, want)
	}

	// The parens must enclose the whole command, or `a & b > file` would
	// redirect only the last &-segment.
	got = buildWMICmdLine("cd C:\\ & dir", "anv-00000000.tmp")
	if !strings.HasPrefix(got, `cmd.exe /C ( cd C:\ & dir ) > `) {
		t.Errorf("command not paren-wrapped: %q", got)
	}
	if !strings.HasSuffix(got, ` 2>&1`) {
		t.Errorf("stderr not merged into output file: %q", got)
	}
}

// TestWin32ProcessCreateError checks the ReturnValue out-parameter mapping:
// 0 is success, the documented codes get plain-language messages, unknown
// codes keep the number for diagnosis.
func TestWin32ProcessCreateError(t *testing.T) {
	tests := []struct {
		code uint32
		want string // substring; "" means nil error expected
	}{
		{0, ""},
		{2, "access denied (admin required)"},
		{3, "insufficient privilege"},
		{8, "unknown failure"},
		{9, "path not found"},
		{21, "invalid parameter"},
		{99, "ReturnValue 99"},
	}
	for _, tt := range tests {
		err := win32ProcessCreateError(tt.code)
		if tt.want == "" {
			if err != nil {
				t.Errorf("code %d: got %v, want nil", tt.code, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("code %d: got %v, want substring %q", tt.code, err, tt.want)
		}
	}
}

// TestWmiUint32 verifies the numeric coercion: wmio decodes CIM numerics to
// varying Go types, and ReturnValue must survive all of them.
func TestWmiUint32(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want uint32
		ok   bool
	}{
		{"uint32", uint32(7), 7, true},
		{"uint64", uint64(9), 9, true},
		{"int", int(3), 3, true},
		{"int32", int32(2), 2, true},
		{"int64", int64(21), 21, true},
		{"float64", float64(8), 8, true},
		{"nil", nil, 0, false},
		{"string", "0", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := wmiUint32(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Errorf("wmiUint32(%v) = %d,%v; want %d,%v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestWMIValueString verifies Impacket-style value rendering: nil as None,
// Python-style booleans, space-joined arrays, collapsed nested objects.
func TestWMIValueString(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "None"},
		{"string", "Running", "Running"},
		{"empty string", "", ""},
		{"true", true, "True"},
		{"false", false, "False"},
		{"uint32", uint32(410), "410"},
		{"int64", int64(-1), "-1"},
		{"float", float64(1.5), "1.5"},
		{"array", []any{"one", "two"}, "one two"},
		{"array with nil", []any{"one", nil}, "one None"},
		{"empty array", []any{}, ""},
		{"nested object", wmio.Values{"a": 1}, "{object}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wmiValueString(tt.in); got != tt.want {
				t.Errorf("wmiValueString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestWMIResultAddRow verifies column ordering follows the server's property
// order (not Go map iteration), rows render through wmiValueString, and a
// later row carrying an unseen property extends the column set.
func TestWMIResultAddRow(t *testing.T) {
	r := &WMIResult{}
	r.addRow([]string{"Name", "State"}, map[string]any{"Name": "Netlogon", "State": "Running"})
	r.addRow([]string{"State", "Name", "Extra"}, map[string]any{
		"Name": "LanmanServer", "State": "Running", "Extra": uint32(1),
	})

	wantCols := []string{"Name", "State", "Extra"}
	if len(r.Columns) != len(wantCols) {
		t.Fatalf("Columns = %v, want %v", r.Columns, wantCols)
	}
	for i, c := range wantCols {
		if r.Columns[i] != c {
			t.Fatalf("Columns = %v, want %v", r.Columns, wantCols)
		}
	}
	if len(r.Rows) != 2 {
		t.Fatalf("Rows = %d, want 2", len(r.Rows))
	}
	if r.Rows[0]["Name"] != "Netlogon" || r.Rows[0]["State"] != "Running" {
		t.Errorf("row 0 wrong: %v", r.Rows[0])
	}
	if r.Rows[1]["Extra"] != "1" {
		t.Errorf("row 1 Extra = %q, want %q", r.Rows[1]["Extra"], "1")
	}
	// Values absent from the vals map (not just nil) are skipped entirely.
	r.addRow([]string{"Name", "Missing"}, map[string]any{"Name": "x"})
	if _, present := r.Rows[2]["Missing"]; present {
		t.Errorf("absent value should not render, got %q", r.Rows[2]["Missing"])
	}
}

// TestMapWMIError verifies HRESULT-text mapping (go-msrpc renders names plus
// codes via the erref tables) and passthrough of unrecognized errors.
func TestMapWMIError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // substring expected in the mapped message
	}{
		{
			name: "E_ACCESS_DENIED by code",
			err:  errors.New("RemoteActivation: E_ACCESS_DENIED(0x80070005)"),
			want: "access denied",
		},
		{
			name: "WBEM access denied by code",
			err:  errors.New("ExecQuery: WBEM_E_ACCESS_DENIED(0x80041003)"),
			want: "access denied",
		},
		{
			name: "invalid class",
			err:  errors.New("ExecQuery: WBEM_E_INVALID_CLASS(0x80041010)"),
			want: "invalid WMI class",
		},
		{
			// Samba has no DCOM OXID resolver — ServerAlive2 fails with a
			// provider rejection before WMI is involved (e2e section 15).
			name: "Samba provider rejection",
			err:  errors.New("ServerAlive2: dcerpc: invoke: /IObjectExporter/v0/ServerAlive2: provider_rejection: abstract syntax not supported"),
			want: "not supported on this server",
		},
		{
			name: "invalid query",
			err:  errors.New("ExecQuery: WBEM_E_INVALID_QUERY(0x80041017)"),
			want: "invalid WQL query",
		},
		{
			name: "RPC server unavailable",
			err:  errors.New("dial :135: RPC_S_SERVER_UNAVAILABLE(0x800706BA)"),
			want: "DCOM unreachable",
		},
		{
			name: "connection refused",
			err:  errors.New("dial: WSAECONNREFUSED(0x8007274D)"),
			want: "DCOM unreachable",
		},
		{
			name: "class not registered",
			err:  errors.New("RemoteActivation: REGDB_E_CLASSNOTREG(0x80040154)"),
			want: "WMI not available on this server",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapWMIError(tt.err)
			if !strings.Contains(got.Error(), tt.want) {
				t.Errorf("mapWMIError(%v) = %q, want substring %q", tt.err, got, tt.want)
			}
		})
	}

	t.Run("passthrough", func(t *testing.T) {
		err := errors.New("something unexpected")
		if got := mapWMIError(err); got != err {
			t.Errorf("mapWMIError(%v) = %v, want passthrough", err, got)
		}
	})
}
