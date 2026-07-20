package smbclient

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
)

// TestDCOMArgs pins the remote command-line construction: the command is
// paren-wrapped so the redirect captures compound commands, and output lands
// in %windir%\Temp.
func TestDCOMArgs(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		tmpFile string
		want    string
	}{
		{
			name:    "simple command",
			cmd:     "whoami",
			tmpFile: "anv-1234abcd.tmp",
			want:    `/Q /C ( whoami ) > %windir%\Temp\anv-1234abcd.tmp 2>&1`,
		},
		{
			name:    "compound command stays inside parens",
			cmd:     "whoami & hostname",
			tmpFile: "anv-deadbeef.tmp",
			want:    `/Q /C ( whoami & hostname ) > %windir%\Temp\anv-deadbeef.tmp 2>&1`,
		},
		{
			name:    "redirect targets the given temp file",
			cmd:     "ipconfig /all",
			tmpFile: "anv-00000000.tmp",
			want:    `/Q /C ( ipconfig /all ) > %windir%\Temp\anv-00000000.tmp 2>&1`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dcomArgs(tc.cmd, tc.tmpFile); got != tc.want {
				t.Errorf("dcomArgs(%q, %q) = %q, want %q", tc.cmd, tc.tmpFile, got, tc.want)
			}
		})
	}
}

// TestMapDCOMError drives the themed error mapping: raw HRESULTs and dial
// failures must come out as plain-language messages, and unknown errors must
// pass through untouched.
func TestMapDCOMError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "E_ACCESSDENIED hex",
			err:  errors.New("activation rejected: 0x80070005 (E_ACCESSDENIED)"),
			want: "access denied (DCOM activation requires administrator)",
		},
		{
			name: "access denied rendered text",
			err:  errors.New("activation rejected: 0x80070005 (Access is denied.)"),
			want: "access denied (DCOM activation requires administrator)",
		},
		{
			name: "RPC_S_SERVER_UNAVAILABLE at activation",
			err:  errors.New("activation rejected: 0x800706ba"),
			want: "cannot start the DCOM object on the target (server unavailable) — shell objects often refuse to launch remotely; exec (task scheduler) may still work",
		},
		{
			name: "CO_E_RUNAS_LOGON_FAILURE",
			err:  errors.New("activation rejected: 0x8000401a (hresult: CO_E_RUNAS_LOGON_FAILURE (0x8000401a): The server process could not be started because the configured identity is incorrect. Check the user name and password.)"),
			want: "cannot start the DCOM object: the configured identity can't log on (no interactive session on the target)",
		},
		{
			name: "REGDB_E_CLASSNOTREG",
			err:  errors.New("activation rejected: 0x80040154 (Class not registered)"),
			want: "class not registered on this server",
		},
		{
			name: "E_NOINTERFACE",
			err:  errors.New("activation rejected: 0x80004002"),
			want: "interface not supported by this server",
		},
		{
			name: "epmapper refused",
			err:  errors.New("endpoint mapper: dial tcp 10.0.0.1:135: connect: connection refused"),
			want: "cannot reach the endpoint mapper (port 135)",
		},
		{
			name: "dial timeout",
			err:  errors.New("endpoint mapper: dial tcp 10.0.0.1:135: i/o timeout"),
			want: "timed out",
		},
		{
			name: "context deadline",
			err:  errors.New("activation: context deadline exceeded"),
			want: "timed out",
		},
		{
			name: "unknown error passes through",
			err:  errors.New("activation rejected: 0x8000ffff (Catastrophic failure)"),
			want: "activation rejected: 0x8000ffff (Catastrophic failure)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapDCOMError(tc.err); got != tc.want {
				t.Errorf("mapDCOMError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestDCOMObjects pins the fallback chain: ShellWindows first (impacket's
// default), ShellBrowserWindow next, MMC20 last — three distinct CLSIDs
// matching the well-known class registrations.
func TestDCOMObjects(t *testing.T) {
	if len(dcomObjects) != 3 {
		t.Fatalf("len(dcomObjects) = %d, want 3", len(dcomObjects))
	}

	wantNames := []string{"ShellWindows", "ShellBrowserWindow", "MMC20"}
	wantCLSIDs := []string{
		"9ba05972-f6a8-11cf-a442-00a0c90a8f39",
		"c08afd90-f2a1-11d1-8455-00a0c91f3880",
		"49b2791a-b1ae-4c90-9b8e-e860ba07f889",
	}
	wantKinds := []dcomObjectKind{objShellWindows, objShellBrowserWindow, objMMC20}

	seen := map[string]bool{}
	for i, obj := range dcomObjects {
		if obj.name != wantNames[i] {
			t.Errorf("dcomObjects[%d].name = %q, want %q", i, obj.name, wantNames[i])
		}
		if obj.kind != wantKinds[i] {
			t.Errorf("dcomObjects[%d].kind = %d, want %d", i, obj.kind, wantKinds[i])
		}
		got := strings.ToLower(obj.clsid.String())
		if got != wantCLSIDs[i] {
			t.Errorf("dcomObjects[%d].clsid = %s, want %s", i, got, wantCLSIDs[i])
		}
		if seen[got] {
			t.Errorf("duplicate CLSID %s in fallback chain", got)
		}
		seen[got] = true
	}
}

// TestNewVariantBSTR verifies the VT_BSTR variant shape the exec methods
// take for every argument.
func TestNewVariantBSTR(t *testing.T) {
	v := newVariantBSTR("cmd.exe")
	if v.VT != uint16(oaut.VarEnumString) {
		t.Errorf("VT = %d, want VarEnumString (%d)", v.VT, oaut.VarEnumString)
	}
	bstr, ok := v.VarUnion.Value.(*oaut.Variant_VarUnion_BSTR)
	if !ok {
		t.Fatalf("VarUnion.Value = %T, want *Variant_VarUnion_BSTR", v.VarUnion.Value)
	}
	if bstr.BSTR == nil || bstr.BSTR.Data != "cmd.exe" {
		t.Errorf("BSTR payload = %+v, want Data=%q", bstr.BSTR, "cmd.exe")
	}
}

// TestDialHost pins the extra-channel dial target: --target-ip wins over the
// SMB host name (lab without DNS), plain sessions dial the host.
func TestDialHost(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		targetIP string
		want     string
	}{
		{name: "target IP wins", host: "dc01.corp.local", targetIP: "192.168.1.10", want: "192.168.1.10"},
		{name: "host name without target IP", host: "dc01.corp.local", targetIP: "", want: "dc01.corp.local"},
		{name: "IP host stays", host: "192.168.1.10", targetIP: "", want: "192.168.1.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{host: tc.host, targetIP: tc.targetIP}
			if got := s.dialHost(); got != tc.want {
				t.Errorf("dialHost() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIPIDFromVariant covers the invoke-result unwrapping: nil results and
// non-IDispatch variants are errors, a VT_DISPATCH variant yields its IPID.
func TestIPIDFromVariant(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		if _, err := ipidFromVariant(nil); err == nil {
			t.Fatal("want error for nil result")
		}
	})
	t.Run("non-dispatch variant", func(t *testing.T) {
		if _, err := ipidFromVariant(newVariantBSTR("x")); err == nil {
			t.Fatal("want error for VT_BSTR result")
		} else if !strings.Contains(err.Error(), "did not return an IDispatch") {
			t.Fatalf("error = %v, want IDispatch complaint", err)
		}
	})
	t.Run("dispatch variant", func(t *testing.T) {
		// A marshaled interface pointer with a nil IPID must still error
		// cleanly rather than panic.
		v := &oaut.Variant{
			VT: 9, // VT_DISPATCH
			VarUnion: &oaut.Variant_VarUnion{
				Value: &oaut.Variant_VarUnion_IDispatch{IDispatch: nil},
			},
		}
		if _, err := ipidFromVariant(v); err == nil {
			t.Fatal("want error for nil IDispatch pointer")
		}
	})
}

// TestDCOMArgsTempName documents the output-file naming contract ExecDCOM
// shares with Exec: anv-<rand>.tmp under %windir%\Temp, read back through
// ADMIN$ as Temp/<file>.
func TestDCOMArgsTempName(t *testing.T) {
	tmp := fmt.Sprintf("anv-%s.tmp", "1234abcd")
	args := dcomArgs("hostname", tmp)
	if !strings.Contains(args, `%windir%\Temp\`+tmp) {
		t.Errorf("args = %q, want redirect to %%windir%%\\Temp\\%s", args, tmp)
	}
}
