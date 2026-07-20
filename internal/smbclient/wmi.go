package smbclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	msrpc "github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/ienumwbemclassobject/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	// The win32/wmi erref tables make go-msrpc render HRESULTs as their
	// MS-ERREF names (WBEM_E_INVALID_CLASS(0x80041010), ...) — the substrings
	// mapWMIError matches. Mirrors gopacket's tools/wmiquery imports.
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/transport"

	"anvil/internal/ui"
)

// wmiNamespace is the WMI namespace every query/exec logs into. cimv2 holds
// the classes anvil cares about (Win32_Process, Win32_Service, Win32_OperatingSystem).
const wmiNamespace = "//./root/cimv2"

// WBEM flags for ExecQuery (MS-WMI 2.7.1): semi-synchronous, forward-only —
// the combination Impacket's wmiquery uses; results stream over the
// enumerator instead of buffering server-side.
const (
	wbemFlagReturnImmediately = 0x00000010
	wbemFlagForwardOnly       = 0x00000020
)

// wmiSSPOnce guards registerWMIMechanisms (see openWMI for why re-
// registration panics).
var wmiSSPOnce sync.Once

// registerWMIMechanisms registers every SSP the WMI paths can need, so the
// auth-path branches in openWMI never have to register their own.
func registerWMIMechanisms() {
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)
	gssapi.AddMechanism(ssp.KRB5)
}

// WMIResult is the outcome of one WQL query. Columns preserves the
// server-returned property order (a bare []map would lose it and the shell
// prints a table); Rows carries one rendered string map per instance.
type WMIResult struct {
	Columns []string
	Rows    []map[string]string
}

// addRow appends one rendered row. order is the instance's property order
// (wmio keeps values in a Go map, so order must come from the property
// list); Columns is extended when a later row carries a property earlier
// rows didn't — WMI makes no per-row schema promise.
func (r *WMIResult) addRow(order []string, vals map[string]any) {
	row := make(map[string]string, len(vals))
	for _, name := range order {
		v, ok := vals[name]
		if !ok {
			continue
		}
		seen := false
		for _, c := range r.Columns {
			if c == name {
				seen = true
				break
			}
		}
		if !seen {
			r.Columns = append(r.Columns, name)
		}
		row[name] = wmiValueString(v)
	}
	r.Rows = append(r.Rows, row)
}

// WMIQuery runs one WQL query against root\cimv2 and returns the result set.
// WMI has no SMB endpoint: this opens ONE transient DCOM channel (announced
// on screen) — TCP/135 for IObjectExporter + IActivation RemoteActivation,
// then the dynamic WMI endpoint the activation hands back — and closes it
// before returning. The SMB session itself is untouched (and unneeded;
// WMIQuery works with no share selected).
//
// DCOM rides go-msrpc (gopacket's tools/wmiquery stack); the SMB session's
// credentials are re-used for the DCOM bind, so no extra auth material is
// asked for. Kerberos mirrors tools/wmiquery's ccache path but is untested.
func (s *Session) WMIQuery(wql string) (*WMIResult, error) {
	// A trailing ';' is shell habit, not WQL — ExecQuery rejects it.
	wql = strings.TrimRight(strings.TrimSpace(wql), ";")
	if wql == "" {
		return nil, fmt.Errorf("empty query")
	}

	wc, err := s.openWMI()
	if err != nil {
		return nil, err
	}
	defer wc.Close()

	resp, err := wc.svcs.ExecQuery(wc.ctx, &iwbemservices.ExecQueryRequest{
		This:          &dcom.ORPCThis{Version: wc.version},
		QueryLanguage: &oaut.String{Data: "WQL"},
		Query:         &oaut.String{Data: wql},
		Flags:         wbemFlagReturnImmediately | wbemFlagForwardOnly,
	})
	if err != nil {
		return nil, mapWMIError(fmt.Errorf("ExecQuery: %v", err))
	}
	if resp.Return != 0 {
		return nil, mapWMIError(fmt.Errorf("ExecQuery: %v", hresult.FromCode(uint32(resp.Return))))
	}
	if resp.Enum == nil {
		return nil, fmt.Errorf("ExecQuery returned no enumerator")
	}

	// The enumerator is another DCOM interface on the SAME connection —
	// rebind by IPID, no new channel.
	enumOpts := append([]msrpc.Option{dcom.WithIPID(resp.Enum.InterfacePointer().IPID())}, wc.secOpts...)
	enumClient, err := ienumwbemclassobject.NewEnumClassObjectClient(wc.ctx, wc.wmiConn, enumOpts...)
	if err != nil {
		return nil, fmt.Errorf("bind result enumerator: %v", err)
	}

	result := &WMIResult{}
	for {
		nextResp, err := enumClient.Next(wc.ctx, &ienumwbemclassobject.NextRequest{
			This:    &dcom.ORPCThis{Version: wc.version},
			Timeout: 0x7FFFFFFF, // WBEM_INFINITE — wait for the server, like Impacket
			Count:   1,
		})
		if err != nil {
			// S_FALSE (0x1) signals end of enumeration. go-msrpc treats any
			// non-zero HRESULT as an error, so match its renderings
			// (tools/wmiquery's exact set, proven against Windows).
			if nextResp != nil && nextResp.Returned > 0 {
				// Results arrived alongside the error — process them below.
			} else {
				es := err.Error()
				if strings.Contains(es, "S_FALSE") ||
					strings.Contains(es, "WBEM_S_FALSE") ||
					strings.Contains(es, "(0x00000001)") ||
					strings.Contains(es, "ERROR_INVALID_FUNCTION") {
					break
				}
				return nil, mapWMIError(fmt.Errorf("enumerating results: %v", err))
			}
		}
		if nextResp == nil || nextResp.Returned == 0 {
			break
		}
		for _, obj := range nextResp.Objects {
			wmioObj, err := wmiClassObjectToWMIO(obj)
			if err != nil {
				ui.Debugf("wmiquery: skipping unparsable object: %v", err)
				continue
			}
			vals := wmioObj.Values()
			if vals == nil || wmioObj.Instance == nil {
				continue
			}
			order := make([]string, len(wmioObj.Instance.Properties))
			for i, p := range wmioObj.Instance.Properties {
				order[i] = p.Name
			}
			result.addRow(order, vals)
		}
	}
	return result, nil
}

// ExecWMI runs a single command on the target via Win32_Process.Create over
// ONE transient DCOM channel (announced on screen), mirroring gopacket's
// tools/wmiexec: `cmd.exe /C ( cmd ) > %windir%\Temp\anv-<rand>.tmp 2>&1` is
// started as a new process, the output file is polled, read back, and
// deleted over the EXISTING SMB session (execShare, same as Exec's TSCH
// path). Requires admin on the target — both for Win32_Process.Create and
// for execShare.
//
// Cleanup is verified, not fire-and-forget: the output file delete is
// retried through the remote process's settle window, and a leftover is
// named in the returned warnings. Unlike Exec there is no task object to
// remove — the process is the only remote artifact.
func (s *Session) ExecWMI(cmd string) (output string, warnings []string, err error) {
	tag := randHex(4) // 8 hex chars
	tmpFile := "anv-" + tag + ".tmp"
	outPath := "Temp/" + tmpFile // relative to execShare (C:\Windows)

	wc, err := s.openWMI()
	if err != nil {
		return "", nil, err
	}
	defer wc.Close()

	// Switch to execShare for output retrieval; restore the caller's share
	// afterwards (same dance as Exec — pkg/smb has no unmount-current).
	prevShare := s.Share()
	if prevShare != execShare {
		if err := s.UseShare(execShare); err != nil {
			return "", nil, fmt.Errorf("cannot access %s for output: %v", execShare, err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	// Delete the output file on ALL paths once the share is up — a failed
	// Create can still have launched the process.
	defer func() {
		if w := s.cleanupExecOutput(outPath); w != "" {
			warnings = append(warnings, w)
		}
	}()

	cmdLine := buildWMICmdLine(cmd, tmpFile)
	ui.Debugf("wmiexec[%s]: %s", tmpFile, cmdLine)

	// query.Builder does GetObject(Win32_Process) + ExecMethod(Create) over
	// the existing channel; the class fetch is one extra round-trip per call.
	out, err := query.NewBuilder(wc.ctx, wc.svcs, wc.version).
		Spawn("Win32_Process").
		Method("Create").
		Values(wmio.Values{"CommandLine": cmdLine, "CurrentDirectory": nil}, wmio.JSONValueToType).
		Exec().
		Object()
	if err != nil {
		return "", nil, mapWMIError(fmt.Errorf("Win32_Process.Create: %v", err))
	}

	// Create's ReturnValue is an out-parameter, not an HRESULT: nonzero means
	// the process never started, so there will never be an output file to
	// poll — bail before the wait would burn the full timeout.
	vals := out.Values()
	ret, _ := wmiUint32(vals["ReturnValue"])
	if err := win32ProcessCreateError(ret); err != nil {
		return "", nil, err
	}

	content, waitErr := s.waitExecOutput(outPath)
	if waitErr != nil {
		return "", nil, waitErr
	}
	return content, nil, nil
}

// wmiClient is one open transient DCOM channel to the target's WMI service:
// the port-135 connection (kept alive — DCOM OXID resolution/pings ride it),
// the WMI endpoint connection activation handed back, and the bound
// IWbemServices client.
type wmiClient struct {
	svcs    iwbemservices.ServicesClient
	version *dcom.COMVersion
	ctx     context.Context
	secOpts []msrpc.Option
	epmConn msrpc.Conn
	wmiConn msrpc.Conn
}

// Close tears down both TCP connections (WMI endpoint first, then :135).
func (c *wmiClient) Close() {
	if c.wmiConn != nil {
		_ = c.wmiConn.Close(c.ctx)
	}
	if c.epmConn != nil {
		_ = c.epmConn.Close(c.ctx)
	}
}

// openWMI establishes one transient DCOM channel with the session's
// credentials, announced on screen per anvil's channel discipline. Mirrors
// gopacket's tools/wmiquery setup exactly: :135 IObjectExporter
// (ServerAlive2 for the COM version) → IActivation RemoteActivation of the
// WBEM Level1Login class → dial the returned OXID endpoint → NTLMLogin into
// root\cimv2 → IWbemServices. Auth is NTLM (password or pass-the-hash) or
// Kerberos via ccache; signing (pkt integrity) is always on.
func (s *Session) openWMI() (*wmiClient, error) {
	if s.null {
		return nil, fmt.Errorf("WMI needs credentials — a null session cannot use DCOM")
	}

	ui.Faint.Println("  opening DCOM channel (RPC/TCP: :135 activation + dynamic WMI endpoint)")

	fullUser := s.creds.Username
	if s.creds.Domain != "" {
		fullUser = s.creds.Domain + "\\" + s.creds.Username
	}

	// pkt-integrity signing: WMI demands it, and every DCOM dial goes through
	// pkg/transport so the connect timeout (and any configured proxy) applies.
	secOpts := []msrpc.Option{
		msrpc.WithSign(),
		msrpc.WithDialer(transport.ContextDialer{}),
	}

	// go-msrpc's SSP registry is process-global. Mechanisms MUST be
	// registered once per process: MechanismStore.AddMechanism panics on a
	// duplicate OID, which a long-lived shell would hit on the second WMI
	// invocation (gopacket's one-shot tools never re-register). Credentials
	// only append (first match wins, same value for a single session), so
	// re-adding per invocation is harmless.
	wmiSSPOnce.Do(registerWMIMechanisms)
	switch {
	case s.creds.UseKerberos:
		// Mirrors tools/wmiquery's ccache path. UNTESTED — dcsync's kerberos
		// precedent: NTLM is the verified path in the lab.
		krbConfig, err := s.wmiKerberosConfig(fullUser)
		if err != nil {
			return nil, err
		}
		// DCOM's service is the host itself; the SPN follows the dialed host.
		secOpts = append(secOpts,
			msrpc.WithTargetName("host/"+s.host),
			msrpc.WithSecurityConfig(krbConfig))
	case s.creds.Hash != "":
		ntHash, err := kerberos.ParseHashes(s.creds.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hash format: %v", err)
		}
		gssapi.AddCredential(credential.NewFromNTHash(fullUser, ntHash))
	default:
		gssapi.AddCredential(credential.NewFromPassword(fullUser, s.creds.Password))
	}

	ctx := gssapi.NewSecurityContext(context.Background())

	fail := func(stage string, err error) (*wmiClient, error) {
		return nil, mapWMIError(fmt.Errorf("%s: %v", stage, err))
	}

	// 1. Endpoint mapper / IObjectExporter on TCP/135.
	epmConn, err := msrpc.Dial(ctx, net.JoinHostPort(s.host, "135"),
		msrpc.WithDialer(transport.ContextDialer{}))
	if err != nil {
		return fail("dial :135 (DCOM endpoint mapper)", err)
	}
	objExp, err := iobjectexporter.NewObjectExporterClient(ctx, epmConn, secOpts...)
	if err != nil {
		epmConn.Close(ctx)
		return fail("bind IObjectExporter", err)
	}
	srv, err := objExp.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		epmConn.Close(ctx)
		return fail("ServerAlive2", err)
	}

	// 2. Remote activation of the WBEM Level1Login class. The COM version
	// comes from ServerAlive2, as the server reports it.
	actClient, err := iactivation.NewActivationClient(ctx, epmConn, secOpts...)
	if err != nil {
		epmConn.Close(ctx)
		return fail("bind IActivation", err)
	}
	act, err := actClient.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{7}, // ncacn_ip_tcp
	})
	if err != nil {
		epmConn.Close(ctx)
		return fail("RemoteActivation", err)
	}
	if act.HResult != 0 {
		epmConn.Close(ctx)
		return fail("RemoteActivation", hresult.FromCode(uint32(act.HResult)))
	}
	std := act.InterfaceData[0].GetStandardObjectReference().Std

	// 3. The activation's OXID bindings carry the dynamic WMI endpoint.
	// "ncacn_ip_tcp:" + host makes go-msrpc parse a StringBinding and hand
	// the host straight to the dialer (no DNS pre-lookup — an IP works).
	endpoints := act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")
	if len(endpoints) == 0 {
		epmConn.Close(ctx)
		return nil, fmt.Errorf("server offered no TCP endpoint for WMI")
	}
	wmiConn, err := msrpc.Dial(ctx, "ncacn_ip_tcp:"+s.host,
		append(endpoints, msrpc.WithDialer(transport.ContextDialer{}))...)
	if err != nil {
		epmConn.Close(ctx)
		return fail("dial WMI endpoint", err)
	}

	// 4. WBEM login into root\cimv2. DCOM interfaces on one connection are
	// addressed by IPID — each client rebinds to its interface's IPID.
	wmiCtx := gssapi.NewSecurityContext(ctx)
	loginOpts := append([]msrpc.Option{dcom.WithIPID(std.IPID)}, secOpts...)
	l1login, err := iwbemlevel1login.NewLevel1LoginClient(wmiCtx, wmiConn, loginOpts...)
	if err != nil {
		wmiConn.Close(ctx)
		epmConn.Close(ctx)
		return fail("bind IWbemLevel1Login", err)
	}
	login, err := l1login.NTLMLogin(wmiCtx, &iwbemlevel1login.NTLMLoginRequest{
		This:            &dcom.ORPCThis{Version: srv.COMVersion},
		NetworkResource: wmiNamespace,
	})
	if err != nil {
		wmiConn.Close(ctx)
		epmConn.Close(ctx)
		return fail("WMI login", err)
	}

	// 5. IWbemServices — the query/exec interface all WMI work rides.
	svcsOpts := append([]msrpc.Option{dcom.WithIPID(login.Namespace.InterfacePointer().IPID())}, secOpts...)
	svcs, err := iwbemservices.NewServicesClient(wmiCtx, wmiConn, svcsOpts...)
	if err != nil {
		wmiConn.Close(ctx)
		epmConn.Close(ctx)
		return fail("bind IWbemServices", err)
	}

	ui.Debugf("wmi: channel up (com %d.%d)", srv.COMVersion.MajorVersion, srv.COMVersion.MinorVersion)
	return &wmiClient{
		svcs:    svcs,
		version: srv.COMVersion,
		ctx:     wmiCtx,
		secOpts: secOpts,
		epmConn: epmConn,
		wmiConn: wmiConn,
	}, nil
}

// wmiKerberosConfig loads the session's ccache and builds the go-msrpc krb5
// security config for the DCOM bind (tools/wmiquery's kerberos branch:
// DCE-style, KDC from --dc-ip, KDC traffic through pkg/transport). The
// credential is registered in go-msrpc's global SSP store as a side effect.
func (s *Session) wmiKerberosConfig(fullUser string) (*krb5.Config, error) {
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath == "" {
		local := s.creds.Username + ".ccache"
		if _, err := os.Stat(local); err == nil {
			ccachePath = local
		}
	}
	if ccachePath == "" {
		return nil, fmt.Errorf("kerberos WMI needs a ccache — mint one (ticket/getTGT) and set KRB5CCNAME")
	}
	ccache, err := gokrb5credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("load ccache: %v", err)
	}
	gssapi.AddCredential(credential.NewFromCCache(fullUser, ccache))

	realm := strings.ToUpper(s.creds.Domain)
	kdc := s.creds.DCIP
	if kdc == "" {
		kdc = s.host
	}
	krb5Conf, err := gokrb5config.NewFromString(kerberos.SynthesizeKrb5Config(realm, kdc))
	if err != nil {
		return nil, fmt.Errorf("kerberos config: %v", err)
	}
	krbConfig := krb5.NewConfig()
	krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
	krbConfig.DCEStyle = true
	krbConfig.KDCDialer = kerberos.TransportKDCDialer{}
	return krbConfig, nil
}

// buildWMICmdLine wraps cmd in cmd.exe with stdout+stderr redirected to the
// output file under %windir%\Temp — the same convention as Exec's TSCH path.
// The command is wrapped in parens so the redirect captures the whole
// thing: `cmd /C a & b > file` would otherwise redirect only the last
// `&`-segment. cmd.exe expands %windir% server-side.
func buildWMICmdLine(cmd, tmpFile string) string {
	return fmt.Sprintf("cmd.exe /C ( %s ) > %%windir%%\\Temp\\%s 2>&1", cmd, tmpFile)
}

// win32ProcessCreateError renders Win32_Process.Create's ReturnValue
// out-parameter (documented set; 0 = success). ReturnValue 2 is what a
// non-admin caller gets, so it names the privilege problem.
func win32ProcessCreateError(code uint32) error {
	switch code {
	case 0:
		return nil
	case 2:
		return fmt.Errorf("Win32_Process.Create: access denied (admin required)")
	case 3:
		return fmt.Errorf("Win32_Process.Create: insufficient privilege")
	case 8:
		return fmt.Errorf("Win32_Process.Create: unknown failure")
	case 9:
		return fmt.Errorf("Win32_Process.Create: path not found")
	case 21:
		return fmt.Errorf("Win32_Process.Create: invalid parameter")
	default:
		return fmt.Errorf("Win32_Process.Create failed (ReturnValue %d)", code)
	}
}

// wmiUint32 coerces a decoded CIM numeric to uint32. wmio's decoder picks
// the Go type per CIM type (uint32, int64, float64, ...), so out-parameters
// like ReturnValue don't arrive under one static type.
func wmiUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case uint32:
		return n, true
	case uint64:
		return uint32(n), true
	case int:
		return uint32(n), true
	case int32:
		return uint32(n), true
	case int64:
		return uint32(n), true
	case float64:
		return uint32(n), true
	}
	return 0, false
}

// wmiValueString renders one CIM property value for table output, matching
// Impacket's wmiquery style: nil is "None", arrays are space-joined, nested
// objects collapse to "{object}".
func wmiValueString(v any) string {
	switch val := v.(type) {
	case nil:
		return "None"
	case string:
		return val
	case bool:
		if val {
			return "True"
		}
		return "False"
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = wmiValueString(item)
		}
		return strings.Join(parts, " ")
	case wmio.Values:
		return "{object}"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// wmiClassObjectToWMIO decodes one wire ClassObject into a wmio.Object: the
// NDR blob is a custom OBJREF whose ObjectData is the WMIO encoding
// (tools/wmiquery's classObjectToWMIO).
func wmiClassObjectToWMIO(classObj *wmi.ClassObject) (*wmio.Object, error) {
	if classObj == nil || len(classObj.Data) == 0 {
		return nil, fmt.Errorf("empty class object")
	}
	ref := &dcom.ObjectReference{}
	if err := ndr.Unmarshal(classObj.Data, ref, ndr.Opaque); err != nil {
		return nil, fmt.Errorf("ndr unmarshal: %v", err)
	}
	custom, ok := ref.ObjectReference.GetValue().(*dcom.ObjectReferenceCustom)
	if !ok || len(custom.ObjectData) == 0 {
		return nil, fmt.Errorf("not a custom object reference or empty data")
	}
	obj, err := wmio.Unmarshal(custom.ObjectData)
	if err != nil {
		return nil, fmt.Errorf("wmio unmarshal: %v", err)
	}
	return obj, nil
}

// mapWMIError translates DCOM/WMI failures into plain-language messages
// (themed-errors idiom: match the rendered HRESULT, never leak raw codes
// alone). With the win32/wmi erref tables linked, go-msrpc renders
// "WBEM_E_INVALID_CLASS(0x80041010)"-style text — match name and code.
func mapWMIError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x80070005"), strings.Contains(msg, "E_ACCESS_DENIED"),
		strings.Contains(msg, "0x80041003"): // WBEM_E_ACCESS_DENIED
		return fmt.Errorf("access denied (WMI needs local admin on the target)")
	case strings.Contains(msg, "0x80041010"): // WBEM_E_INVALID_CLASS
		return fmt.Errorf("invalid WMI class (check the class name)")
	case strings.Contains(msg, "0x80041017"): // WBEM_E_INVALID_QUERY
		return fmt.Errorf("invalid WQL query")
	case strings.Contains(msg, "0x800706BA"), // RPC_S_SERVER_UNAVAILABLE
		strings.Contains(msg, "0x8007274D"): // WSAECONNREFUSED
		return fmt.Errorf("DCOM unreachable — RPC server unavailable (port 135 / dynamic endpoint blocked)")
	case strings.Contains(msg, "0x80040154"): // REGDB_E_CLASSNOTREG
		return fmt.Errorf("WMI not available on this server (class not registered)")
	case strings.Contains(msg, "abstract syntax not supported"):
		// Samba's RPC server has no DCOM OXID resolver (IObjectExporter) —
		// it rejects ServerAlive2 before any WMI class is involved.
		return fmt.Errorf("not supported on this server (no DCOM/WMI endpoint)")
	case strings.Contains(msg, "0x80041002"): // WBEM_E_NOT_FOUND
		return fmt.Errorf("WMI object not found")
	}
	return err
}
