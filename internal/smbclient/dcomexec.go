package smbclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	iactivation "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	iobjectexporter "github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	idispatch "github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut/idispatch/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	// Registering the win32 error table makes hresult.FromCode render
	// human-readable text ("Access is denied.") next to the raw code.
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/transport"

	"anvil/internal/ui"
)

// IDispatch invoke flags (MS-OAUT DISPATCH_*).
const (
	dispatchMethod      uint32 = 0x00000001
	dispatchPropertyGet uint32 = 0x00000002
)

// DCOM object CLSIDs, matching impacket's/gopacket's dcomexec.
var (
	clsidMMC20              = &dcom.ClassID{Data1: 0x49B2791A, Data2: 0xB1AE, Data3: 0x4C90, Data4: []byte{0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}}
	clsidShellWindows       = &dcom.ClassID{Data1: 0x9BA05972, Data2: 0xF6A8, Data3: 0x11CF, Data4: []byte{0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}}
	clsidShellBrowserWindow = &dcom.ClassID{Data1: 0xC08AFD90, Data2: 0xF2A1, Data3: 0x11D1, Data4: []byte{0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}}
)

// dcomObjectKind selects the IDispatch navigation path to the exec method.
type dcomObjectKind int

const (
	objShellWindows dcomObjectKind = iota
	objShellBrowserWindow
	objMMC20
)

// dcomObject is one activatable DCOM class usable for command execution.
type dcomObject struct {
	name  string // display name, used in errors and debug output
	clsid *dcom.ClassID
	kind  dcomObjectKind
}

// dcomObjects is the fallback order tried by ExecDCOM: ShellWindows first
// (impacket's/gopacket's default), then ShellBrowserWindow, then MMC20.
// Server 2022 exposes all three, but shell-extension hosts can refuse
// activation when no interactive session exists (ShellWindows/
// ShellBrowserWindow ride explorer.exe); MMC20's ExecuteShellCommand is the
// classic fallback that needs no shell.
var dcomObjects = []dcomObject{
	{"ShellWindows", clsidShellWindows, objShellWindows},
	{"ShellBrowserWindow", clsidShellBrowserWindow, objShellBrowserWindow},
	{"MMC20", clsidMMC20, objMMC20},
}

// dcomAttemptTimeout bounds one activation+invoke attempt. The go-msrpc
// transport carries its own 10s network timeout; this is the outer backstop
// covering the full round-trip chain (EPM, ServerAlive2, RemoteActivation,
// OXID connect, IDispatch navigation, invoke) so a hung attempt still lets
// the fallback to the next object proceed.
const dcomAttemptTimeout = 60 * time.Second

// dcomPwd is the working directory the remote command starts in (matches
// impacket's dcomexec).
const dcomPwd = `C:\windows\system32`

// ExecDCOM runs a single command on the target via DCOM, mirroring
// gopacket's tools/dcomexec: `cmd.exe /Q /C ( <cmd> ) > %windir%\Temp\<file>
// 2>&1` is launched through a remotely activated DCOM object (ShellWindows,
// falling back to ShellBrowserWindow, then MMC20), and the output file is
// read back over this SMB session through ADMIN$ — the same retrieval path
// as Exec (TSCH). Requires admin on the target.
//
// Unlike Exec, DCOM cannot ride the SMB session: activation talks
// RPC-over-TCP to the endpoint mapper (135) and a dynamic OXID port, so one
// transient DCOM channel is opened per invocation (announced by the caller)
// and closed before returning, after calling Quit() on the object when the
// object supports it (MMC20, ShellBrowserWindow; ShellWindows has none).
//
// Cleanup is verified, not fire-and-forget: the output file is deleted over
// SMB before ExecDCOM returns, or a warning names the leftover.
func (s *Session) ExecDCOM(cmd string) (output string, warnings []string, err error) {
	tag := randHex(4) // 8 hex chars
	tmpFile := "anv-" + tag + ".tmp"
	outPath := "Temp/" + tmpFile // relative to ADMIN$ (C:\Windows)

	// Switch to execShare for output retrieval; restore the caller's share
	// afterwards (same convention as Exec).
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

	// Clean up the output file on ALL paths; waitExecOutput already removed
	// it on success, so this only fires on failure paths.
	defer func() {
		if w := s.cleanupExecOutput(outPath); w != "" {
			warnings = append(warnings, w)
		}
	}()

	secOpts, err := s.dcomAuth()
	if err != nil {
		return "", nil, err
	}

	args := dcomArgs(cmd, tmpFile)
	ui.Debugf("dcomexec[%s]: args: %s", tag, args)

	var failed []string
	for _, obj := range dcomObjects {
		ctx, cancel := context.WithTimeout(context.Background(), dcomAttemptTimeout)
		dc, err := s.dcomConnect(ctx, obj, secOpts)
		if err != nil {
			ui.Debugf("dcomexec[%s]: %s: %v", tag, obj.name, err)
			failed = append(failed, fmt.Sprintf("%s: %s", obj.name, mapDCOMError(err)))
			cancel()
			continue
		}
		ui.Debugf("dcomexec[%s]: %s activated, invoking", tag, obj.name)

		err = dc.invoke(ctx, "cmd.exe", args, dcomPwd)
		dc.close()
		cancel()
		if err != nil {
			ui.Debugf("dcomexec[%s]: %s invoke: %v", tag, obj.name, err)
			failed = append(failed, fmt.Sprintf("%s: %s", obj.name, mapDCOMError(err)))
			continue
		}

		content, waitErr := s.waitExecOutput(outPath)
		if waitErr != nil {
			// The command already ran; retrying another object would run it
			// twice. Surface the retrieval failure instead.
			return "", nil, waitErr
		}
		return content, nil, nil
	}

	return "", nil, fmt.Errorf("DCOM execution failed on all objects (%s)", strings.Join(failed, "; "))
}

// dcomArgs builds the cmd.exe argument string: the command is wrapped in
// parens so the redirect captures the whole thing — `cmd /C a & b > file`
// would otherwise redirect only the last `&`-segment (same convention as
// Exec).
func dcomArgs(cmd, tmpFile string) string {
	return fmt.Sprintf("/Q /C ( %s ) > %%windir%%\\Temp\\%s 2>&1", cmd, tmpFile)
}

// dcomAuth builds the dcerpc security options for the session's auth
// material — password, pass-the-hash, or kerberos via ccache. Mirrors
// tools/dcomexec's setup (including its KDC-via-pkg/transport routing), but
// where the tool registers credentials/mechanisms on gssapi's GLOBAL stores,
// anvil carries them as dcerpc.SecurityContextOptions
// (WithCredentials/WithMechanism). Two reasons, both fatal in a long-lived
// shell session:
//   - gssapi.AddMechanism panics on re-registration — the second ExecDCOM
//     call would crash the process.
//   - A context-local store (gssapi.NewSecurityContext options) is shadowed
//     once the first bind stamps the ctx's AttributeRPCContext attribute:
//     every subsequent client (the activation alter_context, the next
//     fallback attempt) re-wraps the ctx with EMPTY stores and the bind dies
//     with "unsupported mechanism requested". SecurityContextOptions are
//     re-applied by go-msrpc on every NewSecurity call, so each client —
//     first bind or alter_context — gets a fresh store carrying them.
func (s *Session) dcomAuth() ([]dcerpc.Option, error) {
	creds := s.creds

	fullUser := creds.Username
	if creds.Domain != "" {
		fullUser = creds.Domain + "\\" + creds.Username
	}

	// DCERPC runs with packet privacy (WithSeal), matching .NET's DCOM
	// default. On the Server 2022 lab DC, integrity-only (WithSign) got
	// every class's RemoteActivation rejected with a bare 0x800706ba, while
	// sealing surfaced the true per-class errors (e.g. 0x8000401a
	// CO_E_RUNAS_LOGON_FAILURE for the shell objects when no interactive
	// session exists). Dials (and the endpoint-mapper DNS lookup) go through
	// gopacket's pkg/transport like every other anvil channel. go-msrpc's
	// default logger writes to stderr — silence it; diagnostics here go
	// through ui.Debugf.
	secOpts := []dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithDialer(transport.ContextDialer{}),
		dcerpc.WithLogger(zerolog.New(io.Discard)),
	}

	switch {
	case creds.UseKerberos:
		ccachePath := os.Getenv("KRB5CCNAME")
		if ccachePath == "" {
			local := creds.Username + ".ccache"
			if _, err := os.Stat(local); err == nil {
				ccachePath = local
			}
		}
		if ccachePath == "" {
			return nil, fmt.Errorf("no kerberos ticket — mint one (getTGT/kinit) and set KRB5CCNAME, or pass -p")
		}
		ccache, err := gokrb5credentials.LoadCCache(ccachePath)
		if err != nil {
			return nil, fmt.Errorf("load ccache: %v", err)
		}

		// Realm is DNS-form upper-case; the KDC is the DC (--dc-ip), else the
		// SMB host itself (a DC is its own KDC). DCEStyle is required for
		// DCERPC kerberos (no gss-wrap framing on the wire).
		realm := strings.ToUpper(creds.Domain)
		kdc := creds.DCIP
		if kdc == "" {
			kdc = s.dialHost()
		}
		krb5Conf, err := gokrb5config.NewFromString(kerberos.SynthesizeKrb5Config(realm, kdc))
		if err != nil {
			return nil, fmt.Errorf("kerberos config: %v", err)
		}
		krbConfig := krb5.NewConfig()
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
		krbConfig.DCEStyle = true
		krbConfig.KDCDialer = kerberos.TransportKDCDialer{}

		// SPNEGO first: it is the default mechanism for the bind (matching
		// tools/dcomexec's registration order). DCOM authenticates against
		// the machine account's HOST SPN.
		return append(secOpts,
			dcerpc.WithCredentials(credential.NewFromCCache(fullUser, ccache)),
			dcerpc.WithMechanism(ssp.SPNEGO),
			dcerpc.WithMechanism(ssp.KRB5, krbConfig),
			dcerpc.WithTargetName("host/"+s.host),
			dcerpc.WithSecurityConfig(krbConfig)), nil

	case creds.Hash != "":
		ntHash, err := kerberos.ParseHashes(creds.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hash format: %v", err)
		}
		return append(secOpts,
			dcerpc.WithCredentials(credential.NewFromNTHash(fullUser, ntHash)),
			dcerpc.WithMechanism(ssp.NTLM),
			dcerpc.WithMechanism(ssp.SPNEGO)), nil

	default:
		return append(secOpts,
			dcerpc.WithCredentials(credential.NewFromPassword(fullUser, creds.Password)),
			dcerpc.WithMechanism(ssp.NTLM),
			dcerpc.WithMechanism(ssp.SPNEGO)), nil
	}
}

// dialHost returns the address to dial for extra channels: the target IP
// when the session was established through one (--target-ip, no working
// DNS), else the SMB host name.
func (s *Session) dialHost() string {
	if s.targetIP != "" {
		return s.targetIP
	}
	return s.host
}

// dcomConn is one open DCOM channel: the endpoint-mapper connection (135),
// the OXID connection (dynamic port), and the resolved exec interface.
type dcomConn struct {
	epmConn    dcerpc.Conn
	oxidConn   dcerpc.Conn
	opts       []dcerpc.Option          // security options, reused on interface rebinds
	topDisp    idispatch.DispatchClient // top-level IDispatch from activation
	execDisp   idispatch.DispatchClient // interface carrying the exec method
	execDISPID int32                    // DISPID of ExecuteShellCommand/ShellExecute
	quitDISPID *int32                   // DISPID of Quit (nil for ShellWindows)
	comVer     *dcom.COMVersion
	kind       dcomObjectKind
}

// dcomConnect activates obj on the target and navigates to its exec
// interface. Mirrors tools/dcomexec's connect(): endpoint mapper →
// IObjectExporter ServerAlive2 → IRemoteActivation with the server's own COM
// version → connect the returned OXID over ncacn_ip_tcp → per-object
// IDispatch navigation. Every failure path closes what was opened.
func (s *Session) dcomConnect(ctx context.Context, obj dcomObject, secOpts []dcerpc.Option) (*dcomConn, error) {
	host := s.dialHost()

	epmConn, err := dcerpc.Dial(ctx, net.JoinHostPort(host, "135"), dcerpc.WithDialer(transport.ContextDialer{}))
	if err != nil {
		return nil, fmt.Errorf("endpoint mapper: %v", err)
	}
	dc := &dcomConn{epmConn: epmConn, opts: secOpts, comVer: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}, kind: obj.kind}
	fail := func(err error) (*dcomConn, error) {
		dc.close()
		return nil, err
	}

	// ServerAlive2's COMVersion is what the server speaks; ORPCThis headers
	// must carry it or Windows answers E_UNEXPECTED on the activation.
	objExp, err := iobjectexporter.NewObjectExporterClient(ctx, epmConn, secOpts...)
	if err != nil {
		return fail(fmt.Errorf("object exporter client: %v", err))
	}
	alive2, err := objExp.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return fail(fmt.Errorf("ServerAlive2: %v", err))
	}
	if alive2.COMVersion != nil {
		dc.comVer = alive2.COMVersion
	}

	actClient, err := iactivation.NewActivationClient(ctx, epmConn, secOpts...)
	if err != nil {
		return fail(fmt.Errorf("activation client: %v", err))
	}
	actResp, err := actClient.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: alive2.COMVersion},
		ClassID:                    obj.clsid.GUID(),
		IIDs:                       []*dcom.IID{idispatch.DispatchIID},
		RequestedProtocolSequences: []uint16{7}, // ncacn_ip_tcp
	})
	if err != nil {
		return fail(fmt.Errorf("activation: %v", err))
	}
	if actResp.HResult != 0 {
		// hresult.FromCode returns nil for codes outside its table — guard
		// the description so the error never carries a "%!s(<nil>)" artifact.
		hr := uint32(actResp.HResult)
		desc := ""
		if herr := hresult.FromCode(hr); herr != nil {
			desc = " (" + herr.Error() + ")"
		}
		return fail(fmt.Errorf("activation rejected: 0x%08x%s", hr, desc))
	}
	if len(actResp.InterfaceData) == 0 || actResp.InterfaceData[0] == nil {
		return fail(fmt.Errorf("activation returned no interface data"))
	}
	std := actResp.InterfaceData[0].GetStandardObjectReference().Std

	// The OXID bindings name the object's RPC endpoints; dial the TCP one.
	// The ncacn_ip_tcp:<host> prefix pins the address — the server's own
	// string binding may carry a name that doesn't resolve here.
	endpoints := actResp.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")
	if len(endpoints) == 0 {
		return fail(fmt.Errorf("no TCP endpoint in OXID bindings"))
	}
	oxidConn, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+host, append(endpoints, dcerpc.WithDialer(transport.ContextDialer{}))...)
	if err != nil {
		return fail(fmt.Errorf("OXID endpoint: %v", err))
	}
	dc.oxidConn = oxidConn

	dispOpts := append([]dcerpc.Option{dcom.WithIPID(std.IPID)}, secOpts...)
	topDisp, err := idispatch.NewDispatchClient(ctx, oxidConn, dispOpts...)
	if err != nil {
		return fail(fmt.Errorf("IDispatch client: %v", err))
	}
	dc.topDisp = topDisp

	switch obj.kind {
	case objMMC20:
		err = dc.setupMMC20(ctx)
	case objShellWindows:
		err = dc.setupShellExec(ctx, true) // via Item()
	case objShellBrowserWindow:
		err = dc.setupShellBrowserWindow(ctx)
	}
	if err != nil {
		return fail(err)
	}
	return dc, nil
}

// setupMMC20 navigates iMMC → Document → ActiveView → ExecuteShellCommand,
// and remembers iMMC's Quit DISPID for cleanup.
func (c *dcomConn) setupMMC20(ctx context.Context) error {
	c.quitDISPID = c.lookupDISPID(ctx, c.topDisp, "Quit") // best-effort

	docDisp, err := c.propertyDispatch(ctx, c.topDisp, "Document")
	if err != nil {
		return fmt.Errorf("Document: %v", err)
	}
	viewDisp, err := c.propertyDispatch(ctx, docDisp, "ActiveView")
	if err != nil {
		return fmt.Errorf("ActiveView: %v", err)
	}
	execID, err := c.getDISPID(ctx, viewDisp, "ExecuteShellCommand")
	if err != nil {
		return err
	}
	c.execDisp = viewDisp
	c.execDISPID = execID
	return nil
}

// setupShellBrowserWindow navigates iMMC → Document → Application →
// ShellExecute, and remembers the top-level Quit DISPID for cleanup.
func (c *dcomConn) setupShellBrowserWindow(ctx context.Context) error {
	c.quitDISPID = c.lookupDISPID(ctx, c.topDisp, "Quit") // best-effort
	return c.setupShellExec(ctx, false)
}

// setupShellExec is the shared navigation for the two shell objects:
// ShellWindows starts from Item() (a live shell window), ShellBrowserWindow
// goes straight to Document; both end at Application → ShellExecute.
// ShellWindows has no Quit (matches impacket: pQuit = None).
func (c *dcomConn) setupShellExec(ctx context.Context, useItem bool) error {
	startDisp := c.topDisp
	if useItem {
		itemID, err := c.getDISPID(ctx, startDisp, "Item")
		if err != nil {
			return err
		}
		itemDisp, err := c.invokeDispatch(ctx, startDisp, itemID, dispatchMethod)
		if err != nil {
			return fmt.Errorf("Item: %v", err)
		}
		startDisp = itemDisp
	}

	docDisp, err := c.propertyDispatch(ctx, startDisp, "Document")
	if err != nil {
		return fmt.Errorf("Document: %v", err)
	}
	appDisp, err := c.propertyDispatch(ctx, docDisp, "Application")
	if err != nil {
		return fmt.Errorf("Application: %v", err)
	}
	execID, err := c.getDISPID(ctx, appDisp, "ShellExecute")
	if err != nil {
		return err
	}
	c.execDisp = appDisp
	c.execDISPID = execID
	return nil
}

// getDISPID resolves one member name to its DISPID (GetIDsOfNames, en-US
// locale — the only locale guaranteed present on any SKU).
func (c *dcomConn) getDISPID(ctx context.Context, disp idispatch.DispatchClient, name string) (int32, error) {
	resp, err := disp.GetIDsOfNames(ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: c.comVer}, Names: []string{name}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return 0, fmt.Errorf("GetIDsOfNames(%s): %v", name, err)
	}
	if len(resp.DispatchID) == 0 {
		return 0, fmt.Errorf("GetIDsOfNames(%s): no DISPID returned", name)
	}
	return resp.DispatchID[0], nil
}

// lookupDISPID is getDISPID's best-effort variant (used for Quit, which some
// objects lack): nil on failure.
func (c *dcomConn) lookupDISPID(ctx context.Context, disp idispatch.DispatchClient, name string) *int32 {
	id, err := c.getDISPID(ctx, disp, name)
	if err != nil {
		return nil
	}
	return &id
}

// invokeDispatch invokes a method/property that returns an IDispatch and
// rebinds the returned interface pointer (its IPID) as a new client.
func (c *dcomConn) invokeDispatch(ctx context.Context, disp idispatch.DispatchClient, dispid int32, flags uint32) (idispatch.DispatchClient, error) {
	inv, err := disp.Invoke(ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: c.comVer}, DispatchIDMember: dispid,
		LocaleID: 0x409, Flags: flags, DispatchParams: &oaut.DispatchParams{},
	})
	if err != nil {
		return nil, err
	}
	ipid, err := ipidFromVariant(inv.VarResult)
	if err != nil {
		return nil, err
	}
	opts := append([]dcerpc.Option{dcom.WithIPID(ipid)}, c.secOpts()...)
	return idispatch.NewDispatchClient(ctx, c.oxidConn, opts...)
}

// propertyDispatch invokes a property-get returning an IDispatch (the
// Document/ActiveView/Application navigation pattern).
func (c *dcomConn) propertyDispatch(ctx context.Context, disp idispatch.DispatchClient, name string) (idispatch.DispatchClient, error) {
	id, err := c.getDISPID(ctx, disp, name)
	if err != nil {
		return nil, err
	}
	return c.invokeDispatch(ctx, disp, id, dispatchPropertyGet)
}

// secOpts carries the channel's security options for interface rebinds.
func (c *dcomConn) secOpts() []dcerpc.Option { return c.opts }

// invoke runs the exec method: MMC20's ExecuteShellCommand(Command,
// Directory, Parameters, WindowState) or the shell objects'
// ShellExecute(File, vArgs, vDir, vOperation, vShow). DISPPARAMS lists
// arguments in REVERSE order (last parameter first). "7" is
// SW_SHOWMINNOACTIVE / "0" SW_HIDE — the window state parameters are BSTRs
// because the shell objects declare them as VARIANTs.
func (c *dcomConn) invoke(ctx context.Context, shell, args, pwd string) error {
	var dispArgs []*oaut.Variant
	if c.kind == objMMC20 {
		dispArgs = []*oaut.Variant{
			newVariantBSTR("7"),   // WindowState
			newVariantBSTR(args),  // Parameters
			newVariantBSTR(pwd),   // Directory
			newVariantBSTR(shell), // Command
		}
	} else {
		dispArgs = []*oaut.Variant{
			newVariantBSTR("0"),   // vShow
			newVariantBSTR(""),    // vOperation
			newVariantBSTR(pwd),   // vDir
			newVariantBSTR(args),  // vArgs
			newVariantBSTR(shell), // File
		}
	}
	_, err := c.execDisp.Invoke(ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: c.comVer}, DispatchIDMember: c.execDISPID,
		LocaleID: 0x409, Flags: dispatchMethod,
		DispatchParams: &oaut.DispatchParams{Args: dispArgs},
	})
	return err
}

// close calls Quit() on objects that have it (MMC20, ShellBrowserWindow —
// ShellWindows doesn't, matching impacket) and tears down both connections.
// Runs on a fresh context: the attempt context may already be expired.
func (c *dcomConn) close() {
	ctx := context.Background()
	if c.quitDISPID != nil && c.topDisp != nil {
		_, _ = c.topDisp.Invoke(ctx, &idispatch.InvokeRequest{
			This: &dcom.ORPCThis{Version: c.comVer}, DispatchIDMember: *c.quitDISPID,
			LocaleID: 0x409, Flags: dispatchMethod, DispatchParams: &oaut.DispatchParams{},
		})
	}
	if c.oxidConn != nil {
		c.oxidConn.Close(ctx)
	}
	if c.epmConn != nil {
		c.epmConn.Close(ctx)
	}
}

// ipidFromVariant extracts the interface pointer's IPID from an invoke
// result that must carry an IDispatch (VT_DISPATCH).
func ipidFromVariant(result *oaut.Variant) (*dcom.IPID, error) {
	if result == nil || result.VarUnion == nil {
		return nil, fmt.Errorf("returned no result")
	}
	dispVal, ok := result.VarUnion.Value.(*oaut.Variant_VarUnion_IDispatch)
	if !ok || dispVal == nil || dispVal.IDispatch == nil {
		return nil, fmt.Errorf("did not return an IDispatch (VT=%d)", result.VT)
	}
	ipid := (*dcom.InterfacePointer)(dispVal.IDispatch).IPID()
	if ipid == nil {
		return nil, fmt.Errorf("no IPID in returned interface")
	}
	return ipid, nil
}

// newVariantBSTR builds a VT_BSTR variant (the only argument type the exec
// methods take here).
func newVariantBSTR(s string) *oaut.Variant {
	return &oaut.Variant{
		VT: uint16(oaut.VarEnumString),
		VarUnion: &oaut.Variant_VarUnion{
			Value: &oaut.Variant_VarUnion_BSTR{
				BSTR: &oaut.String{Data: s},
			},
		},
	}
}

// mapDCOMError renders a DCOM failure as a plain-language message, in the
// spirit of Describe(): the common HRESULTs and dial failures get themed
// text, everything else passes through.
func mapDCOMError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x80070005"), strings.Contains(msg, "Access is denied"):
		// E_ACCESSDENIED — activation or launch permission.
		return "access denied (DCOM activation requires administrator)"
	case strings.Contains(msg, "0x800706ba"):
		// RPC_S_SERVER_UNAVAILABLE from RemoteActivation. On the Server 2022
		// lab DC this is what every shell/MMC object answers to a REMOTE
		// activation while service-hosted DCOM (WMI) activates fine: the
		// GUI server process can't be launched for a network logon. Proven
		// identical for impacket's dcomexec and gopacket's tools/dcomexec.
		return "cannot start the DCOM object on the target (server unavailable) — shell objects often refuse to launch remotely; exec (task scheduler) may still work"
	case strings.Contains(msg, "0x8000401a"):
		// CO_E_RUNAS_LOGON_FAILURE — the object's AppID identity can't log
		// on (seen for shell objects when no interactive session exists).
		return "cannot start the DCOM object: the configured identity can't log on (no interactive session on the target)"
	case strings.Contains(msg, "0x80040154"):
		// REGDB_E_CLASSNOTREG.
		return "class not registered on this server"
	case strings.Contains(msg, "0x80004002"):
		// E_NOINTERFACE.
		return "interface not supported by this server"
	case strings.Contains(msg, "connection refused"):
		return "cannot reach the endpoint mapper (port 135)"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timed out"
	}
	return msg
}
