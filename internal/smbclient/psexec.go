package smbclient

import (
	"fmt"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
	"github.com/mandiant/gopacket/pkg/smb"

	"anvil/internal/ui"
)

// svcDeleteTimeout bounds the stop/delete/verify loop after the command
// finishes. Deleting an already-stopped service is instant; the loop covers
// the case where the output wait timed out while the remote cmd.exe was
// still running (the service must be stopped before the SCM accepts the
// delete).
const svcDeleteTimeout = 15 * time.Second

// svcManageAccess is the access mask for handles used to manage the
// temporary service: DELETE (0x00010000, a standard right) | SERVICE_STOP |
// SERVICE_QUERY_STATUS. gopacket's svcctl.SERVICE_ALL_ACCESS is 0x01FF — the
// service-specific rights only, WITHOUT the standard DELETE right — so a
// handle opened with it cannot delete the service (RDeleteService fails with
// ERROR_ACCESS_DENIED; observed on Server 2022).
const svcManageAccess = 0x00010000 | svcctl.SERVICE_STOP | svcctl.SERVICE_QUERY_STATUS

// ExecService runs a single command on the target via a temporary Windows
// service, mirroring gopacket's tools/smbexec (SHARE mode): a uniquely-named
// service is created via SVCCTL whose binary path writes a one-line batch
// (`( <cmd> ) > %windir%\Temp\<file> 2>&1`) into %windir%\Temp via echo,
// runs it, and deletes it. The output file is read back over the same SMB
// session — all over this one connection (the svcctl named pipe rides IPC$;
// no new connections). Unlike gopacket's tools/psexec no binary is
// uploaded: the "payload" is cmd.exe itself. Requires admin on the target
// (SC_MANAGER_CREATE_SERVICE).
//
// The batch indirection is not cosmetic: a service whose binary path
// redirects directly (`cmd.exe /C ( cmd ) > file 2>&1`) leaves the output
// file EMPTY on Server 2022 — cmd.exe runs and creates the file but the
// inner command's output never lands (measured; the SCM's CreateProcess
// launch of cmd.exe mangles the compound remainder). Writing the command
// into a batch first and running that batch is the proven form (Impacket's
// and gopacket's smbexec both do exactly this).
//
// Cleanup is verified, not fire-and-forget: the service is stopped, deleted,
// and confirmed gone (and the output file plus any leftover batch deleted)
// before ExecService returns, or warnings name what was left.
func (s *Session) ExecService(cmd string) (output string, warnings []string, err error) {
	// Unique service and file names.
	tag := randHex(4) // 8 hex chars
	svcName := "anv-" + tag
	tmpFile := "anv-" + tag + ".tmp"
	batFile := "anv-" + tag + ".bat"
	outPath := "Temp/" + tmpFile // relative to ADMIN$ (C:\Windows)
	batPath := "Temp/" + batFile

	pipe, err := s.client.OpenPipe("svcctl")
	if err != nil {
		if smb.IsNotFound(err) {
			// Samba has no SVCCTL server pipe; only Windows does.
			return "", nil, fmt.Errorf("service control RPC not available on this server (no svcctl pipe)")
		}
		return "", nil, fmt.Errorf("open svcctl pipe: %v", err)
	}
	defer pipe.Close()
	ui.Debugf("psexec[%s]: svcctl pipe open", svcName)

	// Plain bind + plain calls: SCMR over an authenticated SMB pipe needs no
	// RPC-level auth, and CallAuthAuto faults with RPC_S_CANNOT_SUPPORT
	// (same finding as services.go's EnumServices).
	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return "", nil, fmt.Errorf("bind svcctl: %v", err)
	}

	// gopacket's ServiceController is used directly here — unlike its
	// EnumServicesStatus (reimplemented in services.go), its
	// create/start/stop/delete calls are exercised against real Windows by
	// gopacket's own tools/psexec and tools/smbexec. It opens the SCM
	// handle, which is where a non-admin session is first refused.
	sc, err := svcctl.NewServiceController(rpc)
	if err != nil {
		return "", nil, fmt.Errorf("open service control manager failed%s: %v", scmHint(err), err)
	}
	defer sc.Close()

	// Switch to execShare for output retrieval; restore the caller's share
	// afterwards (same convention as exec.go: with no previously selected
	// share the session stays on ADMIN$).
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

	binPath := svcBatchLine(cmd, tmpFile, batFile)
	ui.Debugf("psexec[%s]: binary path: %s", svcName, binPath)

	svcHandle, err := sc.CreateService(svcName, svcName, binPath,
		svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
	if err != nil {
		return "", nil, fmt.Errorf("create service failed%s: %v", scmHint(err), err)
	}
	ui.Debugf("psexec[%s]: service created", svcName)

	// Clean up on ALL paths: stop+delete the service (verified — the SCM
	// must refuse to reopen it afterwards) and delete the output file plus
	// any leftover batch (the batch normally deletes itself as its last
	// line; the sweep covers a service that died mid-run).
	defer func() {
		if w := s.deleteServiceVerified(sc, svcName); w != "" {
			warnings = append(warnings, w)
		}
		if w := s.cleanupExecOutput(outPath); w != "" {
			warnings = append(warnings, w)
		}
		if w := s.cleanupExecOutput(batPath); w != "" {
			warnings = append(warnings, w)
		}
	}()

	// StartService's error is almost always expected and never fatal: the
	// "service binary" is cmd.exe, which runs the batch and exits without
	// ever calling StartServiceCtrlDispatcher, so the SCM reports the start
	// as failed (0x0000041d ERROR_SERVICE_REQUEST_TIMEOUT on Server 2022).
	// Both gopacket reference tools ignore it for the same reason. The
	// output file is the ground truth for whether the command ran.
	startErr := sc.StartService(svcHandle)
	ui.Debugf("psexec[%s]: start returned: %v (usually expected — cmd.exe is not a service binary)", svcName, startErr)

	// Close the create-handle now: cleanup reopens the service by name, and
	// a service marked for deletion only disappears from the SCM once its
	// last handle closes.
	_ = sc.CloseServiceHandle(svcHandle)

	// SERVICE_STOPPED is the reliable "the remote process exited" signal —
	// the output file is then complete and closed. Reading earlier races the
	// redirect (the file exists from the moment cmd.exe opens it).
	if err := waitServiceStopped(sc, svcName, execTimeout); err != nil {
		return "", nil, err
	}

	content, waitErr := s.waitExecOutput(outPath)
	if waitErr != nil {
		return "", nil, waitErr
	}
	return content, nil, nil
}

// svcBatchLine builds the service binary path: an outer cmd.exe that echoes
// the one-line batch `( <cmd> ) > %windir%\Temp\<tmpFile> 2>&1` into
// %windir%\Temp\<batFile>, runs the batch, and deletes it. The parens make
// the redirect capture the whole command — `( a & b ) > file` redirects both
// segments, where `a & b > file` would redirect only the last one. The
// echoed redirect is ^-escaped so the outer cmd writes it literally into the
// batch instead of honoring it. Same shape as tools/smbexec's command line,
// with %windir%\Temp in place of %TEMP% (the service runs as LocalSystem,
// whose TEMP is C:\Windows\Temp anyway — one location for both files).
func svcBatchLine(cmd, tmpFile, batFile string) string {
	return fmt.Sprintf(`cmd.exe /Q /C echo ( %s ) ^> %%windir%%\Temp\%s 2^>^&1 > %%windir%%\Temp\%s & cmd.exe /Q /C %%windir%%\Temp\%s & del %%windir%%\Temp\%s`,
		escapeForEcho(cmd), tmpFile, batFile, batFile, batFile)
}

// escapeForEcho ^-escapes cmd.exe metacharacters so the outer echo writes
// the command literally into the batch file; the batch then holds the
// original command verbatim (the escapes are consumed by the echo, not
// preserved). Mirrors tools/smbexec's escapeForEcho. '%' is deliberately not
// escaped: env vars in the command expand service-side, which callers expect
// (Impacket behaves the same).
func escapeForEcho(s string) string {
	// Order matters: ^ first, or the escapes added below get re-escaped.
	s = strings.ReplaceAll(s, "^", "^^")
	s = strings.ReplaceAll(s, "&", "^&")
	s = strings.ReplaceAll(s, "|", "^|")
	s = strings.ReplaceAll(s, "<", "^<")
	s = strings.ReplaceAll(s, ">", "^>")
	s = strings.ReplaceAll(s, "(", "^(")
	s = strings.ReplaceAll(s, ")", "^)")
	return s
}

// waitServiceStopped polls the service state until the SCM reports
// SERVICE_STOPPED — for anvil's one-shot cmd.exe services that means the
// process exited, so the output file is complete and closed. The poll is
// bounded; a still-running command past the timeout is a timeout error (the
// deferred cleanup then stops and deletes the service).
func waitServiceStopped(sc *svcctl.ServiceController, svcName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		state, err := serviceState(sc, svcName)
		if err == nil && state == svcctl.SERVICE_STOPPED {
			ui.Debugf("psexec[%s]: service stopped", svcName)
			return nil
		}
		ui.Debugf("psexec[%s]: state=%s err=%v", svcName, svcctl.GetServiceState(state), err)
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for the service to stop (%s)", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// serviceState opens the service with query rights and returns its current
// SCM state (svcctl.SERVICE_*).
func serviceState(sc *svcctl.ServiceController, svcName string) (uint32, error) {
	h, err := sc.OpenService(svcName, svcctl.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer sc.CloseServiceHandle(h)
	st, err := sc.QueryServiceStatus(h)
	if err != nil {
		return 0, err
	}
	return st.CurrentState, nil
}

// deleteServiceVerified stops and deletes the service and confirms the
// deletion actually happened. Ground truth is the SCM refusing a fresh
// OpenService afterwards (serviceGone) — DeleteService's return value alone
// only means the service was *marked* for deletion. Returns a warning
// describing the leftover when the bound expires.
func (s *Session) deleteServiceVerified(sc *svcctl.ServiceController, svcName string) string {
	deadline := time.Now().Add(svcDeleteTimeout)
	var lastNote string
	for {
		gone, note := stopDeleteServiceOnce(sc, svcName)
		if gone {
			ui.Debugf("delete service %s: confirmed gone", svcName)
			return ""
		}
		ui.Debugf("delete service %s: %s", svcName, note)
		lastNote = note
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Sprintf("left service %s on target (%s) — sc.exe delete %s",
		svcName, lastNote, svcName)
}

// stopDeleteServiceOnce performs one open/stop/delete round and reports
// whether the service is gone afterwards. Each round works on freshly opened
// handles because a service marked for deletion lingers in the SCM until its
// last handle closes — deleting through a long-lived handle would keep the
// name openable forever and the deletion would never verify.
func stopDeleteServiceOnce(sc *svcctl.ServiceController, svcName string) (bool, string) {
	h, err := sc.OpenService(svcName, svcManageAccess)
	if err != nil {
		if isServiceGoneErr(err) {
			return true, ""
		}
		return false, fmt.Sprintf("still present (open: %v)", err)
	}
	defer sc.CloseServiceHandle(h)

	// The service is normally already stopped — cmd.exe ran the command and
	// exited, which the SCM records as a failed one-shot service. Stop covers
	// the long-running case (output wait timed out mid-command); its
	// ERROR_SERVICE_NOT_ACTIVE error for the common case is expected.
	_, _ = sc.StopService(h)

	if err := sc.DeleteService(h); err != nil {
		return false, fmt.Sprintf("still present (delete: %v)", err)
	}

	// Verify on a fresh handle: the deletion is real only once the SCM
	// refuses to reopen the name.
	gone, note := serviceGone(sc, svcName)
	return gone, note
}

// serviceGone reports whether the service no longer exists, using the
// OpenService error as the only reliable signal.
func serviceGone(sc *svcctl.ServiceController, svcName string) (bool, string) {
	h, err := sc.OpenService(svcName, svcctl.SERVICE_QUERY_STATUS)
	if err != nil {
		if isServiceGoneErr(err) {
			return true, ""
		}
		return false, fmt.Sprintf("still present (%v)", err)
	}
	_ = sc.CloseServiceHandle(h)
	return false, "still present"
}

// isServiceGoneErr reports whether an OpenService failure means the service
// is gone: 0x00000424 (ERROR_SERVICE_DOES_NOT_EXIST, fully removed) or
// 0x00000430 (ERROR_SERVICE_MARKED_FOR_DELETE — deletion is committed and
// completes when the last handle drains; the name can no longer be started
// or opened, which for anvil's purposes is gone). Win32 codes surface as
// bare hex in gopacket svcctl's "OpenService(...) failed: 0x%08x" rendering.
func isServiceGoneErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "0x00000424") || strings.Contains(msg, "0x00000430")
}

// scmHint names the common SVCCTL failure causes for the error message,
// mirroring exec.go's registerHint. Only ERROR_ACCESS_DENIED (0x00000005)
// justifies "admin required" — other failures are not privilege problems.
func scmHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x00000005"):
		return " (admin required)"
	case strings.Contains(msg, "0x00000431"):
		// ERROR_SERVICE_EXISTS — negligible with random anv-<hex> names,
		// but name it rather than leaking the raw code.
		return " (service name already in use — retry)"
	default:
		return ""
	}
}
