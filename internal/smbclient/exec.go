package smbclient

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/tsch"
	"github.com/mandiant/gopacket/pkg/smb"

	"anvil/internal/ui"
)

// execShare is the administrative share used for output retrieval
// (tools/atexec's convention): output lands in %windir%\Temp, read back
// through ADMIN$ (C:\Windows) as Temp\<file>.
const execShare = "ADMIN$"

// execTimeout bounds the wait for the remote command's output file. A
// command still running past this returns a timeout error; the task and
// output file are still cleaned up.
const execTimeout = 15 * time.Second

// Task XML template matching Impacket's/gopacket's atexec format exactly:
// LocalSystem principal, hidden, run-on-demand, 3-day execution limit.
const taskXMLTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>`

// Exec runs a single command on the target via a Task Scheduler job,
// mirroring gopacket's tools/atexec: a uniquely-named task running
// `cmd.exe /C <cmd> > %windir%\Temp\<file> 2>&1` is registered and run
// immediately, the output file is read back and deleted over the same SMB
// session — all over this one connection (the atsvc named pipe rides
// IPC$; no new connections). Requires admin on the target.
//
// Cleanup is verified, not fire-and-forget: the task is deleted (and
// confirmed gone) before Exec returns, or warnings name what was left.
func (s *Session) Exec(cmd string) (output string, warnings []string, err error) {
	// Unique task and output names.
	tag := randHex(4) // 8 hex chars
	taskName := "anv-" + tag
	taskPath := `\` + taskName
	tmpFile := "anv-" + tag + ".tmp"
	outPath := "Temp/" + tmpFile // relative to ADMIN$ (C:\Windows)

	pipe, err := s.client.OpenPipe("atsvc")
	if err != nil {
		if smb.IsNotFound(err) {
			// Samba has no ITaskSchedulerService; only Windows does.
			return "", nil, fmt.Errorf("task scheduler RPC not available on this server (no atsvc pipe)")
		}
		return "", nil, fmt.Errorf("open atsvc pipe: %v", err)
	}
	defer pipe.Close()
	ui.Debugf("exec[%s]: atsvc pipe open", taskName)

	rpc := dcerpc.NewClient(pipe)
	if s.creds.UseKerberos {
		err = rpc.BindAuthKerberos(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, s.creds, s.host)
	} else {
		err = rpc.BindAuth(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, s.creds)
	}
	if err != nil {
		return "", nil, fmt.Errorf("bind tsch: %v", err)
	}
	ts := tsch.NewTaskScheduler(rpc)
	ui.Debugf("exec[%s]: tsch bound", taskName)

	// Switch to execShare for output retrieval; restore the caller's share
	// afterwards. Note: with no previously selected share the session stays
	// on execShare (pkg/smb has no unmount-current).
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

	// cmd.exe /C runs the command with output redirected; only XML escaping
	// is needed (the scheduler invokes cmd.exe directly, no echo layer).
	// The command is wrapped in parens so the redirect captures the whole
	// thing — `cmd /C a & b > file` would otherwise redirect only the last
	// `&`-segment.
	args := fmt.Sprintf("/C ( %s ) > %%windir%%\\Temp\\%s 2>&1", cmd, tmpFile)
	taskXML := fmt.Sprintf(taskXMLTemplate, xmlEscape("cmd.exe"), xmlEscape(args))
	ui.Debugf("exec[%s]: args: %s", taskName, args)
	ui.Debugf("exec[%s]: xml:\n%s", taskName, taskXML)

	if _, err := ts.RegisterTask(taskPath, taskXML, tsch.TASK_CREATE); err != nil {
		ui.Debugf("exec[%s]: register failed: %v", taskName, err)
		return "", nil, fmt.Errorf("register task failed%s: %v", registerHint(err), err)
	}
	ui.Debugf("exec[%s]: registered %s", taskName, taskPath)

	// Clean up on ALL paths: delete the task (verified, with the real
	// HRESULT parsed — see deleteTaskVerified) and delete the output file.
	defer func() {
		if w := s.deleteTaskVerified(ts, rpc, taskPath, taskName); w != "" {
			warnings = append(warnings, w)
		}
		if w := s.cleanupExecOutput(outPath); w != "" {
			warnings = append(warnings, w)
		}
	}()

	if err := ts.Run(taskPath); err != nil {
		ui.Debugf("exec[%s]: run failed: %v", taskName, err)
		return "", nil, fmt.Errorf("run task failed: %v", err)
	}
	ui.Debugf("exec[%s]: run issued", taskName)

	content, waitErr := s.waitExecOutput(outPath)
	if waitErr != nil {
		return "", nil, waitErr
	}
	return content, nil, nil
}

// waitExecOutput polls for the output file. Cat succeeds while the remote
// side is still writing; Rm failing with a sharing violation is the signal
// to keep waiting (tools/atexec's getOutput logic).
func (s *Session) waitExecOutput(outPath string) (string, error) {
	deadline := time.Now().Add(execTimeout)
	for {
		content, err := s.client.Cat(outPath)
		if err == nil {
			if rmErr := s.client.Rm(outPath); rmErr != nil && smb.IsSharingViolation(rmErr) {
				if time.Now().After(deadline) {
					return "", fmt.Errorf("timed out waiting for command output (%s)", execTimeout)
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return content, nil
		}
		if !smb.IsNotFound(err) {
			return "", err
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out waiting for command output (%s)", execTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// taskDeleteTimeout bounds the delete/stop/verify loop after the command
// finishes. Tasks that are (about to be) running survive delete attempts
// until stopped; the loop covers that settle window.
const taskDeleteTimeout = 25 * time.Second

// deleteTaskVerified deletes the task and confirms the deletion actually
// happened. The SchRpcDelete response carries 0x8004130b in its trailing
// bytes whether the deletion worked or not (proven on the wire against
// Server 2022), so the call's result is useless — ground truth is the
// existence check (taskGone) after each attempt. A task that is (about to
// be) running survives delete attempts until stopped, so stop between
// attempts. Returns a warning describing the leftover when the bound expires.
func (s *Session) deleteTaskVerified(ts *tsch.TaskScheduler, rpc *dcerpc.Client, taskPath, taskName string) string {
	deadline := time.Now().Add(taskDeleteTimeout)
	var lastNote string
	for {
		_ = deleteTaskRPC(rpc, taskPath)
		if gone, note := taskGone(ts, taskPath); gone {
			ui.Debugf("delete %s: confirmed gone", taskPath)
			return ""
		} else {
			ui.Debugf("delete %s: %s", taskPath, note)
			lastNote = note
		}
		if time.Now().After(deadline) {
			break
		}
		_ = stopTaskRPC(rpc, taskPath)
		time.Sleep(1 * time.Second)
	}
	return fmt.Sprintf("left scheduled task %s on target (%s) — schtasks /delete /tn %s /f",
		taskName, lastNote, taskName)
}

// taskGone reports whether the task no longer exists, using the file-not-
// found error (0x80070002) as the only reliable signal.
func taskGone(ts *tsch.TaskScheduler, taskPath string) (bool, string) {
	_, _, err := ts.GetLastRunInfo(taskPath)
	if err != nil {
		if strings.Contains(err.Error(), "0x80070002") {
			return true, ""
		}
		return false, fmt.Sprintf("still present (%v)", err)
	}
	return false, "still present"
}

// stopTaskRPC issues SchRpcStop for the task. Same payload shape as delete.
func stopTaskRPC(rpc *dcerpc.Client, path string) error {
	buf := new(bytes.Buffer)
	writeWideStringNDR(buf, path)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // flags

	resp, err := rpc.CallAuthAuto(tsch.OpSchRpcStop, buf.Bytes())
	ui.Debugf("stop %s: err=%v resp=%x", path, err, resp)
	if err != nil {
		return err
	}
	if len(resp) < 4 {
		return fmt.Errorf("SchRpcStop response too short (%d bytes)", len(resp))
	}
	if hr := binary.LittleEndian.Uint32(resp[len(resp)-4:]); hr != 0 {
		return fmt.Errorf("SchRpcStop returned error 0x%08x", hr)
	}
	return nil
}

// deleteTaskRPC issues SchRpcDelete for its effect only. The 32-byte
// response carries 0x8004130b in its trailing bytes whether the deletion
// worked or was refused (proven on the wire against Server 2022), so the
// result is unverifiable — callers must check existence via taskGone.
func deleteTaskRPC(rpc *dcerpc.Client, path string) error {
	buf := new(bytes.Buffer)
	writeWideStringNDR(buf, path)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // flags: force delete

	_, err := rpc.CallAuthAuto(tsch.OpSchRpcDelete, buf.Bytes())
	return err
}

// writeWideStringNDR writes a UTF-16LE conformant varying string in NDR
// format (same encoding tsch uses for its own calls).
func writeWideStringNDR(buf *bytes.Buffer, s string) {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	n := uint32(len(u))
	binary.Write(buf, binary.LittleEndian, n)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, n)
	for _, c := range u {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-(buf.Len()%4)))
	}
}

// cleanupExecOutput deletes the output file, retrying while the remote
// process may still hold it. Returns a warning carrying the real delete
// error when the file cannot be removed.
func (s *Session) cleanupExecOutput(outPath string) string {
	var lastErr error
	for i := 0; i < 5; i++ {
		err := s.client.Rm(outPath)
		if err == nil || smb.IsNotFound(err) {
			return ""
		}
		lastErr = err
		if !smb.IsSharingViolation(err) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Sprintf("left output file %%windir%%\\%s on target (delete failed: %v)",
		strings.ReplaceAll(outPath, "/", "\\"), lastErr)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// registerHint names the common SchRpcRegisterTask failure causes for the
// error message. Only E_ACCESS_DENIED justifies "admin required" — other
// failures are not privilege problems (0x8004131a SCHED_E_MALFORMEDXML
// means the command produced invalid task XML, e.g. raw control bytes).
func registerHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x80070005"), strings.Contains(msg, "0x00000005"):
		return " (admin required)"
	case strings.Contains(msg, "0x8004131a"):
		return " (task XML rejected as malformed — check for special characters in the command)"
	default:
		return ""
	}
}

// xmlEscape escapes special XML characters (matches atexec's xml_escape).
// Raw control bytes cannot be represented in XML 1.0 and are the caller's
// problem (registerHint names the resulting server error).
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return s
}
