package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/tsch"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"

	"anvil/internal/ui"
)

// TaskInfo is one scheduled task from the Task Scheduler service.
type TaskInfo struct {
	Path    string // full task path, e.g. \Microsoft\Windows\UpdateOrchestrator\Reboot
	Name    string // leaf task name (last path element)
	State   string // "ready", "running", "disabled", or "unknown" (see taskState)
	Enabled bool   // registration XML <Settings><Enabled> value
}

// MS-TSCH constants pkg/dcerpc/tsch does not export.
const (
	// taskEnumHidden is SchRpcEnumTasks' TASK_ENUM_HIDDEN flag. On Server
	// 2022 flags 0 and 1 returned identical lists (observed), but the
	// documented intent is to include hidden tasks, so 1 is passed.
	taskEnumHidden = 1
	// enumPageSize is the per-call name cap — the [range(0, 0x10000)]
	// maximum for pcNames. One page always suffices in practice; the
	// pagination loop exists for correctness on pathological servers.
	enumPageSize = 0x10000
	// maxTaskFolders bounds the recursive walk so a misbehaving server
	// (folder cycles via aliased names) cannot loop EnumTasks forever.
	maxTaskFolders = 2048
)

// EnumTasks walks the entire Task Scheduler tree via SchRpcEnumFolders /
// SchRpcEnumTasks over the session's atsvc pipe (IPC$ on the existing SMB
// connection — no new channel, hence no announcement). State and Enabled
// are per-task lookups: SchRpcGetTaskInfo on Server 2022 returns only the
// 24-byte last-run-info form (no pEnabled/pState — probed on the wire), so
// Enabled is parsed from the registration XML (SchRpcRetrieveTask) and
// "running" comes from SchRpcEnumInstances; everything else is "ready"
// ("disabled" when the XML disables the task). Requires admin on the target.
//
// Root-folder quirk: SchRpcEnumFolders("\\") returns ZERO subfolders on
// Server 2022 (probed flags 0 and 1, path variants "" and "\") even though
// \Microsoft exists — the Microsoft folder is hidden and SchRpcEnumFolders
// has no show-hidden flag (MS-TSCH: flags MUST be 0). Non-hidden folders at
// the root DO show up. The walk therefore always probes \Microsoft as a
// seed alongside whatever the root returns; a missing seed (non-Windows)
// is skipped on 0x80070002.
//
// Cache-staleness caveat (probed against the Server 2022 lab DC):
// SchRpcEnumFolders/SchRpcEnumTasks serve a server-side cached view per
// folder that can lag the on-disk store (%windir%\System32\Tasks). Tasks
// created out-of-band (schtasks.exe, COM, MMC) were INVISIBLE to
// SchRpcEnumTasks until RPC write activity (an SchRpcRegisterTask) occurred
// in that folder, and tasks registered via SchRpcRegisterTask itself were
// NEVER listed. Flags 0 vs 1 (TASK_ENUM_HIDDEN) showed no difference.
// EnumTasks is a recon view of what the scheduler's RPC cache reports, not
// a guaranteed-complete file listing — results can miss recently created
// tasks. GetTask/RunTask/DeleteTask are unaffected: they operate on the
// task directly, however it was created.
func (s *Session) EnumTasks() ([]TaskInfo, error) {
	_, rpc, pipe, err := s.bindTSCH()
	if err != nil {
		return nil, err
	}
	defer pipe.Close()

	var out []TaskInfo
	seenFolder := map[string]bool{}
	queue := []string{`\`, `\Microsoft`} // root + hidden-folder seed (see doc comment)

	for len(queue) > 0 {
		if len(seenFolder) > maxTaskFolders {
			return out, fmt.Errorf("task folder walk exceeded %d folders — server response looks pathological", maxTaskFolders)
		}
		folder := queue[0]
		queue = queue[1:]
		key := strings.ToLower(folder)
		if seenFolder[key] {
			continue
		}
		seenFolder[key] = true

		subfolders, err := enumTSCHNames(rpc, tsch.OpSchRpcEnumFolders, folder, 0)
		if err != nil {
			if folder == `\Microsoft` && isTaskNotFound(err) {
				continue // seed folder does not exist on this server
			}
			return out, mapTaskError(err)
		}
		for _, sub := range subfolders {
			if strings.ContainsAny(sub, `/\`) {
				continue // folder names are single-level; defensive
			}
			queue = append(queue, joinTaskPath(folder, sub))
		}

		names, err := enumTSCHNames(rpc, tsch.OpSchRpcEnumTasks, folder, taskEnumHidden)
		if err != nil {
			return out, mapTaskError(err)
		}
		for _, name := range names {
			if name == "" || strings.ContainsAny(name, `/\`) {
				continue // task names are single-level; defensive
			}
			full := joinTaskPath(folder, name)
			info := TaskInfo{Path: full, Name: name, State: "unknown"}

			// Enabled from the registration XML; running from the instance
			// list. Per-task failures degrade that one task to "unknown"
			// instead of failing the whole walk (ACL'd tasks exist).
			xml, xerr := retrieveTaskXML(rpc, full)
			if xerr != nil {
				ui.Debugf("tasks: retrieve %s: %v", full, xerr)
			} else {
				info.Enabled = parseTaskEnabled(xml)
				running, rerr := enumRunningInstances(rpc, full)
				if rerr != nil {
					ui.Debugf("tasks: instances %s: %v", full, rerr)
				} else {
					info.State = taskState(info.Enabled, running)
				}
			}
			out = append(out, info)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path)
	})
	return out, nil
}

// GetTask returns the task's registration XML exactly as the server sends
// it (UTF-16 schema document decoded to a Go string). Requires admin.
func (s *Session) GetTask(path string) (string, error) {
	p := normalizeTaskPath(path)
	_, rpc, pipe, err := s.bindTSCH()
	if err != nil {
		return "", err
	}
	defer pipe.Close()

	xml, err := retrieveTaskXML(rpc, p)
	if err != nil {
		return "", mapTaskError(err)
	}
	return xml, nil
}

// RunTask triggers immediate execution of a registered task
// (SchRpcRun — the same op exec.go uses for its own tasks). Requires admin.
func (s *Session) RunTask(path string) error {
	p := normalizeTaskPath(path)
	ts, _, pipe, err := s.bindTSCH()
	if err != nil {
		return err
	}
	defer pipe.Close()

	if err := ts.Run(p); err != nil {
		return mapTaskError(err)
	}
	return nil
}

// DeleteTask removes a registered task and confirms the deletion on BOTH
// views of the task store:
//
//   - RPC view: SchRpcDelete's response HRESULT is unreliable (0x8004130b
//     in the trailing bytes whether the delete worked or not — exec.go's
//     finding), so deletion is verified by existence check (taskGone),
//     with a stop between attempts — a running task survives delete until
//     stopped.
//   - File store: every task has a backing file at
//     %windir%\System32\Tasks\<path>. On a server whose scheduler cache is
//     desynced (observed on the Server 2022 lab DC after out-of-band task
//     churn), SchRpcDelete drops the task from the RPC view but LEAVES THE
//     FILE — schtasks.exe still lists the task and it would re-register on
//     service restart. DeleteTask therefore removes the backing file over
//     the same SMB session (via ADMIN$, like exec.go's output retrieval)
//     and verifies it is gone. The file step also reaps "zombie" tasks
//     whose RPC entry is already gone but whose file survived an earlier
//     delete.
//
// Requires admin on the target (tsch ops and ADMIN$ both need it).
func (s *Session) DeleteTask(path string) error {
	p := normalizeTaskPath(path)
	if p == `\` {
		return fmt.Errorf("cannot delete the root task folder")
	}
	ts, rpc, pipe, err := s.bindTSCH()
	if err != nil {
		return err
	}
	defer pipe.Close()

	// Switch to ADMIN$ for backing-file access; restore the caller's share
	// afterwards (exec.go's convention: with no previously selected share
	// the session stays on ADMIN$).
	prevShare := s.Share()
	if prevShare != execShare {
		if err := s.UseShare(execShare); err != nil {
			return fmt.Errorf("cannot access %s for task-file verification: %v", execShare, err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	goneRPC, _ := taskGone(ts, p)
	storeRel, storeIsDir, storeErr := s.statTaskStoreFile(p)
	if storeErr != nil {
		return fmt.Errorf("checking task backing file: %v", storeErr)
	}
	if goneRPC && storeRel == "" {
		return fmt.Errorf("task not found: %s", p)
	}
	if storeIsDir {
		return fmt.Errorf("%s is a task folder, not a task", p)
	}

	if !goneRPC {
		// Same delete/stop/verify cadence as exec.go's deleteTaskVerified,
		// but as an error return: the user asked for this deletion.
		deadline := time.Now().Add(taskDeleteTimeout)
		for {
			_ = deleteTaskRPC(rpc, p)
			if gone, note := taskGone(ts, p); gone {
				ui.Debugf("tasks: delete %s confirmed gone (RPC view)", p)
				break
			} else {
				ui.Debugf("tasks: delete %s: %s", p, note)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("delete of %s could not be confirmed — task may still exist on the target", p)
			}
			_ = stopTaskRPC(rpc, p)
			time.Sleep(1 * time.Second)
		}
	}

	// Backing-file removal, verified (see doc comment for why the RPC
	// delete alone is not enough).
	if storeRel != "" {
		if err := s.removeTaskStoreFile(storeRel); err != nil {
			return err
		}
	}
	return nil
}

// statTaskStoreFile reports the backing file's share-relative path when it
// exists in the file store ("" when absent), and whether it is a directory
// (a task FOLDER with that name). ADMIN$ must be the selected share.
func (s *Session) statTaskStoreFile(p string) (rel string, isDir bool, err error) {
	rel = taskStorePath(p)
	fi, err := s.Stat(rel)
	if err != nil {
		if smb.IsNotFound(err) || errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return rel, fi.IsDir(), nil
}

// removeTaskStoreFile deletes the backing file and verifies the deletion,
// retrying while a still-running task may hold it. ADMIN$ must be the
// selected share.
func (s *Session) removeTaskStoreFile(rel string) error {
	winRel := strings.ReplaceAll(rel, "/", `\`)
	var lastErr error
	for i := 0; i < 5; i++ {
		err := s.Rm(rel)
		if err == nil || smb.IsNotFound(err) {
			break
		}
		lastErr = err
		if !smb.IsSharingViolation(err) {
			return fmt.Errorf("left task file %%windir%%\\%s on target (delete failed: %v)", winRel, err)
		}
		time.Sleep(1 * time.Second)
	}
	if _, err := s.Stat(rel); err == nil {
		if lastErr != nil {
			return fmt.Errorf("left task file %%windir%%\\%s on target (delete failed: %v)", winRel, lastErr)
		}
		return fmt.Errorf("left task file %%windir%%\\%s on target (delete not confirmed)", winRel)
	} else if !smb.IsNotFound(err) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("verifying task file deletion: %v", err)
	}
	ui.Debugf("tasks: backing file %s confirmed gone", rel)
	return nil
}

// taskStorePath maps a task path to its backing-file path relative to
// ADMIN$ (C:\Windows): the on-disk task store is %windir%\System32\Tasks.
func taskStorePath(p string) string {
	return "System32/Tasks" + strings.ReplaceAll(normalizeTaskPath(p), `\`, "/")
}

// bindTSCH opens the atsvc pipe and binds ITaskSchedulerService with the
// session's credentials. Mirrors exec.go's inline bind (kept separate so
// exec.go stays untouched). The pipe rides IPC$ on the existing SMB
// connection — no transient channel, no announcement.
func (s *Session) bindTSCH() (*tsch.TaskScheduler, *dcerpc.Client, *smb2.File, error) {
	pipe, err := s.client.OpenPipe("atsvc")
	if err != nil {
		if smb.IsNotFound(err) {
			// Samba has no ITaskSchedulerService; only Windows does.
			return nil, nil, nil, fmt.Errorf("task scheduler RPC not available on this server (no atsvc pipe)")
		}
		return nil, nil, nil, fmt.Errorf("open atsvc pipe: %v", err)
	}

	rpc := dcerpc.NewClient(pipe)
	if s.creds.UseKerberos {
		err = rpc.BindAuthKerberos(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, s.creds, s.host)
	} else {
		err = rpc.BindAuth(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, s.creds)
	}
	if err != nil {
		pipe.Close()
		return nil, nil, nil, fmt.Errorf("bind tsch: %v", err)
	}
	return tsch.NewTaskScheduler(rpc), rpc, pipe, nil
}

// enumTSCHNames pages through SchRpcEnumFolders/SchRpcEnumTasks (identical
// request/response shapes, opnums 6/7). The path parameter is an EMBEDDED
// conformant varying string — the MS-TSCH IDL annotates it [unique], but
// Server 2022's stub faults with RPC_X_BAD_STUB_DATA (0x6f7) on the
// referent form (probed on the wire; impacket marshals it embedded too).
//
// Response: [startIndex(4)] [pcNames(4)] [pNames referent(4)]
// [array maxCount(4)] [pcNames string referents(4 each)]
// [deferred strings: maxCount/offset/actualCount + UTF-16LE + pad]
// [HRESULT(4)]. pcNames==0 carries a NULL pNames referent.
func enumTSCHNames(rpc *dcerpc.Client, op uint16, folder string, flags uint32) ([]string, error) {
	var all []string
	start := uint32(1) // index range is 1-based per MS-TSCH
	for {
		buf := new(bytes.Buffer)
		writeWideStringNDR(buf, folder)
		binary.Write(buf, binary.LittleEndian, flags)
		binary.Write(buf, binary.LittleEndian, start)
		binary.Write(buf, binary.LittleEndian, uint32(enumPageSize))

		resp, err := rpc.CallAuthAuto(op, buf.Bytes())
		if err != nil {
			return all, err
		}
		next, names, err := parseEnumNamesResponse(resp)
		if err != nil {
			ui.Debugf("tasks: enum op=%d folder=%s start=%d failed: %v", op, folder, start, err)
			return all, err
		}
		ui.Debugf("tasks: enum op=%d folder=%s start=%d → %d names (next %d)", op, folder, start, len(names), next)
		all = append(all, names...)
		if uint32(len(names)) < enumPageSize {
			return all, nil // short page: enumeration complete
		}
		if next <= start {
			return all, fmt.Errorf("enum page did not advance (start %d -> %d)", start, next)
		}
		start = next
	}
}

// parseEnumNamesResponse parses one SchRpcEnumFolders/EnumTasks response
// page. next is the server-updated start index (index after the last
// returned name). The HRESULT sits in the final 4 bytes; note the server
// returns S_FALSE (0x00000001) for a successful-but-empty enumeration on
// some folders (e.g. EnumTasks on \Microsoft) yet S_OK with pcNames=0 on
// others (root) — so FAILED() semantics, never hr != 0.
func parseEnumNamesResponse(resp []byte) (next uint32, names []string, err error) {
	if len(resp) < 16 {
		return 0, nil, fmt.Errorf("enum response too short (%d bytes)", len(resp))
	}
	if hr := binary.LittleEndian.Uint32(resp[len(resp)-4:]); hr&0x80000000 != 0 {
		return 0, nil, fmt.Errorf("enum returned error 0x%08x", hr)
	}
	next = binary.LittleEndian.Uint32(resp[0:4])
	count := binary.LittleEndian.Uint32(resp[4:8])
	if count == 0 {
		return next, nil, nil
	}
	if binary.LittleEndian.Uint32(resp[8:12]) == 0 {
		return 0, nil, fmt.Errorf("enum response: %d names but NULL array pointer", count)
	}
	arrayMax := binary.LittleEndian.Uint32(resp[12:16])
	if arrayMax < count {
		return 0, nil, fmt.Errorf("enum response: array maxCount %d < pcNames %d", arrayMax, count)
	}

	// String referents immediately follow the array maxCount.
	off := 16
	if uint64(off)+uint64(count)*4 > uint64(len(resp)) {
		return 0, nil, fmt.Errorf("enum response truncated (referent table)")
	}
	off += int(count) * 4

	names = make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		var s string
		s, off, err = readNDRString(resp, off)
		if err != nil {
			return 0, nil, fmt.Errorf("enum response name %d: %v", i, err)
		}
		names = append(names, s)
	}
	return next, names, nil
}

// retrieveTaskXML fetches the task's registration XML via SchRpcRetrieveTask
// (opnum 2). Request: path and language ("en-US") as embedded conformant
// varying strings, then the in-plcid DWORD — the referent form for path
// faults 0x6f7 on Server 2022 (probed). The response is just the pXml
// unique-pointer string plus the trailing HRESULT — the plcid/pErrorInfo
// out-params the IDL lists are NOT on the wire (probed; a missing task
// returns a NULL pXml referent and HRESULT 0x80070002).
func retrieveTaskXML(rpc *dcerpc.Client, path string) (string, error) {
	buf := new(bytes.Buffer)
	writeWideStringNDR(buf, path)
	writeWideStringNDR(buf, "en-US")
	binary.Write(buf, binary.LittleEndian, uint32(0x409)) // plcid: en-US

	resp, err := rpc.CallAuthAuto(tsch.OpSchRpcRetrieveTask, buf.Bytes())
	if err != nil {
		return "", err
	}
	return parseRetrieveTaskResponse(resp)
}

// parseRetrieveTaskResponse parses the SchRpcRetrieveTask response:
// [pXml referent(4)] [string: maxCount/offset/actualCount + UTF-16LE + pad]
// [HRESULT(4)]. A NULL referent accompanies an error HRESULT (missing task).
func parseRetrieveTaskResponse(resp []byte) (string, error) {
	if len(resp) < 8 {
		return "", fmt.Errorf("retrieve response too short (%d bytes)", len(resp))
	}
	if hr := binary.LittleEndian.Uint32(resp[len(resp)-4:]); hr&0x80000000 != 0 {
		return "", fmt.Errorf("retrieve returned error 0x%08x", hr)
	}
	if binary.LittleEndian.Uint32(resp[0:4]) == 0 {
		return "", fmt.Errorf("retrieve response: NULL xml pointer with success status")
	}
	xml, _, err := readNDRString(resp, 4)
	if err != nil {
		return "", fmt.Errorf("retrieve response: %v", err)
	}
	return xml, nil
}

// enumRunningInstances returns the count of currently running instances of
// the task via SchRpcEnumInstances (opnum 8). This is the ONE tsch op here
// whose path parameter really is a [unique] pointer: the embedded form
// faults 0x6f7 while the referent form succeeds (probed on Server 2022 —
// the inverse of every other op). Response: [pcGuids(4)] [pGuids
// referent(4)] [array maxCount(4)] [pcGuids 16-byte GUIDs] [HRESULT(4)].
func enumRunningInstances(rpc *dcerpc.Client, path string) (int, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // path: unique pointer referent
	writeWideStringNDR(buf, path)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // flags

	resp, err := rpc.CallAuthAuto(tsch.OpSchRpcEnumInstances, buf.Bytes())
	if err != nil {
		return 0, err
	}
	return parseEnumInstancesResponse(resp)
}

// parseEnumInstancesResponse extracts pcGuids from the SchRpcEnumInstances
// response. The GUID values themselves carry no recon value here.
func parseEnumInstancesResponse(resp []byte) (int, error) {
	if len(resp) < 12 {
		return 0, fmt.Errorf("enum-instances response too short (%d bytes)", len(resp))
	}
	if hr := binary.LittleEndian.Uint32(resp[len(resp)-4:]); hr&0x80000000 != 0 {
		return 0, fmt.Errorf("enum-instances returned error 0x%08x", hr)
	}
	count := binary.LittleEndian.Uint32(resp[0:4])
	if count > 0 {
		if binary.LittleEndian.Uint32(resp[4:8]) == 0 {
			return 0, fmt.Errorf("enum-instances response: %d guids but NULL array pointer", count)
		}
		// 8 (header) + 4 (array maxCount) + count GUIDs + HRESULT.
		if uint64(len(resp)) < 12+16*uint64(count) {
			return 0, fmt.Errorf("enum-instances response truncated (%d guids)", count)
		}
	}
	return int(count), nil
}

// readNDRString reads one deferred conformant varying string (maxCount,
// offset, actualCount, UTF-16LE data, 4-byte padding) at off, returning the
// decoded string and the offset of the next element. Everything before off
// is 4-byte aligned in these responses, so padding the 2*actualCount data
// up to a 4-byte multiple lands on the next string header.
func readNDRString(resp []byte, off int) (string, int, error) {
	if off < 0 || off+12 > len(resp) {
		return "", off, fmt.Errorf("string header out of bounds (off %d, len %d)", off, len(resp))
	}
	actual := binary.LittleEndian.Uint32(resp[off+8 : off+12])
	dataStart := off + 12
	dataLen := uint64(actual) * 2
	if uint64(dataStart)+dataLen > uint64(len(resp)) {
		return "", off, fmt.Errorf("string data out of bounds (%d chars at off %d, len %d)", actual, off, len(resp))
	}
	u := make([]uint16, actual)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(resp[dataStart+i*2 : dataStart+i*2+2])
	}
	if len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1] // trailing null is part of the wire count, not the string
	}
	next := dataStart + int(dataLen)
	if rem := next % 4; rem != 0 {
		next += 4 - rem
	}
	return string(utf16.Decode(u)), next, nil
}

// parseTaskEnabled reads the <Settings><Enabled> value from task
// registration XML. The schema's Enabled defaults to true when absent, and
// only the Settings copy is authoritative — <Triggers> carry their own
// per-trigger <Enabled> elements that must not be picked up. A plain string
// scan beats encoding/xml here: the document declares encoding="UTF-16",
// which Go's decoder refuses without a CharsetReader even after we've
// already decoded the text.
func parseTaskEnabled(xml string) bool {
	i := strings.Index(xml, "<Settings>")
	if i < 0 {
		return true // no Settings section: schema default (Enabled=true)
	}
	settings := xml[i:]
	if j := strings.Index(settings, "</Settings>"); j >= 0 {
		settings = settings[:j]
	}
	k := strings.Index(settings, "<Enabled>")
	if k < 0 {
		return true
	}
	v := settings[k+len("<Enabled>"):]
	if j := strings.Index(v, "</Enabled>"); j >= 0 {
		v = v[:j]
	}
	return !strings.EqualFold(strings.TrimSpace(v), "false")
}

// taskState renders a task's runtime state from the only two signals the
// wire provides: the registration XML's Enabled flag and the running-
// instance count from SchRpcEnumInstances (SchRpcGetTaskInfo's documented
// pEnabled/pState are not returned by Server 2022 — probed). "queued"
// (TASK_STATE 0x2) has no RPC-visible signal and is never reported.
func taskState(enabled bool, runningInstances int) string {
	switch {
	case runningInstances > 0:
		return "running"
	case !enabled:
		return "disabled"
	default:
		return "ready"
	}
}

// normalizeTaskPath canonicalizes a user-supplied task path: forward
// slashes become backslashes, duplicate separators collapse, a leading
// backslash is enforced, and trailing ones are stripped (root stays "\").
// The scheduler accepts both forms but error messages and existence checks
// compare paths, so one canonical spelling keeps behavior predictable.
func normalizeTaskPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "/", `\`)
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	p = strings.TrimRight(p, `\`)
	if p == "" {
		return `\`
	}
	if !strings.HasPrefix(p, `\`) {
		p = `\` + p
	}
	return p
}

// joinTaskPath appends a single-level name to a folder path.
func joinTaskPath(folder, name string) string {
	if folder == `\` {
		return `\` + name
	}
	return folder + `\` + name
}

// isTaskNotFound reports whether err carries ERROR_FILE_NOT_FOUND
// (0x80070002) — the scheduler's "no such task/folder" signal (renders as
// "error 0x80070002" from the HRESULT parsers above and inside
// tsch.GetLastRunInfo).
func isTaskNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "0x80070002")
}

// mapTaskError translates scheduler HRESULTs into plain-language messages
// (feature-local themed-errors idiom — shared errors.go stays untouched).
func mapTaskError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x80070002"): // ERROR_FILE_NOT_FOUND
		return fmt.Errorf("task not found")
	case strings.Contains(msg, "0x80070005"), strings.Contains(msg, "0x00000005"): // E_ACCESS_DENIED
		return fmt.Errorf("access denied (admin required)")
	case strings.Contains(msg, "0x8007007b"): // ERROR_INVALID_NAME
		return fmt.Errorf("invalid task path")
	case strings.Contains(msg, "0x80041326"): // SCHED_E_TASK_DISABLED
		return fmt.Errorf("task is disabled")
	case strings.Contains(msg, "0x8004131a"): // SCHED_E_MALFORMEDXML (retrieve on corrupt registration)
		return fmt.Errorf("task definition is malformed on the server")
	}
	return err
}
