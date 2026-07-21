package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"

	"anvil/internal/perf"
	"anvil/internal/ui"
)

// ProcInfo is one process on the target, read from the Process performance
// object family. Name is the image name as perflib reports it — no ".exe"
// extension ("lsass", not "lsass.exe"), and duplicate image names are NOT
// disambiguated (Server 2022 reports two plain "svchost" rows, no "#n"
// suffixes); PID is the unique key.
type ProcInfo struct {
	PID     uint32
	PPID    uint32
	Name    string
	Handles uint32
	Threads uint32
}

// MS-RRP opnums for the predefined performance hives. pkg/dcerpc/winreg
// exports these constants but ships no stubs for them.
const (
	opOpenPerformanceData    = 3  // HKEY_PERFORMANCE_DATA    (0x80000004)
	opOpenPerformanceText    = 32 // HKEY_PERFORMANCE_TEXT    (0x80000050)
	opOpenPerformanceNlsText = 33 // HKEY_PERFORMANCE_NLSTEXT (0x80000060)
)

// regPerfBufSize is the initial [out]-buffer capacity for perf queries; the
// ERROR_MORE_DATA retry grows it to the server-reported size, capped at
// regPerfMaxValue. The Process blob is ~30 KB on a Server 2022 DC, the
// title database ~320 KB, so one round trip is the norm.
const (
	regPerfBufSize  = 1 << 20
	regPerfMaxValue = 16 << 20
)

// procIndexes is the resolved counter title-index set for the Process
// object family.
type procIndexes struct {
	object  uint32 // "Process" (the object family itself)
	pid     uint32 // "ID Process"
	ppid    uint32 // "Creating Process ID"
	handles uint32 // "Handle Count"
	threads uint32 // "Thread Count"
}

// builtinProcIndexes is the fallback index set used when the target's
// counter title database cannot be read. These indexes are registration
// constants of the kernel's PerfOS provider, invariant across every Windows
// version and locale since NT (Process=230, ID Process=784, Creating
// Process ID=1410, Handle Count=952, Thread Count=680 — the values
// Sysinternals PsList hardcodes); the captured Server 2022 title database
// (internal/perf/testdata/perf-titles-009.bin) confirms them.
var builtinProcIndexes = procIndexes{object: 230, pid: 784, ppid: 1410, handles: 952, threads: 680}

// ListProcesses enumerates running processes WITHOUT WMI. The winreg pipe
// on the existing SMB session serves the predefined performance hives — the
// same channel Sysinternals PsList uses — so no new connection is opened:
// one pipe, two reads (the "Counter 009" title database for index→name
// resolution, then the Process object family's perf blob), parsed locally
// by internal/perf. Read-only; creates nothing on the target. Requires only
// an authenticated session (perf data is world-readable), though the
// RemoteRegistry service must start — winreg's demand-start race is handled
// by openWinreg.
func (s *Session) ListProcesses() ([]ProcInfo, error) {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return nil, mapProcError(err)
	}
	defer cleanup()

	titles := loadCounterTitles(rpc) // nil when unreadable — builtin indexes take over
	idx := resolveProcIndexes(titles)

	hPerf, err := openPredefPerf(rpc, opOpenPerformanceData)
	if err != nil {
		return nil, mapProcError(fmt.Errorf("open HKEY_PERFORMANCE_DATA: %v", err))
	}
	defer winreg.BaseRegCloseKey(rpc, hPerf)

	// Under HKEY_PERFORMANCE_DATA the value name IS the object index as
	// decimal text — "230" returns just the Process family's blob.
	_, blob, err := regQueryValueBlob(rpc, hPerf, strconv.FormatUint(uint64(idx.object), 10), regPerfBufSize)
	if err != nil {
		return nil, mapProcError(fmt.Errorf("query process counters: %v", err))
	}

	objects, err := perf.ParseDataBlock(blob)
	if err != nil {
		return nil, mapProcError(err)
	}
	for _, obj := range objects {
		if obj.NameTitleIndex == idx.object {
			return procsFromObject(obj, idx), nil
		}
	}
	return nil, fmt.Errorf("process object family (index %d) not in the performance data", idx.object)
}

// loadCounterTitles reads the "Counter 009" title database (a REG_MULTI_SZ
// of index/name pairs) for counter index→name resolution. NLSTEXT
// (system-locale titles) is tried first, then TEXT (US English): on a
// localized server NLSTEXT resolves none of the English names
// resolveProcIndexes looks up, but TEXT still carries them. Returns nil
// when neither hive yields a usable database.
func loadCounterTitles(rpc *dcerpc.Client) map[string][]uint32 {
	for _, opnum := range []uint16{opOpenPerformanceNlsText, opOpenPerformanceText} {
		h, err := openPredefPerf(rpc, opnum)
		if err != nil {
			continue
		}
		_, data, err := regQueryValueBlob(rpc, h, "Counter 009", regPerfBufSize)
		winreg.BaseRegCloseKey(rpc, h)
		if err != nil || len(data) == 0 {
			continue
		}
		if titles := perf.ParseTitles(data); len(titles) > 0 {
			return titles
		}
	}
	ui.Debugf("procs: counter title database unreadable — using built-in indexes")
	return nil
}

// resolveProcIndexes picks counter title indexes from the title database,
// falling back to builtinProcIndexes as a whole set when the database is
// missing or any required name is absent (mixing sources could pair
// indexes from different families). Duplicate names resolve to their FIRST
// — lowest — index: the kernel's PerfOS family registered first on every
// Windows version. The Server 2022 database confirms it: "Thread Count" →
// 680 (Process) before 5430 (Job Object), and 680 is the one present in the
// Process object's counter definitions.
func resolveProcIndexes(titles map[string][]uint32) procIndexes {
	if titles == nil {
		return builtinProcIndexes
	}
	idx := procIndexes{}
	for _, n := range []struct {
		name string
		dst  *uint32
	}{
		{"Process", &idx.object},
		{"ID Process", &idx.pid},
		{"Creating Process ID", &idx.ppid},
		{"Handle Count", &idx.handles},
		{"Thread Count", &idx.threads},
	} {
		candidates := titles[n.name]
		if len(candidates) == 0 {
			ui.Debugf("procs: title %q not in database — using built-in indexes", n.name)
			return builtinProcIndexes
		}
		*n.dst = candidates[0]
	}
	return idx
}

// procsFromObject flattens a parsed Process object into ProcInfo rows
// sorted by PID. The synthetic "_Total" instance (perflib's aggregate row)
// is dropped; "Idle" (PID 0) stays — it is a real accounting row. A counter
// missing from an instance's values (perflib snapshots can be racy for a
// process exiting mid-collection) reads as zero.
func procsFromObject(obj *perf.Object, idx procIndexes) []ProcInfo {
	procs := make([]ProcInfo, 0, len(obj.Instances))
	for _, inst := range obj.Instances {
		if inst.Name == "_Total" {
			continue
		}
		procs = append(procs, ProcInfo{
			PID:     uint32(inst.Values[idx.pid]),
			PPID:    uint32(inst.Values[idx.ppid]),
			Name:    inst.Name,
			Handles: uint32(inst.Values[idx.handles]),
			Threads: uint32(inst.Values[idx.threads]),
		})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs
}

// openPredefPerf opens one of the predefined performance hives via its
// MS-RRP Open call and returns the 20-byte RPC handle. Same stub shape as
// winreg.OpenLocalMachine (ServerName NULL + REGSAM); gopacket ships no
// wrappers for these opnums.
func openPredefPerf(rpc *dcerpc.Client, opnum uint16) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // ServerName NULL pointer
	binary.Write(buf, binary.LittleEndian, uint32(winreg.MAXIMUM_ALLOWED))

	resp, err := rpc.Call(opnum, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("short open response (%d bytes)", len(resp))
	}
	if status := binary.LittleEndian.Uint32(resp[20:24]); status != winreg.ERROR_SUCCESS {
		return nil, fmt.Errorf("0x%08x", status)
	}
	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// regQueryValueBlob reads a potentially large registry value. It re-
// implements BaseRegQueryValue rather than calling
// winreg.BaseRegQueryValueWithSize, which transmits a zero-filled
// placeholder the size of the [out] buffer: a 256 KB placeholder makes
// dcerpc.Call truncate the PDU FragLength to uint16, and the server answers
// by dropping the pipe ("the specified named pipe is in the disconnected
// state" — verified against Server 2022). Here the conformant-varying
// [in,out] lpData array goes out with ActualCount=0 — no in-elements are
// transmitted; the buffer capacity rides only in MaxCount/lpcbData — so the
// request stays tiny no matter how large the value. gopacket's own
// BaseRegQueryInfoKey marshals its class-name buffer the same way. Retries
// once with the server-reported size on ERROR_MORE_DATA.
func regQueryValueBlob(rpc *dcerpc.Client, hKey []byte, valueName string, maxSize uint32) (uint32, []byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(hKey)
	writeRRPUnicodeString(buf, valueName)

	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // lpType referent
	binary.Write(buf, binary.LittleEndian, uint32(0))       // in-type
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // lpData referent
	binary.Write(buf, binary.LittleEndian, maxSize)         // MaxCount = capacity
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))       // ActualCount: no in-elements
	binary.Write(buf, binary.LittleEndian, uint32(0x20008)) // lpcbData referent
	binary.Write(buf, binary.LittleEndian, maxSize)         // buffer size
	binary.Write(buf, binary.LittleEndian, uint32(0x2000c)) // lpcbLen referent
	binary.Write(buf, binary.LittleEndian, uint32(0))       // in-length

	resp, err := rpc.Call(winreg.OpBaseRegQueryValue, buf.Bytes())
	if err != nil {
		return 0, nil, err
	}

	// Same response shape as winreg.BaseRegQueryValueWithSize.
	r := bytes.NewReader(resp)
	var typePtr, valueType uint32
	binary.Read(r, binary.LittleEndian, &typePtr)
	if typePtr != 0 {
		binary.Read(r, binary.LittleEndian, &valueType)
	}
	var dataPtr uint32
	binary.Read(r, binary.LittleEndian, &dataPtr)
	var data []byte
	if dataPtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)
		if actualCount > 0 {
			data = make([]byte, actualCount)
			r.Read(data)
		}
	}
	var cbDataPtr, cbData uint32
	binary.Read(r, binary.LittleEndian, &cbDataPtr)
	if cbDataPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbData)
	}
	var cbLenPtr, cbLen uint32
	binary.Read(r, binary.LittleEndian, &cbLenPtr)
	if cbLenPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbLen)
	}
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)

	if status == winreg.ERROR_MORE_DATA && cbData > maxSize && cbData <= regPerfMaxValue {
		return regQueryValueBlob(rpc, hKey, valueName, cbData)
	}
	if status != winreg.ERROR_SUCCESS {
		return 0, nil, fmt.Errorf("BaseRegQueryValue(%s) failed: 0x%08x", valueName, status)
	}
	if cbLen > 0 && int(cbLen) < len(data) {
		data = data[:cbLen]
	}
	return valueType, data, nil
}

// writeRRPUnicodeString marshals an RRP_UNICODE_STRING exactly like
// pkg/dcerpc/winreg's unexported helper: UTF-16LE with the NUL terminator
// counted in Length/MaximumLength and the array counts, 4-byte aligned.
func writeRRPUnicodeString(buf *bytes.Buffer, s string) {
	chars := utf16.Encode([]rune(s))
	chars = append(chars, 0)
	byteLen := len(chars) * 2

	binary.Write(buf, binary.LittleEndian, uint16(byteLen)) // Length
	binary.Write(buf, binary.LittleEndian, uint16(byteLen)) // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Pointer (referent ID)

	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))          // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(chars))) // ActualCount
	for _, c := range chars {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}
}

// mapProcError translates winreg performance-hive failures into plain
// language (themed-errors idiom; feature-local like mapWMIError). The
// status hex is matched on its rendered form, as openPredefPerf and
// regQueryValueBlob return bare "0x........" errors.
func mapProcError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x00000005"): // ERROR_ACCESS_DENIED
		return fmt.Errorf("access denied")
	case strings.Contains(msg, "0x00000002"): // ERROR_FILE_NOT_FOUND
		return fmt.Errorf("server has no such performance data (value not found)")
	case strings.Contains(msg, "0x1c010002"), // nca_s_op_rng_error — Samba winreg lacks the perf hives
		strings.Contains(msg, "0x000006f7"),           // EPT_S_NOT_REGISTERED
		strings.Contains(msg, "data block too small"): // Samba serves an empty blob
		return fmt.Errorf("performance counters not supported on this server")
	case strings.Contains(msg, "listening state"):
		return fmt.Errorf("RemoteRegistry service is not running on the target")
	}
	return err
}
