// Package perf parses Windows performance-counter data as read from the
// registry's performance hives: PERF_DATA_BLOCK blobs served by
// HKEY_PERFORMANCE_DATA and the counter title database (REG_MULTI_SZ) under
// HKEY_PERFORMANCE_NLSTEXT / HKEY_PERFORMANCE_TEXT. Pure: no I/O, no
// network — callers supply the raw bytes.
//
// The wire format is the perflib v1 layout (winperf.h): PERF_DATA_BLOCK →
// PERF_OBJECT_TYPE → PERF_COUNTER_DEFINITION × N → (PERF_INSTANCE_DEFINITION
// + PERF_COUNTER_BLOCK) × M. The registry interface serves the 32-bit
// structure layout on every architecture — verified against a Server 2022
// x64 capture (testdata/perf-process-230.bin): object HeaderLength 64,
// counter-def ByteLength 40, and the ObjectNameTitle/CounterNameTitle
// pointer fields are dead 4-byte slots. Because of that, this parser never
// reads NumCounters/NumInstances (their in-struct offsets shift with
// pointer size); it walks purely by the length fields, which are
// layout-independent. The capture proves both walks terminate exactly: the
// counter-def chain lands on DefinitionLength and the instance chain on
// TotalByteLength.
package perf

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/utf16le"
)

// Counter is one PERF_COUNTER_DEFINITION: where a counter value lives
// inside an instance's PERF_COUNTER_BLOCK and how wide it is.
type Counter struct {
	NameTitleIndex uint32 // index into the counter title database
	Offset         uint32 // byte offset of the value within the counter block
	Size           uint32 // value width in bytes (4 = DWORD, 8 = ULONGLONG)
}

// Instance is one PERF_INSTANCE_DEFINITION plus its counter block, with the
// counter values already extracted and keyed by counter name-title index.
type Instance struct {
	Name   string
	Values map[uint32]uint64
}

// Object is one PERF_OBJECT_TYPE family (e.g. Process): its counter schema
// and per-instance data.
type Object struct {
	NameTitleIndex uint32
	Counters       []Counter
	Instances      []Instance
}

// perfSignature is the PERF_DATA_BLOCK magic: the WCHAR string "PERF".
var perfSignature = []byte{'P', 0, 'E', 0, 'R', 0, 'F', 0}

// PERF_DATA_BLOCK field offsets (pointer-free header — identical on all
// architectures).
const (
	dbLittleEndian = 8
	dbTotalLength  = 20
	dbHeaderLength = 24
	dbFixedSize    = 80 // through SystemNameOffset; SystemName follows
)

// ParseDataBlock walks a PERF_DATA_BLOCK blob (the bytes returned by
// querying a value under HKEY_PERFORMANCE_DATA) and returns its object
// families in blob order. A truncated or internally inconsistent blob is an
// error; objects without instances (PERF_NO_INSTANCES) parse with zero
// instances rather than failing.
func ParseDataBlock(blob []byte) ([]*Object, error) {
	if len(blob) < dbFixedSize {
		return nil, fmt.Errorf("perf: data block too small (%d bytes)", len(blob))
	}
	if string(blob[:8]) != string(perfSignature) {
		return nil, fmt.Errorf("perf: bad data block signature (want \"PERF\")")
	}
	if binary.LittleEndian.Uint32(blob[dbLittleEndian:]) != 1 {
		return nil, fmt.Errorf("perf: big-endian data block not supported")
	}
	total := binary.LittleEndian.Uint32(blob[dbTotalLength:])
	hdrLen := binary.LittleEndian.Uint32(blob[dbHeaderLength:])
	if total > uint32(len(blob)) {
		return nil, fmt.Errorf("perf: truncated data block (TotalByteLength %d, have %d bytes)", total, len(blob))
	}
	if hdrLen < dbFixedSize || hdrLen > total {
		return nil, fmt.Errorf("perf: bad data block header length %d (total %d)", hdrLen, total)
	}

	var objects []*Object
	for off := int(hdrLen); off < int(total); {
		obj, size, err := parseObject(blob[off:int(total)])
		if err != nil {
			return nil, fmt.Errorf("perf: object at blob offset %d: %v", off, err)
		}
		objects = append(objects, obj)
		off += size
	}
	return objects, nil
}

// PERF_OBJECT_TYPE offsets for the fields we read (all before the first
// pointer field, so layout-independent).
const (
	otTotalLength  = 0
	otDefLength    = 4
	otHeaderLength = 8
	otNameIndex    = 12
	otMinFixed     = 16
)

// parseObject parses one PERF_OBJECT_TYPE at the start of data and returns
// its TotalByteLength as the advance to the next object.
func parseObject(data []byte) (*Object, int, error) {
	if len(data) < otMinFixed {
		return nil, 0, fmt.Errorf("object header truncated (%d bytes)", len(data))
	}
	total := binary.LittleEndian.Uint32(data[otTotalLength:])
	defLen := binary.LittleEndian.Uint32(data[otDefLength:])
	hdrLen := binary.LittleEndian.Uint32(data[otHeaderLength:])
	if total < otMinFixed || int(total) > len(data) {
		return nil, 0, fmt.Errorf("object TotalByteLength %d exceeds remaining data (%d)", total, len(data))
	}
	if hdrLen < otMinFixed || hdrLen > defLen || defLen > total {
		return nil, 0, fmt.Errorf("inconsistent object lengths (header %d, definition %d, total %d)", hdrLen, defLen, total)
	}

	obj := &Object{NameTitleIndex: binary.LittleEndian.Uint32(data[otNameIndex:])}

	// Counter definitions: chained by ByteLength from HeaderLength to
	// DefinitionLength. ByteLength carries the whole definition, so the
	// chain must land exactly on DefinitionLength (it does on the Server
	// 2022 capture). Field reads use offsets relative to each definition's
	// END (CounterOffset/CounterSize/CounterType/DetailLevel/DefaultScale
	// are the trailing five DWORDs on every layout), so the pointer-size
	// difference in the middle of the struct never matters.
	defEnd := int(defLen)
	for off := int(hdrLen); off < defEnd; {
		if off+20 > defEnd {
			return nil, 0, fmt.Errorf("counter definition truncated at object offset %d", off)
		}
		bl := int(binary.LittleEndian.Uint32(data[off:]))
		if bl < 20 || off+bl > defEnd {
			return nil, 0, fmt.Errorf("bad counter definition ByteLength %d at object offset %d", bl, off)
		}
		obj.Counters = append(obj.Counters, Counter{
			NameTitleIndex: binary.LittleEndian.Uint32(data[off+4:]),
			Size:           binary.LittleEndian.Uint32(data[off+bl-8:]),
			Offset:         binary.LittleEndian.Uint32(data[off+bl-4:]),
		})
		off += bl
	}

	// Instances: PERF_INSTANCE_DEFINITION + PERF_COUNTER_BLOCK pairs from
	// DefinitionLength to TotalByteLength. The instance definition is
	// pointer-free, so every read is layout-independent. If the FIRST
	// would-be instance fails sanity the object is instance-less
	// (PERF_NO_INSTANCES — a bare counter block sits at DefinitionLength);
	// a failure deeper in the chain means a corrupt blob.
	objEnd := int(total)
	for off := defEnd; off < objEnd; {
		inst, next, ok := parseInstance(data, off, objEnd, obj.Counters)
		if !ok {
			if len(obj.Instances) == 0 {
				break // instance-less object
			}
			return nil, 0, fmt.Errorf("corrupt instance at object offset %d", off)
		}
		obj.Instances = append(obj.Instances, *inst)
		off = next
	}

	return obj, int(total), nil
}

// PERF_INSTANCE_DEFINITION offsets (pointer-free: six DWORDs, then the
// UTF-16 name).
const (
	instByteLength = 0
	instNameOffset = 16
	instNameLength = 20
	instFixedSize  = 24
)

// parseInstance parses one instance definition plus its counter block at
// data[off:]. ok=false means the bytes at off do not look like an instance
// definition (see the PERF_NO_INSTANCES note in parseObject).
func parseInstance(data []byte, off, objEnd int, counters []Counter) (*Instance, int, bool) {
	if off+instFixedSize > objEnd {
		return nil, 0, false
	}
	bl := int(binary.LittleEndian.Uint32(data[off+instByteLength:]))
	// ByteLength covers the fixed part plus the instance name and is
	// 8-aligned in practice; the counter block follows immediately.
	if bl < instFixedSize || off+bl+4 > objEnd {
		return nil, 0, false
	}
	nameOff := int(binary.LittleEndian.Uint32(data[off+instNameOffset:]))
	nameLen := int(binary.LittleEndian.Uint32(data[off+instNameLength:]))
	if nameOff > bl || nameOff+nameLen > bl {
		return nil, 0, false
	}
	cb := off + bl
	cbLen := int(binary.LittleEndian.Uint32(data[cb:]))
	if cbLen < 4 || cb+cbLen > objEnd {
		return nil, 0, false
	}

	name := ""
	if nameLen > 0 {
		name = decodeUTF16String(data[off+nameOff : off+nameOff+nameLen])
	}

	inst := &Instance{Name: name, Values: make(map[uint32]uint64, len(counters))}
	block := data[cb : cb+cbLen]
	for _, c := range counters {
		// CounterSize is authoritative for the value width (4- vs 64-bit);
		// the PERF_SIZE bits in CounterType say the same thing less directly.
		// A counter reaching past the block is skipped, not fatal — perflib
		// snapshots can be internally racy for exiting processes.
		end := int(c.Offset + c.Size)
		if c.Size == 0 || c.Size > 8 || end > cbLen {
			continue
		}
		var v uint64
		for i := uint32(0); i < c.Size; i++ {
			v |= uint64(block[c.Offset+i]) << (8 * i)
		}
		inst.Values[c.NameTitleIndex] = v
	}
	return inst, cb + cbLen, true
}

// decodeUTF16String decodes a UTF-16LE byte slice and trims trailing NULs
// (instance NameLength includes the terminator).
func decodeUTF16String(b []byte) string {
	n := len(b) &^ 1 // odd lengths: drop the dangling byte
	for n >= 2 && b[n-2] == 0 && b[n-1] == 0 {
		n -= 2
	}
	return utf16le.DecodeToString(b[:n])
}

// ParseTitles parses a counter title database value (the REG_MULTI_SZ
// "Counter 009" value under HKEY_PERFORMANCE_NLSTEXT/TEXT) into counter
// name → title indexes. Entries are (decimal index, name) pairs. Names are
// NOT unique across object families ("Thread Count" exists in both Process
// and Job Object), so each name maps to every index seen, in database
// order (ascending registration order — the kernel's PerfOS family comes
// first).
func ParseTitles(data []byte) map[string][]uint32 {
	var strs []string
	var cur []uint16
	for i := 0; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i:])
		if c == 0 {
			strs = append(strs, string(utf16.Decode(cur)))
			cur = nil
		} else {
			cur = append(cur, c)
		}
	}

	titles := make(map[string][]uint32, len(strs)/2)
	for i := 0; i+1 < len(strs); i += 2 {
		idx, err := strconv.ParseUint(strs[i], 10, 32)
		if err != nil || strs[i+1] == "" {
			continue // tolerate a malformed pair; the DB is advisory
		}
		titles[strs[i+1]] = append(titles[strs[i+1]], uint32(idx))
	}
	return titles
}
