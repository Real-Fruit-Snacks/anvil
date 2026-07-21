package smbclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

// Fixture builders construct SchRpc* response bytes the way Server 2022
// sends them (layouts probed on the wire; see tasks.go comments). They are
// deliberately independent of the production parsers.

// ndrString appends one conformant varying string (maxCount, offset=0,
// actualCount, UTF-16LE incl. null, padded to 4) — the deferred-string form
// in tsch enum/retrieve responses.
func ndrString(buf *bytes.Buffer, s string) {
	u := append(utf16.Encode([]rune(s)), 0)
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

// buildEnumResponse builds one SchRpcEnumFolders/EnumTasks page:
// [start][pcNames][pNames ref][array max][string refs][strings][HRESULT].
// A nil names slice emits the zero-name form (NULL pNames referent).
func buildEnumResponse(start, hr uint32, names ...string) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, start)
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))
	if len(names) == 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pNames
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000))
		binary.Write(buf, binary.LittleEndian, uint32(len(names))) // array maxCount
		for i := range names {
			binary.Write(buf, binary.LittleEndian, uint32(0x20004+i*4))
		}
		for _, n := range names {
			ndrString(buf, n)
		}
	}
	binary.Write(buf, binary.LittleEndian, hr)
	return buf.Bytes()
}

// buildRetrieveResponse builds a SchRpcRetrieveTask response:
// [pXml ref][string][HRESULT]; NULL referent when xml is empty.
func buildRetrieveResponse(xml string, hr uint32) []byte {
	buf := new(bytes.Buffer)
	if xml == "" {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000))
		ndrString(buf, xml)
	}
	binary.Write(buf, binary.LittleEndian, hr)
	return buf.Bytes()
}

// buildInstancesResponse builds a SchRpcEnumInstances response:
// [pcGuids][pGuids ref][array max][GUIDs][HRESULT].
func buildInstancesResponse(count uint32, hr uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, count)
	if count == 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000))
		binary.Write(buf, binary.LittleEndian, count)
		buf.Write(make([]byte, 16*count)) // GUID values carry no meaning here
	}
	binary.Write(buf, binary.LittleEndian, hr)
	return buf.Bytes()
}

func TestNormalizeTaskPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{``, `\`},
		{`\`, `\`},
		{`/`, `\`},
		{`\\`, `\`},
		{`Microsoft`, `\Microsoft`},
		{`\Microsoft`, `\Microsoft`},
		{`\Microsoft\`, `\Microsoft`},
		{`Microsoft/Windows`, `\Microsoft\Windows`},
		{`\Microsoft\\Windows\`, `\Microsoft\Windows`},
		{"  \\a\\b  ", `\a\b`},
		{`\Microsoft\Windows\.NET Framework`, `\Microsoft\Windows\.NET Framework`},
	}
	for _, c := range cases {
		if got := normalizeTaskPath(c.in); got != c.want {
			t.Errorf("normalizeTaskPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJoinTaskPath(t *testing.T) {
	cases := []struct{ folder, name, want string }{
		{`\`, `A`, `\A`},
		{`\Microsoft`, `Windows`, `\Microsoft\Windows`},
		{`\Microsoft\Windows`, `Reboot`, `\Microsoft\Windows\Reboot`},
	}
	for _, c := range cases {
		if got := joinTaskPath(c.folder, c.name); got != c.want {
			t.Errorf("joinTaskPath(%q, %q) = %q, want %q", c.folder, c.name, got, c.want)
		}
	}
}

func TestTaskStorePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{`\A`, `System32/Tasks/A`},
		{`A`, `System32/Tasks/A`},
		{`\Microsoft\Windows\Reboot`, `System32/Tasks/Microsoft/Windows/Reboot`},
		{`\`, `System32/Tasks/`},
	}
	for _, c := range cases {
		if got := taskStorePath(c.in); got != c.want {
			t.Errorf("taskStorePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTaskState(t *testing.T) {
	cases := []struct {
		enabled bool
		running int
		want    string
	}{
		{true, 0, "ready"},
		{true, 1, "running"},
		{true, 2, "running"},
		{false, 0, "disabled"},
		{false, 1, "running"}, // a disabled task can still be mid-run
	}
	for _, c := range cases {
		if got := taskState(c.enabled, c.running); got != c.want {
			t.Errorf("taskState(%v, %d) = %q, want %q", c.enabled, c.running, got, c.want)
		}
	}
}

func TestParseTaskEnabled(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want bool
	}{
		{
			"settings enabled true",
			`<Task><Settings><Enabled>true</Enabled></Settings></Task>`, true,
		},
		{
			"settings enabled false",
			`<Task><Settings><Enabled>false</Enabled></Settings></Task>`, false,
		},
		{
			"schema default when absent",
			`<Task><Settings><Hidden>true</Hidden></Settings></Task>`, true,
		},
		{
			"no settings section at all",
			`<Task><Triggers><CalendarTrigger><Enabled>false</Enabled></CalendarTrigger></Triggers></Task>`, true,
		},
		{
			"trigger false but settings true (settings wins)",
			`<Task><Triggers><CalendarTrigger><Enabled>false</Enabled></CalendarTrigger></Triggers>` +
				`<Settings><Enabled>true</Enabled></Settings></Task>`, true,
		},
		{
			"trigger true but settings false (settings wins)",
			`<Task><Triggers><CalendarTrigger><Enabled>true</Enabled></CalendarTrigger></Triggers>` +
				`<Settings><Enabled>false</Enabled></Settings></Task>`, false,
		},
		{
			"whitespace-padded value",
			`<Task><Settings><Enabled> false </Enabled></Settings></Task>`, false,
		},
	}
	for _, c := range cases {
		if got := parseTaskEnabled(c.xml); got != c.want {
			t.Errorf("%s: parseTaskEnabled = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseEnumNamesResponse(t *testing.T) {
	t.Run("two names", func(t *testing.T) {
		// "ABCD" needs 2 padding bytes after its data; "ABC" needs none —
		// exercises alignment between consecutive deferred strings.
		resp := buildEnumResponse(3, 0, "ABCD", "ABC")
		next, names, err := parseEnumNamesResponse(resp)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if next != 3 {
			t.Errorf("next = %d, want 3", next)
		}
		if len(names) != 2 || names[0] != "ABCD" || names[1] != "ABC" {
			t.Errorf("names = %v, want [ABCD ABC]", names)
		}
	})

	t.Run("zero names NULL pointer", func(t *testing.T) {
		resp := buildEnumResponse(1, 0)
		next, names, err := parseEnumNamesResponse(resp)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if next != 1 || len(names) != 0 {
			t.Errorf("next=%d names=%v, want 1 and empty", next, names)
		}
	})

	t.Run("S_FALSE empty enumeration is success", func(t *testing.T) {
		// Server 2022 returns S_FALSE (0x00000001) for a successful but
		// empty enumeration on some folders (e.g. EnumTasks on \Microsoft).
		resp := buildEnumResponse(1, 0x00000001)
		if _, names, err := parseEnumNamesResponse(resp); err != nil || len(names) != 0 {
			t.Errorf("names=%v err=%v, want empty success", names, err)
		}
	})

	t.Run("HRESULT error", func(t *testing.T) {
		resp := buildEnumResponse(1, 0x80070002)
		if _, _, err := parseEnumNamesResponse(resp); err == nil ||
			!strings.Contains(err.Error(), "0x80070002") {
			t.Errorf("err = %v, want 0x80070002", err)
		}
	})

	t.Run("names but NULL array pointer", func(t *testing.T) {
		resp := buildEnumResponse(1, 0, "A")
		binary.LittleEndian.PutUint32(resp[8:12], 0)
		if _, _, err := parseEnumNamesResponse(resp); err == nil {
			t.Error("expected error for NULL array pointer with pcNames=1")
		}
	})

	t.Run("truncated referent table", func(t *testing.T) {
		resp := buildEnumResponse(3, 0, "A", "B")[:20]
		if _, _, err := parseEnumNamesResponse(resp); err == nil {
			t.Error("expected error for truncated referent table")
		}
	})

	t.Run("truncated string data", func(t *testing.T) {
		resp := buildEnumResponse(2, 0, "LongTaskName")
		resp = resp[:len(resp)-10] // cut inside the string data
		if _, _, err := parseEnumNamesResponse(resp); err == nil {
			t.Error("expected error for truncated string data")
		}
	})
}

func TestParseRetrieveTaskResponse(t *testing.T) {
	t.Run("xml ok", func(t *testing.T) {
		xml := `<?xml version="1.0" encoding="UTF-16"?><Task/>`
		got, err := parseRetrieveTaskResponse(buildRetrieveResponse(xml, 0))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got != xml {
			t.Errorf("xml = %q, want %q", got, xml)
		}
	})

	t.Run("missing task: NULL ref + 0x80070002", func(t *testing.T) {
		_, err := parseRetrieveTaskResponse(buildRetrieveResponse("", 0x80070002))
		if err == nil || !strings.Contains(err.Error(), "0x80070002") {
			t.Errorf("err = %v, want 0x80070002", err)
		}
		if me := mapTaskError(err); me == nil || me.Error() != "task not found" {
			t.Errorf("mapTaskError = %v, want 'task not found'", me)
		}
	})

	t.Run("NULL ref with success status", func(t *testing.T) {
		if _, err := parseRetrieveTaskResponse(buildRetrieveResponse("", 0)); err == nil {
			t.Error("expected error for NULL xml pointer with HRESULT 0")
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := parseRetrieveTaskResponse([]byte{1, 2, 3}); err == nil {
			t.Error("expected error for 3-byte response")
		}
	})
}

func TestParseEnumInstancesResponse(t *testing.T) {
	t.Run("no instances", func(t *testing.T) {
		n, err := parseEnumInstancesResponse(buildInstancesResponse(0, 0))
		if err != nil || n != 0 {
			t.Errorf("n=%d err=%v, want 0 nil", n, err)
		}
	})

	t.Run("two instances", func(t *testing.T) {
		n, err := parseEnumInstancesResponse(buildInstancesResponse(2, 0))
		if err != nil || n != 2 {
			t.Errorf("n=%d err=%v, want 2 nil", n, err)
		}
	})

	t.Run("HRESULT error", func(t *testing.T) {
		if _, err := parseEnumInstancesResponse(buildInstancesResponse(0, 0x80070005)); err == nil ||
			!strings.Contains(err.Error(), "0x80070005") {
			t.Errorf("err = %v, want 0x80070005", err)
		}
	})

	t.Run("guids but NULL pointer", func(t *testing.T) {
		resp := buildInstancesResponse(1, 0)
		binary.LittleEndian.PutUint32(resp[4:8], 0)
		if _, err := parseEnumInstancesResponse(resp); err == nil {
			t.Error("expected error for NULL guid pointer with pcGuids=1")
		}
	})

	t.Run("truncated guid array", func(t *testing.T) {
		resp := buildInstancesResponse(2, 0)[:16]
		if _, err := parseEnumInstancesResponse(resp); err == nil {
			t.Error("expected error for truncated guid array")
		}
	})
}

func TestMapTaskError(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means the error passes through unchanged
	}{
		{"enum returned error 0x80070002", "task not found"},
		{"run returned error 0x80070005", "access denied (admin required)"},
		{"NTSTATUS 0x00000005", "access denied (admin required)"},
		{"enum returned error 0x8007007b", "invalid task path"},
		{"run returned error 0x80041326", "task is disabled"},
		{"retrieve returned error 0x8004131a", "task definition is malformed on the server"},
		{"connection reset by peer", ""},
	}
	for _, c := range cases {
		got := mapTaskError(errors.New(c.in))
		if c.want == "" {
			if got.Error() != c.in {
				t.Errorf("mapTaskError(%q) rewrote to %q, want passthrough", c.in, got)
			}
			continue
		}
		if got == nil || got.Error() != c.want {
			t.Errorf("mapTaskError(%q) = %v, want %q", c.in, got, c.want)
		}
	}
	if mapTaskError(nil) != nil {
		t.Error("mapTaskError(nil) != nil")
	}
}
