package smbclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildEventXPath verifies the XPath 1.0 construction: fixed
// conjunction order (provider, level, id, time), the level mapping
// (information covers level 0 — Security audits), the timediff idiom for
// the age filter, and rejection of invalid input.
func TestBuildEventXPath(t *testing.T) {
	tests := []struct {
		name    string
		opts    EventQuery
		want    string // exact XPath; "" means an error is expected
		wantErr string
	}{
		{"no filters", EventQuery{}, "*", ""},
		{"event id", EventQuery{EventID: 7040}, "*[System[EventID=7040]]", ""},
		{
			"minutes",
			EventQuery{Minutes: 10},
			"*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]",
			"",
		},
		{"type error", EventQuery{Type: "error"}, "*[System[Level=2]]", ""},
		{"type warning", EventQuery{Type: "warning"}, "*[System[Level=3]]", ""},
		{
			"type information includes level 0",
			EventQuery{Type: "information"},
			"*[System[(Level=4 or Level=0)]]",
			"",
		},
		{
			"type is case-insensitive",
			EventQuery{Type: "Warning"},
			"*[System[Level=3]]",
			"",
		},
		{
			"source",
			EventQuery{Source: "Service Control Manager"},
			"*[System[Provider[@Name='Service Control Manager']]]",
			"",
		},
		{
			"all server-side filters in fixed order",
			EventQuery{Source: "LsaSrv", Type: "error", EventID: 6038, Minutes: 60},
			"*[System[Provider[@Name='LsaSrv'] and Level=2 and EventID=6038 and TimeCreated[timediff(@SystemTime) <= 3600000]]]",
			"",
		},
		{"invalid type", EventQuery{Type: "bogus"}, "", "invalid event type"},
		{"source with single quote", EventQuery{Source: "bad'source"}, "", "quotes are not supported"},
		{"source with double quote", EventQuery{Source: `bad"source`}, "", "quotes are not supported"},
		{"negative event id", EventQuery{EventID: -1}, "", "invalid event id"},
		{"negative minutes", EventQuery{Minutes: -5}, "", "invalid minutes"},
		{
			"Contains never reaches the XPath (client-side filter)",
			EventQuery{Contains: "foo"},
			"*",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildEventXPath(tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("buildEventXPath(%+v) err = %v, want substring %q", tt.opts, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildEventXPath(%+v) unexpected error: %v", tt.opts, err)
			}
			if got != tt.want {
				t.Errorf("buildEventXPath(%+v) = %q, want %q", tt.opts, got, tt.want)
			}
		})
	}
}

// TestEventQueryCommands verifies the two wevtutil command lines (data
// pass /f:xml, rendered pass /f:RenderedXml — identical otherwise): quoted
// log name and XPath, newest-first (/rd:true), the single-document wrapper
// (/e:Events), the default limit, and the Contains overfetch (inflated
// server-side count, capped) that keeps the client-side substring filter
// meaningful.
func TestEventQueryCommands(t *testing.T) {
	tests := []struct {
		name    string
		logName string
		opts    EventQuery
		want    string // shared command prefix; "" means an error is expected
		wantErr string
	}{
		{
			"plain with explicit limit",
			"System",
			EventQuery{Limit: 5},
			`wevtutil qe "System" /q:"*" /c:5 /rd:true`,
			"",
		},
		{
			"default limit applies",
			"Security",
			EventQuery{},
			`wevtutil qe "Security" /q:"*" /c:20 /rd:true`,
			"",
		},
		{
			"with filters",
			"System",
			EventQuery{EventID: 7036, Limit: 10},
			`wevtutil qe "System" /q:"*[System[EventID=7036]]" /c:10 /rd:true`,
			"",
		},
		{
			"contains overfetches 10x",
			"System",
			EventQuery{Contains: "service", Limit: 3},
			`wevtutil qe "System" /q:"*" /c:30 /rd:true`,
			"",
		},
		{
			"contains overfetch is capped",
			"System",
			EventQuery{Contains: "service", Limit: 500},
			`wevtutil qe "System" /q:"*" /c:1000 /rd:true`,
			"",
		},
		{"empty log name", "", EventQuery{}, "", "no event log name given"},
		{"log name with quote", `Sys"tem`, EventQuery{}, "", "invalid event log name"},
		{"log name with percent", `Sys%tem`, EventQuery{}, "", "invalid event log name"},
		{"log name with control char", "Sys\ntem", EventQuery{}, "", "invalid event log name"},
		{"invalid filter propagates", "System", EventQuery{Type: "bogus"}, "", "invalid event type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataCmd, renderCmd, err := eventQueryCommands(tt.logName, tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("eventQueryCommands(%q, %+v) err = %v, want substring %q",
						tt.logName, tt.opts, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("eventQueryCommands(%q, %+v) unexpected error: %v", tt.logName, tt.opts, err)
			}
			wantData := tt.want + " /f:xml /e:Events"
			wantRender := tt.want + " /f:RenderedXml /e:Events"
			if dataCmd != wantData {
				t.Errorf("data cmd =\n  %q\nwant\n  %q", dataCmd, wantData)
			}
			if renderCmd != wantRender {
				t.Errorf("render cmd =\n  %q\nwant\n  %q", renderCmd, wantRender)
			}
		})
	}
}

// TestFilterEventRecords verifies the client-side Contains filter:
// case-insensitive message matching, limit truncation, and newest-first
// order preservation.
func TestFilterEventRecords(t *testing.T) {
	recs := []EventRecord{
		{ID: 1, Message: "The Remote Registry service entered the running state."},
		{ID: 2, Message: "The system uptime is 29598 seconds."},
		{ID: 3, Message: "The Application Experience service entered the stopped state."},
		{ID: 4, Message: "REMOTE registry stopped."},
	}

	t.Run("no contains passes through in order", func(t *testing.T) {
		got := filterEventRecords(recs, EventQuery{Limit: 10})
		if len(got) != 4 || got[0].ID != 1 || got[3].ID != 4 {
			t.Errorf("got %v, want all 4 records in order", got)
		}
	})

	t.Run("contains is case-insensitive and keeps order", func(t *testing.T) {
		got := filterEventRecords(recs, EventQuery{Contains: "remote registry", Limit: 10})
		if len(got) != 2 || got[0].ID != 1 || got[1].ID != 4 {
			t.Errorf("got %v, want records 1 and 4", got)
		}
	})

	t.Run("limit truncates after filtering", func(t *testing.T) {
		got := filterEventRecords(recs, EventQuery{Contains: "service", Limit: 1})
		if len(got) != 1 || got[0].ID != 1 {
			t.Errorf("got %v, want only record 1", got)
		}
	})

	t.Run("no match yields empty", func(t *testing.T) {
		got := filterEventRecords(recs, EventQuery{Contains: "no such text", Limit: 10})
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("zero limit applies the default", func(t *testing.T) {
		many := make([]EventRecord, eventDefaultLimit+5)
		got := filterEventRecords(many, EventQuery{})
		if len(got) != eventDefaultLimit {
			t.Errorf("got %d records, want the default %d", len(got), eventDefaultLimit)
		}
	})
}

// TestEventLevelName verifies the numeric System.Level fallback mapping
// (used when RenderingInfo is absent); 0 renders as Information like
// Windows does for Security audits.
func TestEventLevelName(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{0, "Information"},
		{1, "Critical"},
		{2, "Error"},
		{3, "Warning"},
		{4, "Information"},
		{5, "Verbose"},
		{99, "Information"},
	}
	for _, tt := range tests {
		if got := eventLevelName(tt.level); got != tt.want {
			t.Errorf("eventLevelName(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// TestParseEventDate verifies SystemTime parsing: the 7-digit-fraction UTC
// form wevtutil emits, a zone-less fallback, and the zero-time passthrough
// for garbage.
func TestParseEventDate(t *testing.T) {
	t.Run("wevtutil 7-digit UTC", func(t *testing.T) {
		got := parseEventDate("2026-07-20T18:54:01.6908541Z")
		if got.IsZero() {
			t.Fatal("parse failed")
		}
		if got.Location() != time.UTC {
			t.Errorf("location = %v, want UTC", got.Location())
		}
		if got.Year() != 2026 || got.Month() != 7 || got.Day() != 20 ||
			got.Hour() != 18 || got.Minute() != 54 || got.Second() != 1 {
			t.Errorf("wrong wall clock: %v", got)
		}
		if got.Nanosecond() != 690854100 {
			t.Errorf("wrong fraction: %d", got.Nanosecond())
		}
	})

	t.Run("zone-less fallback", func(t *testing.T) {
		if got := parseEventDate("2026-07-20T11:49:02.284"); got.IsZero() {
			t.Error("parse failed")
		}
	})

	t.Run("garbage yields zero time", func(t *testing.T) {
		if got := parseEventDate("not a date"); !got.IsZero() {
			t.Errorf("got %v, want zero time", got)
		}
	})
}

// TestParseEventXML parses the live capture from the lab DC
// (testdata/wevtutil-events.xml, `wevtutil qe System /q:* /c:5 /rd:true
// /f:RenderedXml /e:Events` on Server 2022) and checks every mapped field,
// including wevtutil's single-quoted XML attributes.
func TestParseEventXML(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "wevtutil-events.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	recs, err := parseEventXML(string(data))
	if err != nil {
		t.Fatalf("parseEventXML: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("parsed %d records, want 5", len(recs))
	}

	first := recs[0]
	if first.ID != 7040 {
		t.Errorf("first.ID = %d, want 7040", first.ID)
	}
	if first.Source != "Service Control Manager" {
		t.Errorf("first.Source = %q, want Service Control Manager", first.Source)
	}
	if first.Level != "Information" {
		t.Errorf("first.Level = %q, want Information", first.Level)
	}
	if first.TimeCreated.IsZero() || first.TimeCreated.Location() != time.UTC {
		t.Errorf("first.TimeCreated = %v, want a UTC timestamp", first.TimeCreated)
	}
	if !strings.Contains(first.Message, "start type of the Smart Card service") {
		t.Errorf("first.Message = %q, want the rendered start-type text", first.Message)
	}

	// Newest-first order is the document order under /rd:true: timestamps
	// must be non-increasing down the slice.
	for i := 1; i < len(recs); i++ {
		if recs[i].TimeCreated.After(recs[i-1].TimeCreated) {
			t.Errorf("record %d (%v) is newer than record %d (%v) — order broken",
				i, recs[i].TimeCreated, i-1, recs[i-1].TimeCreated)
		}
	}
}

// TestParseEventXMLDataPass parses the /f:xml data-pass capture from the
// lab DC (testdata/wevtutil-events-xml.xml, `wevtutil qe System /q:* /c:3
// /rd:true /f:xml /e:Events` on Server 2022): no RenderingInfo anywhere, so
// every record takes the fallbacks — numeric level mapping and the
// "Name=value" event-data message.
func TestParseEventXMLDataPass(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "wevtutil-events-xml.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	recs, err := parseEventXML(string(data))
	if err != nil {
		t.Fatalf("parseEventXML: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("parsed %d records, want 3", len(recs))
	}
	first := recs[0]
	if first.ID != 7036 {
		t.Errorf("first.ID = %d, want 7036", first.ID)
	}
	if first.Level != "Information" {
		t.Errorf("first.Level = %q, want the numeric fallback Information", first.Level)
	}
	want := "param1=Device Setup Manager, param2=stopped"
	if first.Message != want {
		t.Errorf("first.Message = %q, want %q", first.Message, want)
	}
	if first.recordID == 0 {
		t.Error("recordID (merge key) not parsed from EventRecordID")
	}
}

// TestParseEventXMLEdgeCases covers the shapes a fixture cannot: the empty
// result document, a RenderingInfo-less event (fallbacks to numeric level +
// "Name=value" event data), and non-XML input (wevtutil error text)
// surfacing a parse error.
func TestParseEventXMLEdgeCases(t *testing.T) {
	t.Run("empty events document", func(t *testing.T) {
		recs, err := parseEventXML("<Events>\r\n</Events>\r\n")
		if err != nil {
			t.Fatalf("parseEventXML: %v", err)
		}
		if len(recs) != 0 {
			t.Errorf("got %d records, want 0", len(recs))
		}
	})

	t.Run("missing RenderingInfo falls back", func(t *testing.T) {
		doc := `<Events><Event><System><Provider Name='TestProv'/><EventID>42</EventID>` +
			`<Level>3</Level><EventRecordID>777</EventRecordID>` +
			`<TimeCreated SystemTime='2026-07-20T10:00:00.0000000Z'/></System>` +
			`<EventData><Data Name='param1'>alpha</Data><Data>beta</Data></EventData></Event></Events>`
		recs, err := parseEventXML(doc)
		if err != nil {
			t.Fatalf("parseEventXML: %v", err)
		}
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0].Level != "Warning" {
			t.Errorf("Level = %q, want the numeric fallback Warning", recs[0].Level)
		}
		if recs[0].Message != "param1=alpha, beta" {
			t.Errorf("Message = %q, want the event-data fallback", recs[0].Message)
		}
		if recs[0].recordID != 777 {
			t.Errorf("recordID = %d, want 777 (merge key)", recs[0].recordID)
		}
	})

	t.Run("wevtutil error text is not XML", func(t *testing.T) {
		_, err := parseEventXML("Failed to open event query. The specified channel could not be found.\r\n")
		if err == nil {
			t.Error("want a parse error on non-XML input")
		}
	})

	t.Run("invalid UTF-8 is sanitized, not fatal", func(t *testing.T) {
		doc := "<Events><Event><System><Provider Name='P'/><EventID>1</EventID>" +
			"<Level>4</Level><TimeCreated SystemTime='2026-07-20T10:00:00Z'/></System>" +
			"<RenderingInfo><Message>caf\xE9 closed</Message><Level>Information</Level>" +
			"</RenderingInfo></Event></Events>"
		recs, err := parseEventXML(doc)
		if err != nil {
			t.Fatalf("parseEventXML: %v", err)
		}
		if !strings.Contains(recs[0].Message, "closed") {
			t.Errorf("Message = %q, want the CP1252 byte sanitized away", recs[0].Message)
		}
	})
}

// TestMergeRenderedMessages verifies the two-pass overlay: rendered
// Message/Level attach by EventRecordID, records the rendered pass dropped
// keep their fallbacks, empty rendered fields never overwrite, and the
// slice order (newest-first) is untouched.
func TestMergeRenderedMessages(t *testing.T) {
	recs := []parsedEvent{
		{EventRecord: EventRecord{ID: 1, Level: "Information", Message: "param1=raw1"}, recordID: 100},
		{EventRecord: EventRecord{ID: 2, Level: "Information", Message: "param1=raw2"}, recordID: 99},
		{EventRecord: EventRecord{ID: 3, Level: "Information", Message: "param1=raw3"}, recordID: 98},
	}
	rendered := []parsedEvent{
		{EventRecord: EventRecord{ID: 1, Level: "Information", Message: "rendered one"}, recordID: 100},
		// recordID 99 dropped by the rendered pass (unrenderable provider).
		{EventRecord: EventRecord{ID: 3, Level: "", Message: "rendered three"}, recordID: 98},
	}
	mergeRenderedMessages(recs, rendered)

	if recs[0].Message != "rendered one" {
		t.Errorf("recs[0].Message = %q, want rendered overlay", recs[0].Message)
	}
	if recs[1].Message != "param1=raw2" {
		t.Errorf("recs[1].Message = %q, want the kept data fallback", recs[1].Message)
	}
	if recs[2].Message != "rendered three" {
		t.Errorf("recs[2].Message = %q, want rendered overlay", recs[2].Message)
	}
	if recs[2].Level != "Information" {
		t.Errorf("recs[2].Level = %q, want the kept fallback (empty rendered level must not overwrite)", recs[2].Level)
	}
	if recs[0].recordID != 100 || recs[1].recordID != 99 || recs[2].recordID != 98 {
		t.Errorf("order changed: %v", recs)
	}
}

// TestStripEventRecords verifies the merge key is dropped and order kept.
func TestStripEventRecords(t *testing.T) {
	recs := []parsedEvent{
		{EventRecord: EventRecord{ID: 1}, recordID: 100},
		{EventRecord: EventRecord{ID: 2}, recordID: 99},
	}
	out := stripEventRecords(recs)
	if len(out) != 2 || out[0].ID != 1 || out[1].ID != 2 {
		t.Errorf("got %v, want [1 2] in order", out)
	}
}

// TestParseEventLogList parses a trimmed live capture of `wevtutil el`
// (testdata/wevtutil-el.txt): CRLF endings and blank lines must not leak
// into the result.
func TestParseEventLogList(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "wevtutil-el.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	logs := parseEventLogList(string(data))
	if len(logs) == 0 {
		t.Fatal("no logs parsed")
	}
	for _, want := range []string{"Application", "Security", "System"} {
		found := false
		for _, l := range logs {
			if l == want {
				found = true
			}
		}
		if !found {
			t.Errorf("log %q missing from %v", want, logs)
		}
	}
	for _, l := range logs {
		if strings.TrimSpace(l) != l {
			t.Errorf("log name carries whitespace: %q", l)
		}
	}

	t.Run("empty output", func(t *testing.T) {
		if logs := parseEventLogList(""); logs != nil {
			t.Errorf("got %v, want nil", logs)
		}
	})
}

// TestEventlogError verifies the wevtutil failure-string mapping (its
// stderr lands in the output via Exec's 2>&1) and that clean/empty output
// maps to no error.
func TestEventlogError(t *testing.T) {
	tests := []struct {
		name string
		out  string
		log  string
		want string // substring; "" means nil error expected
	}{
		{
			"unknown log",
			"Failed to open event query. The specified channel could not be found.\r\n",
			"No-Such-Log",
			`event log "No-Such-Log" not found`,
		},
		{
			"access denied",
			"Failed to open event query. Access is denied.\r\n",
			"Security",
			"access denied",
		},
		{
			"bad XPath",
			"Failed to open event query. The parameter is incorrect.\r\n",
			"System",
			"invalid XPath",
		},
		{
			"unknown failure surfaces the first line",
			"Failed to frobnicate the channel.\r\nmore detail\r\n",
			"System",
			"wevtutil failed: Failed to frobnicate the channel.",
		},
		{"empty output", "", "System", ""},
		{"blank output", "  \r\n", "System", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eventlogError(tt.out, tt.log)
			if tt.want == "" {
				if err != nil {
					t.Errorf("eventlogError(%q) = %v, want nil", tt.out, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("eventlogError(%q) = %v, want substring %q", tt.out, err, tt.want)
			}
		})
	}
}

// TestValidateEventLogName pins the cmd.exe metacharacter rules: the log
// name lands double-quoted inside `cmd /C ( ... )`, so quotes (close the
// argument), percent (expands even inside quotes) and control characters
// (corrupt Exec's task XML) are rejected; ordinary special names pass.
func TestValidateEventLogName(t *testing.T) {
	valid := []string{
		"System", "Security", "Application", "ForwardedEvents",
		"Microsoft-Windows-PowerShell/Operational",
		"Windows PowerShell",
	}
	for _, name := range valid {
		if err := validateEventLogName(name); err != nil {
			t.Errorf("validateEventLogName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{"", `a"b`, "a%b", "a\nb", "a\tb"}
	for _, name := range invalid {
		if err := validateEventLogName(name); err == nil {
			t.Errorf("validateEventLogName(%q) = nil, want error", name)
		}
	}
}

// TestEmitEventWarnings is a compile-time guard on the warning helper's
// shape — the actual printing goes to stderr via ui.Warm and is verified by
// inspection, not capture.
func TestEmitEventWarnings(t *testing.T) {
	emitEventWarnings(nil) // must not panic
}
