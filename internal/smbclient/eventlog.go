package smbclient

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode"

	"anvil/internal/ui"
)

// Event-log access rides wevtutil over the existing Exec (TSCH) channel.
//
// Transport rationale: gopacket carries no client for the eventlog RPC
// interfaces — pkg/dcerpc covers samr/srvsvc/svcctl/tsch/winreg/drsuapi/
// lsarpc/netlogon/wkssvc/epmapper/bkrp/gkdi/icpr, and neither Even
// (MS-EVEN, \pipe\eventlog) nor Even6 (MS-EVEN6) is among them; no tool
// under gopacket's tools/ touches event logs either. Writing an Even6
// client from scratch (context handles, BinXml rendering templates) is
// out of proportion for read-only queries, so both functions below run
// wevtutil.exe through Session.Exec — the same one-connection discipline
// as exec/ntdsdump (atsvc pipe on IPC$, output file over ADMIN$, no new
// channels). The cost: admin on the target is required, exactly like exec.
//
// Output format: XML, NOT /f:text. Proven on the wire against Server 2022:
// when wevtutil's stdout is redirected (which Exec's output file always
// does), its text renderer degrades — newlines come out as NUL/'?' garbage
// and most events lose their rendered metadata (Level/Task/Description all
// "N/A"). Reproduced with plain `wevtutil ... > file` on the DC console,
// so it is a wevtutil rendering bug, not a transport artifact.
//
// Query shape: TWO passes, merged (see EventLogQuery). wevtutil's
// /f:RenderedXml SILENTLY DROPS events whose provider message file it
// cannot render — on the lab DC's Application log only 252 of 869 records
// survive, and a newest-first query whose tail is all-unrenderable (SceCli
// in that session context) returns ZERO events from a non-empty log. /f:xml
// never drops events but carries no rendered message. So: /f:xml for the
// complete event set, /f:RenderedXml for the localized messages, merged by
// EventRecordID. Both queries cost one Exec round-trip each; the second is
// skipped when the first matches nothing.
//
// wevtutil is read-only by design here: `el` only lists, `qe` only reads.
// The remote artifacts (scheduled task + %windir%\Temp output file) are
// Exec's own and are cleanup-verified there; the rare leftover is surfaced
// as a warm warning by emitEventWarnings.

const (
	// eventDefaultLimit is the record cap when EventQuery.Limit is unset.
	eventDefaultLimit = 20

	// eventSubstringOverfetch compensates for Contains being client-side:
	// the server must return more than Limit records for the substring
	// filter to have something to reject, so the fetch count is inflated.
	eventSubstringOverfetch = 10

	// eventMaxFetch caps the inflated fetch so a substring query cannot
	// pull an unbounded event stream through the SMB session.
	eventMaxFetch = 1000
)

// EventQuery carries the optional filters for EventLogQuery. The zero value
// means "newest eventDefaultLimit records of the log, any content". Type,
// EventID, Source, and Minutes are applied server-side via XPath; Contains
// is applied client-side (see EventLogQuery for why).
type EventQuery struct {
	Minutes  int    // only events of the last N minutes on the target's clock (0 = any age)
	EventID  int    // exact event ID (0 = any)
	Type     string // "error", "warning", or "information" (case-insensitive; "" = any)
	Source   string // exact provider/source name, e.g. "Service Control Manager" ("" = any)
	Contains string // case-insensitive substring of the event message ("" = any)
	Limit    int    // max records returned (<= 0 = eventDefaultLimit)
}

// EventRecord is one parsed event from wevtutil's XML rendering.
type EventRecord struct {
	TimeCreated time.Time // UTC — the XML SystemTime is always Zulu; zero when unparseable
	ID          int
	Level       string // rendered level name: "Error", "Warning", "Information", ...
	Source      string // provider name
	Message     string // rendered message; "Name=value" event-data pairs when the provider message file is unrenderable
}

// EventLogList returns the names of all event logs on the target
// (`wevtutil el`), in the server's order. Requires admin (Exec transport).
func (s *Session) EventLogList() ([]string, error) {
	out, warnings, err := s.Exec("wevtutil el")
	emitEventWarnings(warnings)
	if err != nil {
		return nil, err
	}
	logs := parseEventLogList(out)
	if len(logs) == 0 {
		if err := eventlogError(out, ""); err != nil {
			return nil, err
		}
	}
	return logs, nil
}

// EventLogQuery queries one event log and returns matching records newest
// first. Requires admin (Exec transport; reading the Security log needs it
// anyway).
//
// Two wevtutil passes ride the same Exec transport, merged by
// EventRecordID: `/f:xml` (complete — never drops events) plus
// `/f:RenderedXml` (localized messages — but silently drops unrenderable
// events; see the package-level comment). Records the rendered pass
// dropped keep their raw event data as the message. When the rendered
// pass itself fails, the complete set is returned with data-only messages
// (degraded, debug-logged — never an error while the data pass worked).
//
// Type/EventID/Source/Minutes become one XPath 1.0 expression the server's
// Event Log service evaluates (MS-EVEN6's restricted subset — no contains()
// function exists there), which is why Contains is matched client-side
// against the message instead; the fetch count is over-inflated
// (eventSubstringOverfetch, capped at eventMaxFetch) so up to Limit records
// still survive the client-side filter. wevtutil's stderr is merged into
// its output by Exec, so its failure strings are detected and mapped to
// plain-language errors (eventlogError).
func (s *Session) EventLogQuery(logName string, opts EventQuery) ([]EventRecord, error) {
	dataCmd, renderCmd, err := eventQueryCommands(logName, opts)
	if err != nil {
		return nil, err
	}

	// Pass 1: /f:xml — the complete matching set, newest first.
	out, warnings, err := s.Exec(dataCmd)
	ui.Debugf("eventlog: cmd=%q outlen=%d err=%v", dataCmd, len(out), err)
	emitEventWarnings(warnings)
	if err != nil {
		return nil, err
	}
	recs, perr := parseEventXML(out)
	if perr != nil {
		// wevtutil prints its failures as text (merged into the output by
		// Exec's 2>&1), which is not XML — map the known failure strings
		// before reporting a parse problem.
		if err := eventlogError(out, logName); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("cannot parse wevtutil output: %v", perr)
	}
	ui.Debugf("eventlog: parsed %d records", len(recs))
	if len(recs) == 0 {
		return nil, nil // no matching events — not an error
	}

	// Pass 2: /f:RenderedXml — rendered messages for the same set. Skipped
	// on an empty first pass; degraded (not failed) when it errors.
	out, warnings, err = s.Exec(renderCmd)
	ui.Debugf("eventlog: cmd=%q outlen=%d err=%v", renderCmd, len(out), err)
	emitEventWarnings(warnings)
	if err != nil {
		ui.Debugf("eventlog: rendered pass failed, keeping raw messages: %v", err)
	} else if rendered, perr := parseEventXML(out); perr != nil {
		ui.Debugf("eventlog: rendered pass unparsable, keeping raw messages: %v", perr)
	} else {
		mergeRenderedMessages(recs, rendered)
	}

	return filterEventRecords(stripEventRecords(recs), opts), nil
}

// eventQueryCommands builds the two wevtutil qe command lines (data pass,
// rendered pass). Log name is validated and double-quoted (cmd.exe metachar
// safety — the line lands inside `cmd /C ( ... )`), the XPath is built by
// buildEventXPath, and the fetch count carries the Contains overfetch.
// /e:Events wraps the events in one root element so each output is a single
// well-formed XML document.
func eventQueryCommands(logName string, opts EventQuery) (dataCmd, renderCmd string, err error) {
	if err := validateEventLogName(logName); err != nil {
		return "", "", err
	}
	xpath, err := buildEventXPath(opts)
	if err != nil {
		return "", "", err
	}
	limit := normalizedEventLimit(opts.Limit)
	fetch := limit
	if opts.Contains != "" {
		fetch = limit * eventSubstringOverfetch
		if fetch > eventMaxFetch {
			fetch = eventMaxFetch
		}
	}
	// The XPath itself contains only single quotes (Provider[@Name='...']),
	// so wrapping it in cmd double quotes is collision-free.
	base := fmt.Sprintf(`wevtutil qe "%s" /q:"%s" /c:%d /rd:true`, logName, xpath, fetch)
	return base + " /f:xml /e:Events", base + " /f:RenderedXml /e:Events", nil
}

// buildEventXPath renders opts as one XPath 1.0 expression for wevtutil's
// /q. With no server-side filters the query is `*` (everything). Filter
// order in the conjunction is fixed (provider, level, id, time) so the
// output is deterministic and testable.
//
//   - Source:  Provider[@Name='...'] — exact match, the same equality
//     Event Viewer uses; the restricted XPath has no substring match.
//   - Type:    Level equality — 2 = Error, 3 = Warning, 4 = Information.
//     Level 0 logs as Information too (no level set; Security audits are
//     level 0), hence the "or".
//   - Minutes: timediff(@SystemTime) <= ms — the idiom Event Viewer itself
//     generates for "last hour"-style custom filters.
func buildEventXPath(opts EventQuery) (string, error) {
	var conds []string

	if opts.Source != "" {
		if strings.ContainsAny(opts.Source, `'"`) {
			return "", fmt.Errorf("event source %q is invalid: quotes are not supported", opts.Source)
		}
		conds = append(conds, fmt.Sprintf("Provider[@Name='%s']", opts.Source))
	}

	switch strings.ToLower(strings.TrimSpace(opts.Type)) {
	case "":
	case "error":
		conds = append(conds, "Level=2")
	case "warning":
		conds = append(conds, "Level=3")
	case "information":
		conds = append(conds, "(Level=4 or Level=0)")
	default:
		return "", fmt.Errorf("invalid event type %q (want error, warning, or information)", opts.Type)
	}

	if opts.EventID < 0 {
		return "", fmt.Errorf("invalid event id %d", opts.EventID)
	}
	if opts.EventID > 0 {
		conds = append(conds, fmt.Sprintf("EventID=%d", opts.EventID))
	}

	if opts.Minutes < 0 {
		return "", fmt.Errorf("invalid minutes %d", opts.Minutes)
	}
	if opts.Minutes > 0 {
		conds = append(conds, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", opts.Minutes*60*1000))
	}

	if len(conds) == 0 {
		return "*", nil
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]", nil
}

// normalizedEventLimit applies the default record cap.
func normalizedEventLimit(limit int) int {
	if limit <= 0 {
		return eventDefaultLimit
	}
	return limit
}

// parsedEvent is an EventRecord plus its EventRecordID — the per-log
// sequence number that keys the data/rendered merge. Not exported: the
// caller's surface is EventRecord.
type parsedEvent struct {
	EventRecord
	recordID int64
}

// stripEventRecords drops the merge key, yielding the caller-facing slice.
func stripEventRecords(recs []parsedEvent) []EventRecord {
	out := make([]EventRecord, len(recs))
	for i, r := range recs {
		out[i] = r.EventRecord
	}
	return out
}

// mergeRenderedMessages overlays the rendered pass's Message and Level onto
// the complete data set, matched by EventRecordID (stable per log). Records
// absent from the rendered set — the events /f:RenderedXml silently drops —
// keep their data-fallback message and numeric-fallback level. A log roll
// between the two passes can renumber records; a mismatched overlay then
// simply does not attach, never corrupts.
func mergeRenderedMessages(recs, rendered []parsedEvent) {
	byID := make(map[int64]parsedEvent, len(rendered))
	for _, r := range rendered {
		byID[r.recordID] = r
	}
	for i := range recs {
		r, ok := byID[recs[i].recordID]
		if !ok {
			continue
		}
		if r.Message != "" {
			recs[i].Message = r.Message
		}
		if r.Level != "" {
			recs[i].Level = r.Level
		}
	}
}

// filterEventRecords applies the client-side Contains filter and truncates
// to the (normalized) limit. wevtutil already returned newest-first
// (/rd:true), and filtering preserves that order. With no Contains set the
// server-side /c count already enforces the limit, so records pass through.
func filterEventRecords(recs []EventRecord, opts EventQuery) []EventRecord {
	limit := normalizedEventLimit(opts.Limit)
	if opts.Contains == "" {
		if len(recs) > limit {
			return recs[:limit]
		}
		return recs
	}
	needle := strings.ToLower(opts.Contains)
	out := make([]EventRecord, 0, limit)
	for _, r := range recs {
		if !strings.Contains(strings.ToLower(r.Message), needle) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out
}

// validateEventLogName rejects names that would break out of the double
// quotes eventQueryCommands wraps the log name in (cmd /C context): a quote
// closes the argument, '%' triggers cmd variable expansion even inside
// quotes. Control characters would corrupt the task XML Exec builds.
func validateEventLogName(name string) error {
	if name == "" {
		return fmt.Errorf("no event log name given")
	}
	if strings.ContainsAny(name, `"%`) {
		return fmt.Errorf("invalid event log name %q (quote and %% are not allowed)", name)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("invalid event log name %q (control characters are not allowed)", name)
		}
	}
	return nil
}

// parseEventLogList parses `wevtutil el` output: one log name per line,
// CRLF-terminated, possibly with blank lines.
func parseEventLogList(out string) []string {
	var logs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line = strings.TrimSpace(line); line != "" {
			logs = append(logs, line)
		}
	}
	return logs
}

// wevtutilEvents mirrors the document wevtutil emits with /f:xml or
// /f:RenderedXml plus /e:Events: one <Events> root holding one <Event> per
// record. The schema is MS-EVEN6's event XSD (namespace
// .../win/2004/08/events/event); encoding/xml matches struct tags on local
// names, so the namespace needs no handling. Only the fields anvil reports
// are mapped.
type wevtutilEvents struct {
	Events []wevtutilEvent `xml:"Event"`
}

// wevtutilEvent mirrors one <Event>: <System> carries the machine-generated
// header (provider, id, numeric level, UTC timestamp, record id),
// <RenderingInfo> the localized renderings (present only in the
// /f:RenderedXml pass, and only for events whose provider message file
// loads), <EventData> the raw substitution values (the message fallback).
type wevtutilEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       int `xml:"EventID"`
		Level         int `xml:"Level"`
		EventRecordID int64
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo *struct {
		Message string `xml:"Message"`
		Level   string `xml:"Level"`
	} `xml:"RenderingInfo"`
}

// parseEventXML parses one wevtutil XML pass into records, keeping the
// document order (wevtutil already emitted newest-first under /rd:true).
// The output is sanitized to valid UTF-8 first: rendered messages arrive in
// the console codepage, and a Security-log message carrying a CP1252 high
// byte (accented account names, smart quotes) is not valid UTF-8 — proven
// on the wire against the lab DC, where encoding/xml rejected the document
// with "invalid UTF-8". The replacement rune only touches those bytes.
func parseEventXML(out string) ([]parsedEvent, error) {
	var doc wevtutilEvents
	if err := xml.Unmarshal([]byte(strings.ToValidUTF8(out, "�")), &doc); err != nil {
		return nil, err
	}
	recs := make([]parsedEvent, 0, len(doc.Events))
	for _, e := range doc.Events {
		rec := parsedEvent{
			EventRecord: EventRecord{
				ID:          e.System.EventID,
				Source:      e.System.Provider.Name,
				TimeCreated: parseEventDate(e.System.TimeCreated.SystemTime),
			},
			recordID: e.System.EventRecordID,
		}
		if e.RenderingInfo != nil {
			rec.Level = e.RenderingInfo.Level
			rec.Message = strings.TrimSpace(e.RenderingInfo.Message)
		}
		if rec.Level == "" {
			rec.Level = eventLevelName(e.System.Level)
		}
		if rec.Message == "" {
			rec.Message = eventDataMessage(e)
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// eventDataMessage renders the EventData substitution values as
// "Name=value" pairs (bare values when unnamed) — the message for events
// wevtutil could not render.
func eventDataMessage(e wevtutilEvent) string {
	parts := make([]string, 0, len(e.EventData.Data))
	for _, d := range e.EventData.Data {
		if d.Name != "" {
			parts = append(parts, d.Name+"="+d.Value)
		} else {
			parts = append(parts, d.Value)
		}
	}
	return strings.Join(parts, ", ")
}

// eventLevelName maps the numeric System.Level when RenderingInfo carries
// no localized name (winmeta values: 1 Critical ... 5 Verbose; 0 is "level
// not set" and renders as Information — Security audit events are level 0).
func eventLevelName(level int) string {
	switch level {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 5:
		return "Verbose"
	default: // 0 and 4
		return "Information"
	}
}

// eventDateLayouts are tried in order. The XML SystemTime is always UTC
// ("...Z", RFC3339Nano — the 7-digit fraction parses under .999999999);
// the no-zone layout is a defensive fallback.
var eventDateLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
}

// parseEventDate parses the SystemTime attribute. Unparseable dates yield
// the zero time — a record with an unknown timestamp is still a valid
// record.
func parseEventDate(s string) time.Time {
	for _, layout := range eventDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// eventlogError inspects wevtutil's merged stderr/stdout and maps its known
// failure strings to plain-language messages (themed-errors idiom,
// feature-local). Returns nil when the output shows no failure. Callers run
// this only when the output is not the expected success shape (no logs
// listed / not XML): a real event message may itself contain phrases like
// "access is denied", so this must never run on successful parses.
func eventlogError(out, logName string) error {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil
	}
	low := strings.ToLower(trimmed)
	switch {
	case strings.Contains(low, "could not be found"):
		// "Failed to open event query. The specified channel could not be
		// found." — unknown log name.
		return fmt.Errorf("event log %q not found on the target", logName)
	case strings.Contains(low, "access is denied"):
		return fmt.Errorf("access denied reading the event log (admin required)")
	case strings.Contains(low, "parameter is incorrect"),
		strings.Contains(low, "not valid"):
		// "Failed to open event query. The parameter is incorrect." is how
		// wevtutil reports a rejected XPath.
		return fmt.Errorf("wevtutil rejected the query (invalid XPath)")
	case strings.Contains(low, "failed"), strings.Contains(low, "error"):
		// Unknown failure — surface wevtutil's own first line for diagnosis.
		first, _, _ := strings.Cut(trimmed, "\n")
		return fmt.Errorf("wevtutil failed: %s", strings.TrimRight(first, "\r"))
	}
	return nil
}

// emitEventWarnings surfaces Exec cleanup leftovers as warm warnings. The
// eventlog API returns no warnings slice (data + error only), and a
// leftover artifact must never pass silently (cleanup-and-verify rule), so
// the rare failure prints here instead of travelling the return value.
func emitEventWarnings(warnings []string) {
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
}
