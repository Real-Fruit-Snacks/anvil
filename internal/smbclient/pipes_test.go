package smbclient

import (
	"strings"
	"testing"
)

func TestCategorizePipe(t *testing.T) {
	cases := []struct {
		name     string
		pipe     string
		wantCat  string
		wantNote string // "" means we only assert the category
	}{
		// Exact DB entries — the core Windows RPC set EnumPipes must
		// recognize on any DC.
		{"samr admin", "samr", catAdmin, ""},
		{"svcctl admin", "svcctl", catAdmin, ""},
		{"atsvc admin", "atsvc", catAdmin, ""},
		{"winreg admin", "winreg", catAdmin, ""},
		{"eventlog admin", "eventlog", catAdmin, ""},
		{"spoolss admin", "spoolss", catAdmin, ""},
		{"netlogon admin", "netlogon", catAdmin, ""},
		{"lsarpc admin", "lsarpc", catAdmin, ""},
		{"efsrpc admin", "efsrpc", catAdmin, ""},
		{"lsass system", "lsass", catSystem, ""},
		{"epmapper system", "epmapper", catSystem, ""},
		{"ntsvcs system", "ntsvcs", catSystem, ""},
		{"srvsvc file", "srvsvc", catFile, ""},
		{"netdfs file", "netdfs", catFile, ""},
		{"webdav file", "DAV RPC SERVICE", catFile, ""},
		{"sql default database", `sql\query`, catDatabase, ""},
		{"wid database", `microsoft##wid\tsql\query`, catDatabase, ""},
		{"mysql database", "MySQL", catDatabase, ""},
		{"crowdstrike secav", "CSFalconService", catSecAV, ""},
		{"osquery secav", "osquery.em", catSecAV, ""},
		{"termsrv terminal", "TermSrv_API_service", catTerminal, ""},
		{"psexec admin", "PSEXESVC", catAdmin, ""},
		{"docker devops", "docker_engine", catDevOps, ""},
		{"vmware authd virt", "vmware-authdpipe", catVirt, ""},

		// Case and path-prefix normalization.
		{"leading pipe prefix", `\pipe\SAMR`, catAdmin, ""},
		{"upper pipe prefix", `\PIPE\SvcCtl`, catAdmin, ""},
		{"mixed case sql", `\pipe\SQL\QUERY`, catDatabase, ""},

		// Heuristics.
		{"mssql instance", `MSSQL$SSEER\sql\query`, catDatabase, ""},
		{"oracle", "orapipe_main", catDatabase, ""},
		{"crashpad", "crashpad_1234_AABBCCDD", catWeb, ""},
		{"mojo", "mojo.1234.56.78", catWeb, ""},
		{"iis app pool", "iisipmAABBCCDD", catWeb, ""},
		{"veeam", "VeeamBackupAgent", catBackup, ""},
		{"generic backup", "acme-backup-svc", catBackup, ""},
		{"vmware", "vmware-foo", catVirt, ""},
		{"hyperv", "vmcompute-extra", catVirt, ""},
		{"jenkins", "jenkins-agent-1", catDevOps, ""},
		{"sophos", "sophos-router", catSecAV, ""},
		{"teamviewer", "TeamViewer11", catTerminal, ""},
		{"dropbox", "dropbox_pipe", catFile, ""},
		{"sap", "sapservice", catAdmin, ""},
		{"pshost", "PSHost.1.AABB.DefaultAppDomain.jdoe", catAdmin, ""},
		{"winsock listener", `Winsock2\CatalogChangeListener-1a2b-0`, catSystem, ""},

		// Unknown: category unknown, note empty.
		{"unknown random", "totally-random-pipe", catUnknown, ""},
		{"unknown app", "widget-svc-ipc", catUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, note := categorizePipe(c.pipe)
			if cat != c.wantCat {
				t.Errorf("categorizePipe(%q) category = %q, want %q", c.pipe, cat, c.wantCat)
			}
			if c.wantNote != "" && note != c.wantNote {
				t.Errorf("categorizePipe(%q) note = %q, want %q", c.pipe, note, c.wantNote)
			}
			if c.wantCat == catUnknown && note != "" {
				t.Errorf("categorizePipe(%q) unknown pipe has note %q, want empty", c.pipe, note)
			}
		})
	}
}

func TestNormalizePipeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"samr", "samr"},
		{"SAMR", "samr"},
		{`\pipe\samr`, "samr"},
		{`\PIPE\SAMR`, "samr"},
		{`\\pipe\SAMR`, "samr"},
		{`/pipe/srvsvc`, "srvsvc"},
		{`sql\query`, `sql\query`},
		{`SQL/QUERY`, `sql\query`},
		{`pipe\epmapper`, "epmapper"},
	}
	for _, c := range cases {
		if got := normalizePipeName(c.in); got != c.want {
			t.Errorf("normalizePipeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPipeNameFromBinding(t *testing.T) {
	cases := []struct {
		name    string
		binding string
		want    string
		wantOK  bool
	}{
		{"np with host", `ncacn_np:DC01[\pipe\lsass]`, "lsass", true},
		{"np without host", `ncacn_np:[\pipe\sql\query]`, `sql\query`, true},
		{"np case preserved", `ncacn_np:[\PIPE\SPOOLSS]`, "SPOOLSS", true},
		{"np forward slashes", `ncacn_np:[/pipe/winreg]`, "winreg", true},
		{"tcp rejected", "ncacn_ip_tcp:49671", "", false},
		{"tcp with bracket rejected", "ncacn_ip_tcp:192.0.2.10[49671]", "", false},
		{"lrpc rejected", "ncalrpc:[LRPC-123]", "", false},
		{"empty bracket rejected", "ncacn_np:HOST[]", "", false},
		{"bare pipe prefix rejected", `ncacn_np:[\pipe\]`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := pipeNameFromBinding(c.binding)
			if ok != c.wantOK {
				t.Fatalf("pipeNameFromBinding(%q) ok = %v, want %v", c.binding, ok, c.wantOK)
			}
			if got != c.want {
				t.Errorf("pipeNameFromBinding(%q) = %q, want %q", c.binding, got, c.want)
			}
		})
	}
}

// TestKnownPipeDBConsistency validates the database itself: no duplicate
// names, every category valid, notes present, names stored normalized.
func TestKnownPipeDBConsistency(t *testing.T) {
	valid := make(map[string]bool, len(pipeCategories))
	for _, c := range pipeCategories {
		valid[c] = true
	}

	seen := make(map[string]bool, len(knownPipes))
	for _, kp := range knownPipes {
		if kp.name == "" {
			t.Error("knownPipes entry with empty name")
		}
		if seen[kp.name] {
			t.Errorf("duplicate known-pipe name %q", kp.name)
		}
		seen[kp.name] = true
		if !valid[kp.category] {
			t.Errorf("known pipe %q: invalid category %q", kp.name, kp.category)
		}
		if kp.note == "" {
			t.Errorf("known pipe %q: empty note", kp.name)
		}
		if norm := normalizePipeName(kp.name); norm != kp.name {
			t.Errorf("known pipe %q: not stored normalized (normalizes to %q)", kp.name, norm)
		}
	}

	substrs := make(map[string]bool, len(pipeHeuristics))
	for _, h := range pipeHeuristics {
		if h.substr == "" {
			t.Error("heuristic with empty substr")
		}
		if substrs[h.substr] {
			t.Errorf("duplicate heuristic substr %q", h.substr)
		}
		substrs[h.substr] = true
		if !valid[h.category] {
			t.Errorf("heuristic %q: invalid category %q", h.substr, h.category)
		}
		if h.note == "" {
			t.Errorf("heuristic %q: empty note", h.substr)
		}
		if h.substr != strings.ToLower(h.substr) {
			t.Errorf("heuristic substr %q: not lowercase", h.substr)
		}
	}

	// A specific rule must precede any generic rule whose substring it
	// contains — first match wins, so "mssql$" before "sql", "sapdb"
	// before "sap". Reversed order silently shadows the specific note.
	for i := 0; i < len(pipeHeuristics); i++ {
		for j := i + 1; j < len(pipeHeuristics); j++ {
			if strings.Contains(pipeHeuristics[j].substr, pipeHeuristics[i].substr) {
				t.Errorf("heuristic %q (later) contains %q (earlier) — the earlier generic rule shadows it; reorder",
					pipeHeuristics[j].substr, pipeHeuristics[i].substr)
			}
		}
	}

	// The DB targets ~120 entries (exact + heuristic); guard against
	// accidental mass deletion.
	if total := len(knownPipes) + len(pipeHeuristics); total < 100 {
		t.Errorf("DB size = %d entries, want >= 100 (~120 target)", total)
	}
}

// TestExactMatchPrecedence: names matching both an exact entry and a
// heuristic (docker_engine vs "docker", sql\query vs "sql") must resolve
// to the exact entry — its note is the precise one.
func TestExactMatchPrecedence(t *testing.T) {
	cases := []struct {
		pipe     string
		wantCat  string
		wantNote string
	}{
		{"docker_engine", catDevOps, "Docker Engine API"},
		{`sql\query`, catDatabase, "Microsoft SQL Server (default instance)"},
		{"CSFalconService", catSecAV, "CrowdStrike Falcon sensor"},
	}
	for _, c := range cases {
		cat, note := categorizePipe(c.pipe)
		if cat != c.wantCat || note != c.wantNote {
			t.Errorf("categorizePipe(%q) = (%q, %q), want (%q, %q)", c.pipe, cat, note, c.wantCat, c.wantNote)
		}
	}
}
