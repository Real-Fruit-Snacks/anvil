package smbclient

import "strings"

// Known-pipe database for EnumPipes. Two layers, checked in order:
//
//  1. knownPipes — exact pipe names (lowercase, relative to \pipe\, '\'
//     separated). These are pipes that exist verbatim on real systems:
//     the core Windows RPC set (verified against Server 2022 IPC$
//     listings), well-known third-party services, and recon-relevant
//     coercion targets.
//  2. pipeHeuristics — ordered substring rules for the long tail:
//     instance-named pipes (MSSQL$<name>\sql\query), vendor product
//     families, and dynamic pipes (crashpad_*, Winsock2\...). First
//     matching rule wins, so specific rules precede generic ones
//     ("sapdb" before "sap", "mssql$" before "sql").
//
// Anything unmatched is reported as category "unknown" with an empty
// note — that is a normal outcome, not an error (app-specific and
// randomly-named pipes are common on workstations).

// Pipe categories. Category boundaries follow the pipe's purpose to an
// operator: "admin" is a remote-management RPC interface, "system" is
// core OS/runtime IPC, "file" is file access/sync, "web" covers browsers
// and web servers, "terminal" is remote-control/RDP-style access.
const (
	catUnknown  = "unknown"
	catAdmin    = "admin"
	catFile     = "file"
	catSystem   = "system"
	catDatabase = "database"
	catSecAV    = "security-av"
	catTerminal = "terminal"
	catWeb      = "web"
	catVirt     = "virtualization"
	catDevOps   = "devops"
	catBackup   = "backup"
)

// pipeCategories is the valid-category set the DB is checked against in
// tests (every entry must use one of these).
var pipeCategories = []string{
	catAdmin, catFile, catSystem, catDatabase, catSecAV,
	catTerminal, catWeb, catVirt, catDevOps, catBackup, catUnknown,
}

// knownPipe is one exact pipe name in the database.
type knownPipe struct {
	name     string // lowercase, relative to \pipe\
	category string
	note     string
}

// knownPipes holds exact-name entries. Names are lowercase; matching is
// case-insensitive via normalizePipeName.
var knownPipes = []knownPipe{
	// --- Remote administration RPC interfaces -------------------------------
	{"svcctl", catAdmin, "Service Control Manager (remote service management)"},
	{"atsvc", catAdmin, "Task Scheduler, legacy ATSvc interface (MS-TSCH)"},
	{"tsch", catAdmin, "Task Scheduler (ITaskSchedulerService)"},
	{"winreg", catAdmin, "Remote Registry (MS-RRP)"},
	{"eventlog", catAdmin, "Event Log remoting (MS-EVEN)"},
	{"spoolss", catAdmin, "Print Spooler (MS-RPRN; PrinterBug coercion target)"},
	{"samr", catAdmin, "Security Account Manager (user/group management)"},
	{"wkssvc", catAdmin, "Workstation service (host/session info)"},
	{"netlogon", catAdmin, "Netlogon domain authentication channel"},
	{"lsarpc", catAdmin, "LSA policy and secrets management (MS-LSAD)"},
	{"efsrpc", catAdmin, "Encrypting File System RPC (MS-EFSR; PetitPotam coercion target)"},
	{"drsuapi", catAdmin, "Directory replication (MS-DRSR; DCSync interface)"},
	{"trkwks", catAdmin, "Distributed Link Tracking management"},
	{"psexesvc", catAdmin, "PsExec service control pipe"},
	{"cert", catAdmin, "AD Certificate Services enrollment (MS-ICPR)"},
	{"router", catAdmin, "Routing and Remote Access management (MS-RRASM)"},

	// --- Core OS / runtime --------------------------------------------------
	{"lsass", catSystem, "Local Security Authority (authentication, secrets)"},
	{"ntsvcs", catSystem, "Plug-and-Play / service control RPC"},
	{"scerpc", catSystem, "Security Configuration Engine (GPO, security templates)"},
	{"epmapper", catSystem, "RPC endpoint mapper over SMB"},
	{"initshutdown", catSystem, "System shutdown/initiation"},
	{"lsm_api_service", catSystem, "Local Session Manager"},
	{"w32time_alt", catSystem, "Windows Time service"},
	{"browser", catSystem, "Computer Browser service (legacy)"},
	{"protected_storage", catSystem, "Protected Storage (legacy XP/2003)"},
	{"msgsvcsend", catSystem, "Messenger service (legacy XP/2003)"},
	{"openssh-ssh-agent", catSystem, "OpenSSH authentication agent"},
	{"gpg-agent", catSystem, "GnuPG agent"},
	{`openvpn\service`, catSystem, "OpenVPN interactive service"},

	// --- File services ------------------------------------------------------
	{"srvsvc", catFile, "Server service (shares, sessions, file access)"},
	{"netdfs", catFile, "Distributed File System namespace management"},
	{"dav rpc service", catFile, "WebDAV client (WebClient; coercion-relevant)"},

	// --- Databases ----------------------------------------------------------
	{`sql\query`, catDatabase, "Microsoft SQL Server (default instance)"},
	{`microsoft##wid\tsql\query`, catDatabase, "Windows Internal Database (WSUS/ADFS)"},
	{"mysql", catDatabase, "MySQL / MariaDB"},

	// --- Security / AV products ---------------------------------------------
	{"csfalconservice", catSecAV, "CrowdStrike Falcon sensor"},
	{"osquery.em", catSecAV, "osquery extension socket"},
	{"vgc", catSecAV, "Riot Vanguard anti-cheat (Valorant)"},

	// --- Terminal / remote control ------------------------------------------
	{"hydralspipe", catTerminal, "Terminal Services listener (legacy Hydra pipe)"},
	{"termsrv_api_service", catTerminal, "Terminal Services API"},
	{"sessenvpublicrpc", catTerminal, "Remote Desktop SessionEnv RPC"},
	{"ctx_winstation_api_service", catTerminal, "Citrix/Terminal Services WinStation API"},
	{"dntus26", catTerminal, "DameWare NT Utilities remote control"},

	// --- Virtualization -----------------------------------------------------
	{"vmware-authdpipe", catVirt, "VMware authentication daemon"},
	{"vgauth-service", catVirt, "VMware Tools Guest Authentication"},

	// --- DevOps -------------------------------------------------------------
	{"docker_engine", catDevOps, "Docker Engine API"},
	{"containerd-containerd", catDevOps, "containerd runtime"},
}

// pipeHeuristic is an ordered substring rule for names not in knownPipes.
type pipeHeuristic struct {
	substr   string // lowercase substring to match
	category string
	note     string
}

// pipeHeuristics: first match wins; keep specific rules above generic
// ones. Notes describe the product family the rule points at.
var pipeHeuristics = []pipeHeuristic{
	// Databases (instance-named SQL Server pipes first).
	{"mssql$", catDatabase, "Microsoft SQL Server (named instance)"},
	{"sapdb", catDatabase, "SAP MaxDB"},
	{"maxdb", catDatabase, "SAP MaxDB"},
	{"pgsql", catDatabase, "PostgreSQL"},
	{"postgres", catDatabase, "PostgreSQL"},
	{"sql", catDatabase, "SQL-based database"},
	{"mariadb", catDatabase, "MariaDB"},
	{"oracle", catDatabase, "Oracle Database"},
	{"extproc", catDatabase, "Oracle external procedures"},
	{"orapipe", catDatabase, "Oracle TNS named-pipe listener"},
	{"mongo", catDatabase, "MongoDB"},
	{"redis", catDatabase, "Redis/Memurai"},
	{"db2", catDatabase, "IBM Db2"},
	{"sybase", catDatabase, "SAP Sybase ASE"},
	{"informix", catDatabase, "IBM Informix"},
	{"firebird", catDatabase, "Firebird"},

	// Security / AV.
	{"crowdstrike", catSecAV, "CrowdStrike Falcon"},
	{"falcon", catSecAV, "CrowdStrike Falcon sensor"},
	{"sophos", catSecAV, "Sophos endpoint"},
	{"mcafee", catSecAV, "McAfee/Trellix endpoint"},
	{"trellix", catSecAV, "Trellix (McAfee) endpoint"},
	{"symantec", catSecAV, "Symantec/Broadcom endpoint"},
	{"trendmicro", catSecAV, "Trend Micro endpoint"},
	{"carbonblack", catSecAV, "Carbon Black sensor"},
	{"confer", catSecAV, "Carbon Black (confer) sensor"},
	{"sentinelone", catSecAV, "SentinelOne agent"},
	{"cylance", catSecAV, "Cylance endpoint"},
	{"cybereason", catSecAV, "Cybereason sensor"},
	{"tanium", catSecAV, "Tanium client"},
	{"qualys", catSecAV, "Qualys agent"},
	{"rapid7", catSecAV, "Rapid7 agent"},
	{"osquery", catSecAV, "osquery"},
	{"elastic-endpoint", catSecAV, "Elastic Defend endpoint"},

	// Virtualization.
	{"vmware", catVirt, "VMware component"},
	{"vgauth", catVirt, "VMware Tools GuestAuth"},
	{"vbox", catVirt, "VirtualBox"},
	{"vmms", catVirt, "Hyper-V Management"},
	{"vmcompute", catVirt, "Hyper-V Host Compute"},
	{"hyper-v", catVirt, "Hyper-V"},
	{"hyperv", catVirt, "Hyper-V"},
	{"xen", catVirt, "Citrix Xen"},
	{"qemu", catVirt, "QEMU/KVM guest"},
	{"proxmox", catVirt, "Proxmox guest agent"},
	{"wsl", catVirt, "Windows Subsystem for Linux"},

	// Terminal / remote control.
	{"winstation", catTerminal, "Terminal/Citrix WinStation"},
	{"termsrv", catTerminal, "Terminal Services"},
	{"hydra", catTerminal, "Terminal Services (Hydra)"},
	{"citrix", catTerminal, "Citrix Virtual Apps"},
	{"vnc", catTerminal, "VNC remote control"},
	{"screenconnect", catTerminal, "ConnectWise ScreenConnect"},
	{"teamviewer", catTerminal, "TeamViewer"},
	{"anydesk", catTerminal, "AnyDesk"},
	{"logmein", catTerminal, "LogMeIn"},
	{"splashtop", catTerminal, "Splashtop"},
	{"dameware", catTerminal, "DameWare remote control"},

	// Web (browsers — Chromium's crashpad_*/mojo.* pipes are the most
	// common third-party pipes on workstations — and web servers).
	{"crashpad", catWeb, "Chromium crash handler (browser/Electron app)"},
	{"mojo.", catWeb, "Chromium Mojo IPC"},
	{"chrome", catWeb, "Chromium-based browser"},
	{"msedge", catWeb, "Microsoft Edge"},
	{"firefox", catWeb, "Mozilla Firefox"},
	{"mozilla", catWeb, "Mozilla product"},
	{"brave", catWeb, "Brave browser"},
	{"iisipm", catWeb, "IIS process manager (app pool)"},
	{"iisadmin", catWeb, "IIS admin service"},
	{"rpcproxy", catWeb, "RPC over HTTP proxy (RpcProxy)"},
	{"nginx", catWeb, "nginx"},
	{"apache", catWeb, "Apache httpd"},
	{"httpd", catWeb, "Apache httpd"},
	{"tomcat", catWeb, "Apache Tomcat"},
	{"jetty", catWeb, "Jetty"},
	{"haproxy", catWeb, "HAProxy"},

	// DevOps.
	{"docker", catDevOps, "Docker"},
	{"containerd", catDevOps, "containerd"},
	{"vpnkit", catDevOps, "Docker Desktop networking (vpnkit)"},
	{"kubelet", catDevOps, "Kubernetes kubelet"},
	{"jenkins", catDevOps, "Jenkins agent"},
	{"gitlab", catDevOps, "GitLab runner"},
	{"teamcity", catDevOps, "TeamCity agent"},
	{"octopus", catDevOps, "Octopus Deploy Tentacle"},
	{"puppet", catDevOps, "Puppet agent"},
	{"chef", catDevOps, "Chef Infra client"},
	{"ansible", catDevOps, "Ansible"},
	{"salt", catDevOps, "Salt minion"},
	{"vagrant", catDevOps, "Vagrant"},
	{"consul", catDevOps, "HashiCorp Consul"},
	{"nomad", catDevOps, "HashiCorp Nomad"},
	{"rancher", catDevOps, "Rancher"},
	{"azuredevops", catDevOps, "Azure DevOps agent"},
	{"vsts", catDevOps, "Azure DevOps (VSTS) agent"},

	// Backup agents.
	{"veeam", catBackup, "Veeam Backup"},
	{"backupexec", catBackup, "Veritas Backup Exec"},
	{"beremote", catBackup, "Backup Exec remote agent"},
	{"netbackup", catBackup, "Veritas NetBackup"},
	{"commvault", catBackup, "Commvault"},
	{"simpana", catBackup, "Commvault (Simpana)"},
	{"arcserve", catBackup, "Arcserve backup"},
	{"acronis", catBackup, "Acronis backup"},
	{"rubrik", catBackup, "Rubrik agent"},
	{"cohesity", catBackup, "Cohesity agent"},
	{"macrium", catBackup, "Macrium Reflect"},
	{"duplicati", catBackup, "Duplicati"},
	{"datto", catBackup, "Datto backup agent"},
	{"backup", catBackup, "backup software (generic)"},

	// File sync clients.
	{"dropbox", catFile, "Dropbox sync client"},
	{"onedrive", catFile, "OneDrive sync client"},
	{"googledrive", catFile, "Google Drive sync"},
	{"nextcloud", catFile, "Nextcloud sync client"},
	{"syncthing", catFile, "Syncthing"},

	// Admin (enterprise apps and remote-admin tooling).
	{"sap", catAdmin, "SAP NetWeaver"},
	{"fipfs", catAdmin, "Exchange antimalware engine (FIP-FS)"},
	{"exchange", catAdmin, "Microsoft Exchange"},
	{"pshost", catAdmin, "PowerShell remoting host"},
	{"paexec", catAdmin, "PAExec remote admin"},

	// System (dynamic OS pipes).
	{"catalogchangelistener", catSystem, "Winsock catalog change listener (dynamic)"},
	{"pipe_eventroot", catSystem, "WMI event provider pipe"},
	{"w32posixpipe", catSystem, "OpenSSH for Windows server channel"},
	{"openvpn", catSystem, "OpenVPN"},
}

// knownPipeIndex maps normalized exact names to their DB entry.
var knownPipeIndex = func() map[string]knownPipe {
	m := make(map[string]knownPipe, len(knownPipes))
	for _, kp := range knownPipes {
		m[kp.name] = kp
	}
	return m
}()

// normalizePipeName folds a pipe name to its canonical match key:
// lowercase, forward slashes converted, leading backslashes stripped,
// and a leading "pipe\" segment removed (so both "samr" and
// "\pipe\samr" hit the same entry).
func normalizePipeName(name string) string {
	n := strings.ReplaceAll(name, "/", `\`)
	n = strings.TrimLeft(n, `\`)
	n = strings.ToLower(n)
	return strings.TrimPrefix(n, `pipe\`)
}

// categorizePipe classifies a pipe name against the known-pipe database:
// exact match first, then ordered heuristics, else "unknown" with an
// empty note.
func categorizePipe(name string) (category, note string) {
	n := normalizePipeName(name)
	if kp, ok := knownPipeIndex[n]; ok {
		return kp.category, kp.note
	}
	for _, h := range pipeHeuristics {
		if strings.Contains(n, h.substr) {
			return h.category, h.note
		}
	}
	return catUnknown, ""
}
