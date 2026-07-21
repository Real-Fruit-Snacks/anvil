package shell

// Shell commands for the slinger-inspired feature set: service control,
// task management, server time, registry writes + portfwd, procs, find,
// resumable downloads, eventlog, enumpipes, changes, ping/reconnect, and
// the `!` local-shell escape. Conventions mirror shell.go: session methods
// return data, the shell prints via internal/ui, recoverable failures go
// through opError.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"anvil/internal/smbclient"
	"anvil/internal/track"
	"anvil/internal/ui"
)

// ensureWinreg lazily starts the target's RemoteRegistry service the first
// time a winreg consumer needs it; the restore closure runs at shell exit
// (shutdown) so the service returns to its prior state. On Samba and
// default Windows it is already running, making this a no-op. Failures are
// non-fatal by design: a non-admin session can't even query the service
// config on some targets, but the command that follows must be allowed to
// produce its own (themed) result rather than being blocked up front.
func (s *shell) ensureWinreg() bool {
	if s.rrRestore != nil {
		return true
	}
	restore, err := s.sess.EnsureRemoteRegistry()
	if err != nil {
		ui.Debugf("ensure RemoteRegistry: %v (continuing anyway)", err)
		return true
	}
	s.rrRestore = restore
	return true
}

// trackOp records one attempted remote mutation in the change tracker.
func (s *shell) trackOp(cat track.Category, action, target, detail string, err error) {
	st := track.StatusSuccess
	if err != nil {
		st = track.StatusFailed
	}
	s.tracker.Record(cat, action, target, detail, st)
}

// cmdSvc controls Windows services: svc <start|stop|config> <name> [type].
func (s *shell) cmdSvc(args []string) {
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: svc <start|stop|config> <name> [disabled|demand|auto]"))
		return
	}
	op, name := strings.ToLower(args[0]), args[1]
	var err error
	switch op {
	case "start":
		err = s.sess.StartService(name)
		if err == nil {
			ui.Faint.Printf("  %s started\n", name)
		}
	case "stop":
		err = s.sess.StopService(name)
		if err == nil {
			ui.Faint.Printf("  %s stopped\n", name)
		}
	case "config":
		if len(args) >= 3 {
			st, perr := smbclient.ParseServiceStartType(args[2])
			if perr != nil {
				fmt.Printf("  %s\n", ui.Muted.Sprint("start type must be disabled, demand, or auto"))
				return
			}
			err = s.sess.SetServiceStartType(name, st)
			if err == nil {
				ui.Faint.Printf("  %s start type set to %s\n", name, st)
			}
			s.trackOp(track.CategoryService, "config", name, "start type "+st.String(), err)
			if err != nil {
				s.opError(err)
			}
			return
		}
		cfg, cerr := s.sess.GetServiceConfig(name)
		if cerr != nil {
			s.opError(cerr)
			return
		}
		fmt.Printf("  %-24s %-10s %s\n", cfg.Name, cfg.StartType, cfg.StateString())
		return
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: svc <start|stop|config> <name> [disabled|demand|auto]"))
		return
	}
	s.trackOp(track.CategoryService, op, name, "", err)
	if err != nil {
		s.opError(err)
	}
}

// cmdTasks manages scheduled tasks: tasks | taskshow|taskrun|taskdel <path>.
func (s *shell) cmdTasks(args []string) {
	if len(args) == 0 {
		tasks, err := s.sess.EnumTasks()
		if err != nil {
			s.opError(err)
			return
		}
		ui.Muted.Printf("  %-52s %-10s %s\n", "PATH", "STATE", "ENABLED")
		for _, t := range tasks {
			state := t.State
			if !t.Enabled {
				state = ui.Faint.Sprint(state)
			}
			fmt.Printf("  %-52s %-10s %v\n", t.Path, state, t.Enabled)
		}
		ui.Faint.Printf("  %d tasks\n", len(tasks))
		return
	}
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: tasks | taskshow <path> | taskrun <path> | taskdel <path>"))
		return
	}
	op, path := strings.ToLower(args[0]), args[1]
	switch op {
	case "taskshow":
		xml, err := s.sess.GetTask(path)
		if err != nil {
			s.opError(err)
			return
		}
		fmt.Println(xml)
	case "taskrun":
		err := s.sess.RunTask(path)
		s.trackOp(track.CategoryTask, "run", path, "", err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  ran %s\n", path)
	case "taskdel":
		err := s.sess.DeleteTask(path)
		s.trackOp(track.CategoryTask, "delete", path, "", err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  deleted %s\n", path)
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: tasks | taskshow <path> | taskrun <path> | taskdel <path>"))
	}
}

// cmdTime prints the server's clock, zone offset, and uptime.
func (s *shell) cmdTime() {
	info, err := s.sess.ServerTimeInfo()
	if err != nil {
		s.opError(err)
		return
	}
	fmt.Printf("  %s  %s\n", ui.Muted.Sprint("TIME"), info.Time.Format("2006-01-02 15:04:05 -0700"))
	fmt.Printf("  %s  %s\n", ui.Muted.Sprint("UPTIME"), info.Uptime.Round(time.Second))
}

// cmdPortfwd manages the PortProxy v4tov4 relay store.
func (s *shell) cmdPortfwd(args []string) {
	if !s.ensureWinreg() {
		return
	}
	op := "list"
	if len(args) >= 1 {
		op = strings.ToLower(args[0])
	}
	switch op {
	case "list":
		rules, err := s.sess.PortFwdList()
		if err != nil {
			s.opError(err)
			return
		}
		if len(rules) == 0 {
			ui.Faint.Println("  no portfwd rules")
			return
		}
		for _, r := range rules {
			fmt.Printf("  %s\n", r)
		}
	case "add":
		if len(args) < 3 {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: portfwd add <listen host:port> <connect host:port> [--activate]"))
			return
		}
		err := s.sess.PortFwdAdd(args[1], args[2])
		s.trackOp(track.CategoryRegistry, "portfwd add", args[1], "-> "+args[2], err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  rule added: %s -> %s\n", args[1], args[2])
		if hasFlag(args[3:], "--activate") {
			steps := s.sess.PortFwdActivate(args[2], listenPort(args[1]))
			s.printPortFwdSteps(steps, smbclient.PortFwdFirewallRuleName(args[1]), true)
		} else {
			ui.Faint.Println("  (active after iphlpsvc restart/reboot; persists until removed)")
		}
	case "remove":
		if len(args) < 2 {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: portfwd remove <listen host:port> [--deactivate]"))
			return
		}
		err := s.sess.PortFwdRemove(args[1])
		s.trackOp(track.CategoryRegistry, "portfwd remove", args[1], "", err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  rule removed: %s\n", args[1])
		if hasFlag(args[2:], "--deactivate") {
			steps := s.sess.PortFwdDeactivate(listenPort(args[1]))
			s.printPortFwdSteps(steps, smbclient.PortFwdFirewallRuleName(args[1]), false)
		}
	case "clear":
		n, err := s.sess.PortFwdClear()
		s.trackOp(track.CategoryRegistry, "portfwd clear", "v4tov4", fmt.Sprintf("%d rules", n), err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  removed %d rule(s)\n", n)
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: portfwd [list|add <l> <c>|remove <l>|clear]"))
	}
}

// printPortFwdSteps renders one PortFwdActivate/Deactivate step list in
// the portfwd contract form: one line per step, failures as warm
// warnings that never abort the session. ruleName (anv-portfwd-<port>)
// names the firewall rule; add selects the netsh form in the manual-fix
// hint. Mutating hops feed the change tracker.
func (s *shell) printPortFwdSteps(steps []smbclient.PortFwdStep, ruleName string, add bool) {
	for _, st := range steps {
		switch st.Name {
		case "ipv6 check":
			switch {
			case st.Err != nil:
				ui.Warm.Printf("  warning: ipv6 check failed (%v)\n", st.Err)
			case strings.HasPrefix(st.Detail, "DisabledComponents=0xff"):
				ui.Warm.Println("  warning: IPv6 disabled on target (DisabledComponents=0xff) — portproxy rules are inert")
			default:
				ui.Faint.Println("  ipv6 enabled")
			}
		case "firewall rule":
			verb, hint := "add", fmt.Sprintf("netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow protocol=TCP localport=%s", ruleName, strings.TrimPrefix(ruleName, "anv-portfwd-"))
			if !add {
				verb, hint = "delete", fmt.Sprintf("netsh advfirewall firewall delete rule name=\"%s\"", ruleName)
			}
			if st.Err != nil {
				ui.Warm.Printf("  warning: firewall rule failed (%v) — %s manually: %s\n", st.Err, verb, hint)
			} else {
				ui.Faint.Printf("  firewall %s\n", st.Detail)
			}
			s.trackOp(track.CategoryExec, "firewall "+verb, ruleName, "", st.Err)
		case "iphlpsvc restart":
			if st.Err != nil {
				ui.Warm.Printf("  warning: iphlpsvc restart failed (%v) — restart manually or reboot to activate\n", st.Err)
			} else {
				ui.Faint.Println("  iphlpsvc restarted — relay active")
			}
			s.trackOp(track.CategoryService, "restart", "iphlpsvc", "portfwd", st.Err)
		}
	}
}

// hasFlag reports whether args contains flag (case-insensitive).
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if strings.EqualFold(a, flag) {
			return true
		}
	}
	return false
}

// listenPort extracts the port from a listen host:port (a bare port is
// accepted too); 0 on garbage — PortFwdAdd already validated the pair.
func listenPort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		p = listen
	}
	port, _ := strconv.Atoi(p)
	return port
}

// cmdProcs lists processes via the registry performance hives (no WMI).
func (s *shell) cmdProcs() {
	if !s.ensureWinreg() {
		return
	}
	procs, err := s.sess.ListProcesses()
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %-7s %-7s %-32s %-9s %s\n", "PID", "PPID", "NAME", "HANDLES", "THREADS")
	for _, p := range procs {
		fmt.Printf("  %-7d %-7d %-32s %-9d %d\n", p.PID, p.PPID, p.Name, p.Handles, p.Threads)
	}
	ui.Faint.Printf("  %d processes\n", len(procs))
}

// cmdFind searches the current share recursively with filters.
func (s *shell) cmdFind(args []string) {
	opts := smbclient.FindOptions{Timeout: 60 * time.Second}
	start := ""
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch strings.ToLower(args[i]) {
		case "-name":
			opts.Name = next()
		case "-regex":
			opts.Regex = next()
		case "-i":
			opts.CaseInsensitive = true
		case "-size":
			opts.Size = next()
		case "-newer":
			opts.NewerDays, _ = strconv.Atoi(next())
		case "-older":
			opts.OlderDays, _ = strconv.Atoi(next())
		case "-type":
			opts.Type = next()
		case "-maxdepth":
			opts.MaxDepth, _ = strconv.Atoi(next())
		case "-limit":
			opts.Limit, _ = strconv.Atoi(next())
		case "-timeout":
			d, _ := time.ParseDuration(next())
			if d > 0 {
				opts.Timeout = d
			}
		default:
			if start == "" && !strings.HasPrefix(args[i], "-") {
				start = args[i]
			} else {
				fmt.Printf("  %s\n", ui.Muted.Sprintf("unexpected argument %q", args[i]))
				return
			}
		}
	}
	results, err := s.sess.Find(start, opts)
	for _, r := range results {
		size := "       -"
		if !r.IsDir {
			size = fmt.Sprintf("%8d", r.Size)
		}
		mark := ""
		if r.IsDir {
			mark = "/"
		}
		fmt.Printf("  %s  %s%s\n", size, r.Path, mark)
	}
	if err != nil {
		if err == smbclient.ErrFindTimeout {
			ui.Warm.Printf("  warning: walk timeout after %d results (partial)\n", len(results))
			return
		}
		s.opError(err)
		return
	}
	ui.Faint.Printf("  %d results\n", len(results))
}

// cmdDownload pulls a file with resumable progress.
func (s *shell) cmdDownload(args []string) {
	var opts smbclient.DownloadOptions
	var paths []string
	for _, a := range args {
		switch strings.ToLower(a) {
		case "--resume":
			opts.Resume = true
		case "--restart":
			opts.Restart = true
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: download <remote> <local> [--resume] [--restart]"))
		return
	}
	res, err := s.sess.Download(paths[0], paths[1], opts)
	if err != nil {
		s.opError(err)
		return
	}
	switch {
	case res.Done && res.Resumed:
		ui.Faint.Printf("  %s — resumed and completed %d bytes total (%d fetched now) in %s\n", paths[1], res.TotalSize, res.BytesWritten, res.Elapsed.Round(time.Millisecond))
	case res.Done:
		ui.Faint.Printf("  %s — %d bytes in %s\n", paths[1], res.TotalSize, res.Elapsed.Round(time.Millisecond))
	default:
		ui.Faint.Printf("  partial: %d/%d bytes — continue with download %s %s --resume\n", res.TotalSize-res.BytesWritten+res.BytesWritten, res.TotalSize, paths[0], paths[1])
	}
}

// cmdEventlog reads Windows event logs (wevtutil over the exec channel).
func (s *shell) cmdEventlog(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: eventlog list | eventlog query <log> [--minutes N] [--id N] [--type t] [--source s] [--contains x] [--limit n]"))
		return
	}
	switch strings.ToLower(args[0]) {
	case "list":
		logs, err := s.sess.EventLogList()
		if err != nil {
			s.opError(err)
			return
		}
		for _, l := range logs {
			fmt.Printf("  %s\n", l)
		}
		ui.Faint.Printf("  %d logs\n", len(logs))
	case "query":
		if len(args) < 2 {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: eventlog query <log> [filters]"))
			return
		}
		var q smbclient.EventQuery
		for i := 2; i < len(args); i++ {
			next := func() string {
				if i+1 < len(args) {
					i++
					return args[i]
				}
				return ""
			}
			switch strings.ToLower(args[i]) {
			case "--minutes":
				q.Minutes, _ = strconv.Atoi(next())
			case "--id":
				q.EventID, _ = strconv.Atoi(next())
			case "--type":
				q.Type = next()
			case "--source":
				q.Source = next()
			case "--contains":
				q.Contains = next()
			case "--limit":
				q.Limit, _ = strconv.Atoi(next())
			default:
				fmt.Printf("  %s\n", ui.Muted.Sprintf("unexpected argument %q", args[i]))
				return
			}
		}
		records, err := s.sess.EventLogQuery(args[1], q)
		if err != nil {
			s.opError(err)
			return
		}
		for _, r := range records {
			fmt.Printf("  %s  %-12s %-28s %d\n", r.TimeCreated.Format("01-02 15:04:05"), r.Level, r.Source, r.ID)
			msg := r.Message
			if i := strings.Index(msg, "\n"); i >= 0 {
				msg = msg[:i]
			}
			if len(msg) > 110 {
				msg = msg[:110] + "…"
			}
			ui.Faint.Printf("    %s\n", msg)
		}
		ui.Faint.Printf("  %d events\n", len(records))
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: eventlog list | eventlog query <log> [filters]"))
	}
}

// cmdChanges shows, saves, or clears the session's write-op audit trail.
func (s *shell) cmdChanges(args []string) {
	for _, a := range args {
		switch strings.ToLower(a) {
		case "--save":
			path, err := track.DefaultPath()
			if err != nil {
				s.opError(err)
				return
			}
			if err := s.tracker.SaveJSON(path); err != nil {
				s.opError(err)
				return
			}
			ui.Faint.Printf("  changes saved to %s\n", path)
		case "--clear":
			s.tracker.Clear()
			ui.Faint.Println("  changes cleared")
		default:
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: changes [--save] [--clear]"))
			return
		}
	}
	if len(args) == 0 || args[len(args)-1] == "--clear" {
		return
	}
	if s.tracker.Count() == 0 {
		ui.Faint.Println("  no changes recorded")
		return
	}
	ui.Muted.Printf("  %-19s %-9s %-8s %-24s %s\n", "TIME", "CATEGORY", "STATUS", "TARGET", "ACTION")
	for _, e := range s.tracker.Entries() {
		status := ui.Accent.Sprint(string(e.Status))
		if e.Status == track.StatusFailed {
			status = ui.Warm.Sprint(string(e.Status))
		}
		fmt.Printf("  %-19s %-9s %-8s %-24s %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Category, status, e.Target, e.Action)
	}
}

// cmdEnumPipes enumerates and categorizes named pipes.
func (s *shell) cmdEnumPipes() {
	pipes, err := s.sess.EnumPipes()
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %-16s %-40s %s\n", "CATEGORY", "NAME", "NOTE")
	for _, p := range pipes {
		cat := p.Category
		if cat == "unknown" {
			cat = ui.Faint.Sprint(cat)
		}
		fmt.Printf("  %-16s %-40s %s\n", cat, p.Name, ui.Faint.Sprint(p.Note))
	}
	ui.Faint.Printf("  %d pipes\n", len(pipes))
}

// cmdPing probes session liveness.
func (s *shell) cmdPing() {
	if err := s.sess.Ping(); err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Println("  session alive")
}

// cmdReconnect re-dials with the original connect parameters and
// re-attaches the previously selected share.
func (s *shell) cmdReconnect() {
	if err := s.sess.Reconnect(); err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Println("  reconnected")
}

// cmdBang runs a local command (`! <cmd...>`) or re-executes a history
// entry (`!<n>`).
func (s *shell) cmdBang(line string) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "!"))
	if rest == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: ! <local command> | !<n> (re-run history entry n)"))
		return
	}
	if n, err := strconv.Atoi(rest); err == nil {
		if n < 1 || n > len(s.history) || s.bangDepth > 2 {
			fmt.Printf("  %s\n", ui.Muted.Sprintf("no such history entry: %d", n))
			return
		}
		target := s.history[n-1]
		ui.Faint.Printf("  ! %s\n", target)
		s.bangDepth++
		code, _ := s.dispatch(target, splitArgs(target))
		s.bangDepth--
		_ = code
		return
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", rest)
	} else {
		cmd = exec.Command("sh", "-c", rest)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		ui.PrintErr(fmt.Sprintf("local command failed: %v", err))
	}
}

// cmdRegSet writes a registry value: reg set <key> <value> <type> <data>.
func (s *shell) cmdRegSet(args []string) {
	if len(args) < 4 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: reg set <key> <value> <type> <data> (types: REG_SZ, REG_EXPAND_SZ, REG_BINARY hex, REG_DWORD, REG_QWORD, REG_MULTI_SZ a|b|c)"))
		return
	}
	valType, err := smbclient.RegTypeFromName(args[2])
	if err != nil {
		fmt.Printf("  %s\n", ui.Muted.Sprint("unknown type — use REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, or REG_MULTI_SZ"))
		return
	}
	err = s.sess.RegSetValue(args[0], args[1], valType, args[3])
	s.trackOp(track.CategoryRegistry, "set", args[0], args[1], err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  set %s\\%s (%s)\n", args[0], args[1], smbclient.RegTypeName(valType))
}

// cmdRegDelValue deletes a registry value.
func (s *shell) cmdRegDelValue(args []string) {
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: reg delvalue <key> <value>"))
		return
	}
	err := s.sess.RegDeleteValue(args[0], args[1])
	s.trackOp(track.CategoryRegistry, "delvalue", args[0], args[1], err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  deleted %s\\%s\n", args[0], args[1])
}

// cmdRegCreateKey creates a registry key (and missing parents).
func (s *shell) cmdRegCreateKey(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: reg createkey <key>"))
		return
	}
	err := s.sess.RegCreateKey(args[0])
	s.trackOp(track.CategoryRegistry, "createkey", args[0], "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  created %s\n", args[0])
}

// cmdRegDelKey deletes a registry key (must have no subkeys).
func (s *shell) cmdRegDelKey(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: reg delkey <key>"))
		return
	}
	err := s.sess.RegDeleteKey(args[0])
	s.trackOp(track.CategoryRegistry, "delkey", args[0], "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  deleted %s\n", args[0])
}

// cmdRegSearch searches key/value names under a root, depth/limit bounded.
func (s *shell) cmdRegSearch(args []string) {
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: reg search <root> <pattern> [maxdepth] [limit]"))
		return
	}
	depth, limit := 5, 100
	if len(args) >= 3 {
		depth, _ = strconv.Atoi(args[2])
	}
	if len(args) >= 4 {
		limit, _ = strconv.Atoi(args[3])
	}
	hits, err := s.sess.RegSearch(args[0], args[1], depth, limit)
	if err != nil {
		s.opError(err)
		return
	}
	for _, h := range hits {
		if h.ValueName == "" {
			fmt.Printf("  %s\n", h.Path)
		} else {
			fmt.Printf("  %s  %s %s\n", h.Path, ui.Faint.Sprint(h.ValueName), ui.Faint.Sprint(smbclient.RegTypeName(h.ValueType)))
		}
	}
	ui.Faint.Printf("  %d hits\n", len(hits))
}
