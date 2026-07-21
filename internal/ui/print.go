package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	"anvil/internal/scan"
)

// PrintProfile renders a TargetProfile in the Terminal Workbench idiom:
// uppercase muted section labels, column-aligned key/value rows, blank line
// between sections.
func PrintProfile(p *scan.TargetProfile) {
	fmt.Printf("%s  %s\n", Muted.Sprint("TARGET"), p.Target)

	fmt.Println()
	printPorts(p.Ports)

	if p.SMB != nil {
		fmt.Println()
		printSMB(p.SMB)
	}
	if p.LDAP != nil {
		fmt.Println()
		printLDAP(p.LDAP)
	}
	if p.Kerberos != nil {
		fmt.Println()
		printKerberos(p.Kerberos)
	}
	if p.RPC != nil {
		fmt.Println()
		printRPC(p.RPC)
	}
	if p.NullSession != nil {
		fmt.Println()
		printNullSession(p.NullSession)
	}
	if p.TLS != nil {
		fmt.Println()
		printTLS(p.TLS)
	}
	if p.ADCS != nil {
		fmt.Println()
		printADCS(p.ADCS)
	}
	if len(p.Hints) > 0 {
		fmt.Println()
		printHints(p.Hints)
	}
}

func printPorts(ports []scan.PortResult) {
	closed := 0
	Muted.Printf("%-10s%-7s%s\n", "PORT", "STATE", "SERVICE")
	for _, r := range ports {
		if !r.Open {
			closed++
			continue
		}
		fmt.Printf("%s%s%s\n",
			Faint.Sprintf("%-10s", fmt.Sprintf("%d/tcp", r.Port)),
			Accent.Sprintf("%-7s", "open"),
			r.Service)
	}
	Faint.Printf("%d/%d closed\n", closed, len(ports))
}

func printSMB(s *scan.SMBInfo) {
	Muted.Println("SMB")
	if s.Error != "" {
		probeError(s.Error)
		return
	}
	kv("dialect", s.Dialect, nil)
	if s.SMB1Enabled {
		kv("smb1", "enabled", Warm)
	}
	if s.SigningRequired {
		kv("signing", "required", Accent)
	} else {
		kv("signing", "not required", Warm)
	}
	if s.OSVersion != "" {
		kv("os", s.OSVersion, nil)
	}
	if s.NBDomain != "" {
		kv("netbios dom", s.NBDomain, AccentAlt)
	}
	if s.NBComputer != "" {
		kv("netbios host", s.NBComputer, AccentAlt)
	}
	if s.DNSComputer != "" {
		kv("dns host", s.DNSComputer, AccentAlt)
	}
	if s.DNSDomain != "" {
		kv("dns domain", s.DNSDomain, AccentAlt)
	}
	if s.SkewSeconds != nil {
		skew := time.Duration(*s.SkewSeconds) * time.Second
		text := "+" + skew.String()
		if skew < 0 {
			text = skew.String() // carries its own '-'
		}
		var c *color.Color
		if *s.SkewSeconds > 300 || *s.SkewSeconds < -300 {
			c = Warm // past the kerberos 5-minute tolerance
		}
		kv("clock skew", text, c)
	}
}

func printLDAP(l *scan.LDAPInfo) {
	Muted.Println("LDAP")
	if l.Error != "" {
		probeError(l.Error)
	}
	if l.SigningRequired != nil {
		if *l.SigningRequired {
			kv("signing", "required", Accent)
		} else {
			kv("signing", "not required", Warm)
		}
	}
	if l.ChannelBinding != "" {
		var c *color.Color
		switch l.ChannelBinding {
		case "Always":
			c = Accent
		case "Never":
			c = Warm
		}
		kv("channel bind", l.ChannelBinding, c)
	}
	if l.NamingContext != "" {
		kv("naming ctx", l.NamingContext, nil)
	}
	if l.DCFunctionality != "" {
		kv("dc func level", l.DCFunctionality, nil)
	}
	if l.DomainFunctionality != "" {
		kv("domain func", l.DomainFunctionality, nil)
	}
	if l.ForestFunctionality != "" {
		kv("forest func", l.ForestFunctionality, nil)
	}
	if l.ForestRoot != "" {
		kv("forest root", l.ForestRoot, AccentAlt)
	}
	if len(l.SASLMechanisms) > 0 {
		kv("sasl", strings.Join(l.SASLMechanisms, ", "), Faint)
	}
	if l.DNSHostName != "" {
		kv("dns host", l.DNSHostName, AccentAlt)
	}
}

func printRPC(r *scan.RPCInfo) {
	Muted.Printf("%s  %s\n", "RPC",
		Faint.Sprintf("%d/tcp — %d endpoints", r.Port, len(r.Endpoints)))
	if r.Error != "" {
		probeError(r.Error)
		return
	}
	for _, ep := range r.Endpoints {
		annotation := ep.Annotation
		if annotation == "" {
			annotation = Faint.Sprint("-")
		}
		fmt.Printf("  %s %s %s\n",
			Faint.Sprintf("%-38s", ep.UUID),
			fmt.Sprintf("%-8s", ep.Version),
			annotation)
	}
}

func printHints(hints []string) {
	Muted.Println("HINTS")
	for _, h := range hints {
		line := h
		if strings.Contains(h, "signing not required") ||
			strings.Contains(h, "coercion target") ||
			strings.Contains(h, "null session") ||
			strings.Contains(h, "clock skew") ||
			strings.Contains(h, "ESC8") ||
			strings.Contains(h, "ANONYMOUS") ||
			strings.Contains(h, "expired TLS") {
			line = Warm.Sprint(h)
		}
		fmt.Printf("  %s\n", line)
	}
}

func printADCS(a *scan.ADCSInfo) {
	Muted.Println("ADCS")
	if a.Error != "" {
		probeError(a.Error)
		return
	}
	if !a.WebEnrollment {
		kv("web enrollment", "not found", Faint)
		return
	}
	kv("web enrollment", a.URL, Warm) // the endpoint's presence is the finding
	if len(a.AuthSchemes) > 0 {
		kv("auth schemes", strings.Join(a.AuthSchemes, ", "), nil)
	} else {
		kv("auth schemes", "none (anonymous)", Warm)
	}
}

func printTLS(t *scan.TLSInfo) {
	Muted.Println("TLS CERT")
	if t.Error != "" {
		probeError(t.Error)
		return
	}
	for _, c := range t.Certs {
		fmt.Printf("  %s %s\n", Faint.Sprintf(":%-6d", c.Port), c.SubjectCN)
		if c.IssuerCN != "" {
			kv("issuer", c.IssuerCN, Faint)
		}
		if len(c.SANs) > 0 {
			kv("sans", strings.Join(c.SANs, ", "), Faint)
		}
		var col *color.Color
		expiry := c.NotAfter.Format("2006-01-02")
		switch {
		case c.Expired:
			expiry += fmt.Sprintf(" (expired %dd ago)", -c.DaysLeft)
			col = Warm
		case c.DaysLeft < 30:
			expiry += fmt.Sprintf(" (%dd left)", c.DaysLeft)
			col = Warm
		default:
			expiry += fmt.Sprintf(" (%dd left)", c.DaysLeft)
		}
		kv("expiry", expiry, col)
	}
}

func printKerberos(k *scan.KerberosInfo) {
	Muted.Println("KERBEROS")
	if k.Error != "" {
		probeError(k.Error)
		return
	}
	if k.Realm != "" {
		kv("realm", k.Realm, AccentAlt)
	}
	if k.KDCReply != "" {
		kv("kdc reply", k.KDCReply, nil)
	}
}

// printNullSession renders the anonymous-share attempt. Refusal is the
// expected posture on modern Windows, so it prints faint rather than as
// an error; accepted-or-enumerated are the findings worth color.
func printNullSession(n *scan.NullSessionInfo) {
	Muted.Println("NULL SESSION")
	switch {
	case n.SigningBlocked:
		kv("status", "accepted (enumeration blocked by client signing)", Warm)
	case n.Error != "":
		kv("status", n.Error, Faint)
	case n.Shares != nil:
		for _, sh := range n.Shares {
			fmt.Printf("  %s\n", sh)
		}
		Faint.Printf("  %d shares\n", len(n.Shares))
	}
}

// kv prints one two-space-indented key/value row, key column width 15.
func kv(key, value string, c *color.Color) {
	if c != nil {
		value = c.Sprint(value)
	}
	fmt.Printf("  %s%s\n", Muted.Sprintf("%-15s", key), value)
}

func probeError(msg string) {
	PrintErr(msg)
}

// PrintErr renders a one-line error: red "error:" label, muted message.
func PrintErr(msg string) {
	fmt.Printf("  %s %s\n", Red.Sprint("error:"), Muted.Sprint(msg))
}
