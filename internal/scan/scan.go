package scan

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Options controls a scan run.
type Options struct {
	Ports   []PortDef
	Timeout time.Duration
	// Probes selects the phase-2 probes (see SelectProbes); nil = all.
	Probes map[Probe]bool
}

// Run executes phase 1 (TCP reachability) followed by phase 2
// (unauthenticated probes against open ports) and returns the assembled
// profile. Probe failures are recorded in the profile, never fatal.
func Run(target string, opts Options) *TargetProfile {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultPorts
	}

	profile := &TargetProfile{
		Target:    target,
		ScannedAt: time.Now().UTC(),
		Ports:     scanPorts(target, opts.Ports, opts.Timeout),
	}

	open := func(port int) bool {
		for _, p := range profile.Ports {
			if p.Port == port {
				return p.Open
			}
		}
		return false
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	if open(445) && opts.enabled(ProbeSMB) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeSMB(target, 445, opts.Timeout)
			mu.Lock()
			profile.SMB = info
			mu.Unlock()
		}()
	}
	if open(135) && opts.enabled(ProbeRPC) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeRPC(target, 135, opts.Timeout)
			mu.Lock()
			profile.RPC = info
			mu.Unlock()
		}()
	}
	if (open(389) || open(636)) && opts.enabled(ProbeLDAP) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeLDAP(target, open(389), open(636), opts.Timeout)
			mu.Lock()
			profile.LDAP = info
			mu.Unlock()
		}()
	}
	if open(445) && opts.enabled(ProbeNullSession) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeNullSession(target, 445, opts.Timeout)
			mu.Lock()
			profile.NullSession = info
			mu.Unlock()
		}()
	}
	wg.Wait()

	if open(88) && opts.enabled(ProbeKerberos) {
		// Sequential, after the batch: the realm hint borrows the SMB/LDAP
		// results, and one quick exchange doesn't justify a goroutine.
		profile.Kerberos = probeKRB(target, 88, opts.Timeout, realmHint(profile))
	}

	profile.Hints = buildHints(profile, open)
	return profile
}

// realmHint picks the best guess for the target's kerberos realm from the
// probes that already ran: the SMB NTLM fingerprint's DNS domain first,
// then the LDAP naming context. The KRB-ERROR answer is authoritative —
// the hint only shapes the request.
func realmHint(p *TargetProfile) string {
	if p.SMB != nil && p.SMB.DNSDomain != "" {
		return p.SMB.DNSDomain
	}
	if p.LDAP != nil {
		return dcStringToDomain(p.LDAP.NamingContext)
	}
	return ""
}

// buildHints derives short, data-driven observations from the profile.
func buildHints(p *TargetProfile, open func(int) bool) []string {
	var hints []string

	if open(88) && open(389) && open(3268) {
		hints = append(hints, "likely domain controller (kerberos + ldap + gc open)")
	}
	if open(445) && p.SMB != nil && p.SMB.Error == "" && p.SMB.Dialect != "" && !p.SMB.SigningRequired {
		hints = append(hints, "SMB signing not required (relay candidate)")
	}
	if open(1433) {
		hints = append(hints, "MSSQL present")
	}
	if open(5985) || open(5986) {
		hints = append(hints, "WinRM present")
	}
	if p.SMB != nil && p.SMB.SkewSeconds != nil {
		if s := *p.SMB.SkewSeconds; s > 300 || s < -300 {
			hints = append(hints, fmt.Sprintf("clock skew %s breaks kerberos (use --sync-clock)", formatSkew(s)))
		}
	}
	if p.RPC != nil {
		seen := map[string]bool{}
		for _, ep := range p.RPC.Endpoints {
			note := CoercionNote(ep.UUID)
			if note == "" {
				continue
			}
			// One line per (interface, attack) pair — MS-EFSR and MS-PAR
			// each register two UUIDs, which would otherwise double-print.
			key := shortIfaceName(ep.UUID) + "|" + note
			if seen[key] {
				continue
			}
			seen[key] = true
			hints = append(hints, fmt.Sprintf("%s exposed (%s)", shortIfaceName(ep.UUID), note))
		}
	}
	if p.LDAP != nil && p.LDAP.ForestRoot != "" {
		if strings.EqualFold(dcStringToDomain(p.LDAP.NamingContext), p.LDAP.ForestRoot) {
			hints = append(hints, "target is a forest-root DC")
		} else {
			hints = append(hints, "forest root: "+p.LDAP.ForestRoot)
		}
	}
	if p.NullSession != nil {
		switch {
		case p.NullSession.Error == "" && p.NullSession.Shares != nil:
			hints = append(hints, fmt.Sprintf("null session exposes share enumeration (%d shares)", len(p.NullSession.Shares)))
		case p.NullSession.SigningBlocked:
			hints = append(hints, "null session accepted by target (enumeration blocked by client signing)")
		}
	}
	return hints
}

// dcStringToDomain renders an LDAP DN's DC= RDNs as a DNS name
// ("DC=hackerblueprint,DC=local" → "hackerblueprint.local"); "" when no
// DC= parts are present.
func dcStringToDomain(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "DC=") {
			parts = append(parts, rdn[3:])
		}
	}
	return strings.Join(parts, ".")
}

// shortIfaceName extracts the MS-* designator from the UUID table's
// annotation ("Print System Remote (MS-RPRN)" → "MS-RPRN"), falling back
// to the UUID itself.
func shortIfaceName(uuid string) string {
	a, ok := UUIDAnnotation(uuid)
	if !ok {
		return uuid
	}
	if i := strings.Index(a, "("); i >= 0 && strings.HasSuffix(a, ")") {
		return a[i+1 : len(a)-1]
	}
	return a
}

// formatSkew renders a signed second count as a duration with an explicit
// sign ("+6m12s", "-45s").
func formatSkew(s int64) string {
	d := time.Duration(s) * time.Second
	if d >= 0 {
		return "+" + d.String()
	}
	return d.String() // negative durations carry their own '-'
}
