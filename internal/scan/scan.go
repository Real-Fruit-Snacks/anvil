package scan

import (
	"sync"
	"time"
)

// Options controls a scan run.
type Options struct {
	Ports   []PortDef
	Timeout time.Duration
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

	if open(445) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeSMB(target, 445, opts.Timeout)
			mu.Lock()
			profile.SMB = info
			mu.Unlock()
		}()
	}
	if open(135) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeRPC(target, 135, opts.Timeout)
			mu.Lock()
			profile.RPC = info
			mu.Unlock()
		}()
	}
	if open(389) || open(636) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := probeLDAP(target, open(389), open(636), opts.Timeout)
			mu.Lock()
			profile.LDAP = info
			mu.Unlock()
		}()
	}
	wg.Wait()

	profile.Hints = buildHints(profile, open)
	return profile
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
	return hints
}
