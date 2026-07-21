package scan

import (
	"fmt"
	"strings"
)

// Probe names one optional phase-2 probe of a scan run, selectable via
// `anvil scan --only/--skip`. The phase-1 port sweep always runs; a
// probe fires when its port is open AND it is selected.
type Probe string

const (
	ProbeSMB         Probe = "smb"
	ProbeRPC         Probe = "rpc"
	ProbeLDAP        Probe = "ldap"
	ProbeKerberos    Probe = "krb"
	ProbeNullSession Probe = "nullsession"
)

// AllProbes lists every selectable probe — the effective set when
// neither --only nor --skip is given.
var AllProbes = []Probe{ProbeSMB, ProbeRPC, ProbeLDAP, ProbeKerberos, ProbeNullSession}

// ProbeNames returns the valid probe names in display order, for help
// and error text.
func ProbeNames() []string {
	names := make([]string, len(AllProbes))
	for i, p := range AllProbes {
		names[i] = string(p)
	}
	return names
}

// ParseProbeList validates a comma-separated probe list (an --only or
// --skip value) and returns it as a set. Matching is case-insensitive
// and space-tolerant; unknown names are rejected with the valid list.
func ParseProbeList(s string) (map[Probe]bool, error) {
	valid := make(map[string]Probe, len(AllProbes))
	for _, p := range AllProbes {
		valid[string(p)] = p
	}
	set := map[Probe]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		p, ok := valid[part]
		if !ok {
			return nil, fmt.Errorf("unknown probe %q (valid: %s)", part, strings.Join(ProbeNames(), ", "))
		}
		set[p] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no valid probes in list (valid: %s)", strings.Join(ProbeNames(), ", "))
	}
	return set, nil
}

// SelectProbes resolves the --only/--skip flag values into the probe set
// for one run: --only is a whitelist, --skip a blacklist, both together
// is a usage error, and neither means nil (everything, the default).
// Skipping all five is legitimate — the run is then a bare port sweep.
func SelectProbes(only, skip string) (map[Probe]bool, error) {
	only = strings.TrimSpace(only)
	skip = strings.TrimSpace(skip)
	if only != "" && skip != "" {
		return nil, fmt.Errorf("--only and --skip cannot be used together")
	}
	if only != "" {
		return ParseProbeList(only)
	}
	if skip == "" {
		return nil, nil
	}
	skipSet, err := ParseProbeList(skip)
	if err != nil {
		return nil, err
	}
	set := map[Probe]bool{}
	for _, p := range AllProbes {
		if !skipSet[p] {
			set[p] = true
		}
	}
	return set, nil
}

// enabled reports whether probe p runs under the Options selection:
// nil Probes selects everything (the default), a non-nil set whitelists.
func (o Options) enabled(p Probe) bool {
	if o.Probes == nil {
		return true
	}
	return o.Probes[p]
}
