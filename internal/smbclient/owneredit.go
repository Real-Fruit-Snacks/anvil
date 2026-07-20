package smbclient

import (
	"fmt"

	"github.com/mandiant/gopacket/pkg/security"
)

// OwnerInfo is an AD object's current owner, display-ready.
type OwnerInfo struct {
	SID  string // owner SID, always present when an owner is set
	Name string // resolved sAMAccountName / well-known name, "" when unresolvable
	DN   string // distinguishedName when the SID resolves to a live object
}

// GetOwner reads the owner of targetCN's nTSecurityDescriptor and returns
// the target's DN plus the resolved owner. One transient LDAP channel.
func (s *Session) GetOwner(targetCN string) (string, *OwnerInfo, error) {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return "", nil, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return "", nil, fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveObjectDN(cl, baseDN, targetCN)
	if err != nil {
		return "", nil, err
	}

	sd, err := readNTSD(cl, targetDN, security.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", nil, err
	}
	if sd.Owner == nil {
		return targetDN, &OwnerInfo{}, nil
	}

	info := &OwnerInfo{SID: sd.Owner.String()}
	resolved := newSIDResolver(cl, baseDN).resolve(info.SID)
	info.Name = resolved.name
	info.DN = resolved.dn
	return targetDN, info, nil
}

// SetOwner replaces the owner of targetCN's security descriptor with
// newOwnerCN's SID and returns the previous owner's SID ("" when none was
// set) so the change can be reported or rolled back. Only the OWNER portion
// of the descriptor is written (SD-flags control), so the DACL and SACL are
// untouched. Requires WriteOwner on the target or the Take Ownership
// privilege. One transient LDAP channel.
func (s *Session) SetOwner(targetCN, newOwnerCN string) (string, error) {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return "", err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return "", fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveObjectDN(cl, baseDN, targetCN)
	if err != nil {
		return "", err
	}

	sidStr, err := resolveAccountSID(cl, baseDN, newOwnerCN)
	if err != nil {
		return "", fmt.Errorf("account %s not found: %v", newOwnerCN, err)
	}
	newSID, err := security.ParseSID(sidStr)
	if err != nil {
		return "", fmt.Errorf("account %s SID: %v", newOwnerCN, err)
	}

	sd, err := readNTSD(cl, targetDN, security.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	prev := ""
	if sd.Owner != nil {
		prev = sd.Owner.String()
	}
	sd.Owner = newSID

	if err := writeNTSD(cl, targetDN, sd.Marshal(), security.OWNER_SECURITY_INFORMATION); err != nil {
		return "", fmt.Errorf("write owner on %s: %v", targetCN, err)
	}
	return prev, nil
}
