package smbclient

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/security"
)

// rbcdAttr is the Resource-Based Constrained Delegation attribute.
const rbcdAttr = "msDS-AllowedToActOnBehalfOfOtherIdentity"

// RBCDEntry is one SID allowed to act on behalf of the target identity.
type RBCDEntry struct {
	SID  string
	Name string // resolved sAMAccountName, empty when unresolvable
}

// GetRBCD reads the RBCD security descriptor on targetCN and lists the
// allowed principals (SIDs with names resolved where possible). One
// transient LDAP channel.
func (s *Session) GetRBCD(targetCN string) ([]RBCDEntry, error) {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return nil, fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveAccountDN(cl, baseDN, targetCN)
	if err != nil {
		return nil, err
	}

	sd, err := readRBCDSD(cl, targetDN)
	if err != nil {
		return nil, err
	}
	if sd == nil || sd.DACL == nil {
		return nil, nil
	}

	var out []RBCDEntry
	for _, ace := range sd.DACL.ACEs {
		e := RBCDEntry{SID: ace.SID.String()}
		e.Name = resolveSIDName(cl, baseDN, e.SID)
		out = append(out, e)
	}
	return out, nil
}

// SetRBCD grants allowedCN the right to act on behalf of targetCN by
// appending an ACCESS_ALLOWED ACE to the target's RBCD security descriptor
// (mirrors tools/rbcd's write path). Idempotent when already present.
func (s *Session) SetRBCD(targetCN, allowedCN string) error {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return fmt.Errorf("naming context: %v", err)
	}

	sid, err := resolveAccountSID(cl, baseDN, allowedCN)
	if err != nil {
		return fmt.Errorf("account %s not found: %v", allowedCN, err)
	}

	targetDN, err := resolveAccountDN(cl, baseDN, targetCN)
	if err != nil {
		return err
	}
	sd, err := readRBCDSD(cl, targetDN)
	if err != nil {
		return err
	}
	if sd == nil {
		sd = newEmptyRBCDSD()
	}
	if sd.DACL == nil {
		sd.DACL = &security.ACL{AclRevision: 4}
		sd.Control |= security.SE_DACL_PRESENT
	}

	for _, ace := range sd.DACL.ACEs {
		if ace.SID.String() == sid {
			return nil // already allowed — nothing to do
		}
	}

	ace := newAllowACE(sid)
	sd.DACL.AddACE(ace)

	if err := cl.Modify(targetDN, []ldap.ModifyChange{
		{Operation: 2, AttrName: rbcdAttr, AttrVals: []string{string(sd.Marshal())}},
	}); err != nil {
		return fmt.Errorf("write RBCD attribute (write rights on target required): %v", err)
	}
	return nil
}

// ClearRBCD removes the RBCD attribute from targetCN entirely (tools/rbcd's
// flush: replace with no values).
func (s *Session) ClearRBCD(targetCN string) error {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveAccountDN(cl, baseDN, targetCN)
	if err != nil {
		return err
	}

	if err := cl.Modify(targetDN, []ldap.ModifyChange{
		{Operation: 2, AttrName: rbcdAttr, AttrVals: []string{}},
	}); err != nil {
		return fmt.Errorf("clear RBCD attribute (write rights on target required): %v", err)
	}
	return nil
}

// readRBCDSD fetches and parses the RBCD security descriptor from targetDN,
// or returns nil when the attribute is absent/empty.
func readRBCDSD(cl *ldap.Client, targetDN string) (*security.SecurityDescriptor, error) {
	res, err := cl.SearchBase(targetDN, "(objectClass=*)", []string{"sAMAccountName", rbcdAttr})
	if err != nil {
		return nil, fmt.Errorf("target %s not found: %v", targetDN, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("target %s not found", targetDN)
	}

	raw := res.Entries[0].GetRawAttributeValue(rbcdAttr)
	if len(raw) == 0 {
		return nil, nil
	}
	sd, err := security.ParseSecurityDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("parse RBCD security descriptor: %v", err)
	}
	return sd, nil
}

// resolveAccountDN resolves a sAMAccountName (machine or user) to its full
// DN via search (mirrors tools/rbcd's getUserInfo) — DCs live in OU=Domain
// Controllers, not CN=Computers, so the DN must not be constructed.
func resolveAccountDN(cl *ldap.Client, baseDN, samName string) (string, error) {
	name := strings.TrimSuffix(samName, "$") + "$"
	res, err := cl.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(name)),
		[]string{"distinguishedName"})
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("account %s not found", name)
	}
	return res.Entries[0].DN, nil
}

// resolveAccountSID resolves a sAMAccountName to its SID string. The name
// is tried as-is first (users) and with a trailing $ (machine accounts).
func resolveAccountSID(cl *ldap.Client, baseDN, samName string) (string, error) {
	names := []string{samName}
	if !strings.HasSuffix(samName, "$") {
		names = append(names, samName+"$")
	}
	for _, name := range names {
		res, err := cl.Search(baseDN,
			fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(name)),
			[]string{"objectSid"})
		if err != nil || len(res.Entries) == 0 {
			continue
		}
		raw := res.Entries[0].GetRawAttributeValue("objectSid")
		if len(raw) == 0 {
			continue
		}
		sid, _, err := security.ParseSIDBytes(raw)
		if err != nil {
			return "", err
		}
		return sid.String(), nil
	}
	return "", fmt.Errorf("no such account")
}

// resolveSIDName resolves a SID string back to a sAMAccountName ("" when it
// cannot be resolved — deleted accounts, foreign SIDs).
func resolveSIDName(cl *ldap.Client, baseDN, sidStr string) string {
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range sid.Marshal() {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	res, err := cl.Search(baseDN, "(objectSid="+b.String()+")", []string{"sAMAccountName"})
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	return res.Entries[0].GetAttributeValue("sAMAccountName")
}

// newEmptyRBCDSD creates an empty RBCD security descriptor (owner
// BUILTIN\Administrators) — mirrors tools/rbcd's createEmptySD.
func newEmptyRBCDSD() *security.SecurityDescriptor {
	owner, _ := security.ParseSID("S-1-5-32-544")
	return &security.SecurityDescriptor{
		Revision: 1,
		Control:  security.SE_SELF_RELATIVE | security.SE_DACL_PRESENT,
		Owner:    owner,
		DACL:     &security.ACL{AclRevision: 4},
	}
}

// newAllowACE creates an ACCESS_ALLOWED_ACE with full control for the SID
// (mirrors tools/rbcd's createAllowACE).
func newAllowACE(sidStr string) *security.ACE {
	sid, _ := security.ParseSID(sidStr)
	return &security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0x00,
		Mask:  983551, // 0xF01FF — full control
		SID:   sid,
	}
}
