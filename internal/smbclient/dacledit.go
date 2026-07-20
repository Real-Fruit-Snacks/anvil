package smbclient

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/security"
)

// sdAttr is the AD attribute carrying an object's self-relative security
// descriptor (owner, group, DACL, SACL).
const sdAttr = "nTSecurityDescriptor"

// daclRightsPreset is one ACE template of a named rights set: standard ACEs
// carry only a mask; object ACEs additionally target an extended right or
// property-set GUID (dcsync, resetpassword, writemembers). Mirrors the
// presets of gopacket's tools/dacledit.
type daclRightsPreset struct {
	objectType *security.GUID // non-nil → ACCESS_*_OBJECT ACE for this GUID
	mask       uint32
}

// daclRightsPresets maps a case-insensitive rights name to its ACE
// templates. dcsync needs both replication GUIDs to be useful, so it builds
// two ACEs.
var daclRightsPresets = map[string][]daclRightsPreset{
	"fullcontrol":   {{mask: security.FULL_CONTROL}}, // 0xF01FF
	"genericall":    {{mask: security.GENERIC_ALL}},  // 0x10000000
	"writedacl":     {{mask: security.WRITE_DAC}},
	"writeowner":    {{mask: security.WRITE_OWNER}},
	"writemembers":  {{mask: security.DS_WRITE_PROP, objectType: &security.GUID_WRITE_MEMBERS}},
	"resetpassword": {{mask: security.DS_CONTROL_ACCESS, objectType: &security.GUID_RESET_PASSWORD}},
	"dcsync": {
		{mask: security.DS_CONTROL_ACCESS, objectType: &security.GUID_DS_REPLICATION_GET_CHANGES},
		{mask: security.DS_CONTROL_ACCESS, objectType: &security.GUID_DS_REPLICATION_GET_CHANGES_ALL},
	},
}

// DACLEntry is one ACE of an AD object's DACL, display-ready: the trustee
// SID resolved to a name where possible and the access mask decomposed into
// right names (all formatting via gopacket's pkg/security).
type DACLEntry struct {
	Index               int    // position in the DACL
	ACEType             string // ACCESS_ALLOWED, ACCESS_DENIED, and their OBJECT variants
	Trustee             string // resolved sAMAccountName / well-known name, "" when unresolvable
	SID                 string // trustee SID, always present
	Mask                uint32 // raw access mask
	Rights              string // decomposed mask, e.g. "GENERIC_ALL", "WRITE_DAC|READ_CONTROL"
	Flags               string // inheritance flags, e.g. "CONTAINER_INHERIT|OBJECT_INHERIT"; "" when none
	ObjectType          string // object ACE's targeted right/property, "" for standard ACEs
	InheritedObjectType string // object ACE's inheritance scope, "" when absent
}

// GetDACL reads targetCN's nTSecurityDescriptor DACL and returns the
// target's DN and its ACEs, display-ready. One transient LDAP channel.
func (s *Session) GetDACL(targetCN string) (string, []DACLEntry, error) {
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

	sd, err := readNTSD(cl, targetDN, security.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", nil, err
	}
	if sd.DACL == nil {
		return targetDN, nil, nil
	}

	resolver := newSIDResolver(cl, baseDN)
	entries := make([]DACLEntry, 0, len(sd.DACL.ACEs))
	for i, ace := range sd.DACL.ACEs {
		e := DACLEntry{
			Index:   i,
			ACEType: aceTypeName(ace.Type),
			SID:     ace.SID.String(),
			Mask:    ace.Mask,
			Rights:  security.FormatAccessMask(ace.Mask),
		}
		e.Trustee = resolver.resolve(e.SID).name
		if ace.Flags != 0 {
			e.Flags = security.FormatACEFlags(ace.Flags)
		}
		if ace.IsObjectACE() {
			if !ace.ObjectType.IsZero() {
				e.ObjectType = guidDisplay(ace.ObjectType)
			}
			if !ace.InheritedObjectType.IsZero() {
				e.InheritedObjectType = guidDisplay(ace.InheritedObjectType)
			}
		}
		entries = append(entries, e)
	}
	return targetDN, entries, nil
}

// WriteDACL grants principalCN the named rights on targetCN by appending
// ACE(s) to the target's DACL, and reports how many ACEs were added (dcsync
// adds two). denied produces ACCESS_DENIED ACEs; inheritance marks them
// CONTAINER_INHERIT|OBJECT_INHERIT so they propagate to child objects. Only
// the DACL portion of the descriptor is written (SD-flags control), so the
// owner and SACL are untouched. One transient LDAP channel.
//
// Windows Server 2022 canonicalizes the DACL on write (observed on the lab
// DC): ACEs are re-sorted into canonical order rather than left appended,
// exact duplicate ACEs are merged, and GENERIC_ALL is stored as the AD
// full-control set (0xF01FF) — a granted "genericall" ACE therefore reads
// back as FULL_CONTROL. RemoveDACL's matching accounts for the mapping.
func (s *Session) WriteDACL(targetCN, principalCN, rights string, denied, inheritance bool) (int, error) {
	presets, err := lookupRightsPresets(rights)
	if err != nil {
		return 0, err
	}

	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return 0, fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveObjectDN(cl, baseDN, targetCN)
	if err != nil {
		return 0, err
	}

	sidStr, err := resolveAccountSID(cl, baseDN, principalCN)
	if err != nil {
		return 0, fmt.Errorf("principal %s not found: %v", principalCN, err)
	}
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return 0, fmt.Errorf("principal %s SID: %v", principalCN, err)
	}

	sd, err := readNTSD(cl, targetDN, security.DACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	if sd.DACL == nil {
		sd.DACL = &security.ACL{AclRevision: 4}
		sd.Control |= security.SE_DACL_PRESENT
	}

	aces := buildRightACEs(sid, presets, denied, inheritance)
	for _, ace := range aces {
		sd.DACL.AddACE(ace)
	}

	if err := writeNTSD(cl, targetDN, sd.Marshal(), security.DACL_SECURITY_INFORMATION); err != nil {
		return 0, fmt.Errorf("write DACL on %s: %v", targetCN, err)
	}
	return len(aces), nil
}

// RemoveDACL deletes ACEs granted to principalCN from targetCN's DACL and
// reports how many were removed. With rights empty every ACE for the
// principal goes; otherwise only ACEs covering the named rights preset
// (mask cover + matching object GUID) are removed — a FullControl ACE
// therefore matches a "writedacl" removal, mirroring tools/dacledit, and
// GENERIC_ALL ↔ FULL_CONTROL cover each other because the DC canonicalizes
// one into the other on write (see WriteDACL). One transient LDAP channel.
func (s *Session) RemoveDACL(targetCN, principalCN, rights string) (int, error) {
	var presets []daclRightsPreset
	if rights != "" {
		p, err := lookupRightsPresets(rights)
		if err != nil {
			return 0, err
		}
		presets = p
	}

	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return 0, fmt.Errorf("naming context: %v", err)
	}
	targetDN, err := resolveObjectDN(cl, baseDN, targetCN)
	if err != nil {
		return 0, err
	}

	sidStr, err := resolveAccountSID(cl, baseDN, principalCN)
	if err != nil {
		return 0, fmt.Errorf("principal %s not found: %v", principalCN, err)
	}
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return 0, fmt.Errorf("principal %s SID: %v", principalCN, err)
	}

	sd, err := readNTSD(cl, targetDN, security.DACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	if sd.DACL == nil {
		return 0, nil
	}

	// Iterate backward so removals don't shift the indices still to visit.
	removed := 0
	for i := len(sd.DACL.ACEs) - 1; i >= 0; i-- {
		ace := sd.DACL.ACEs[i]
		if !ace.SID.Equal(sid) {
			continue
		}
		if len(presets) > 0 && !aceMatchesAnyPreset(ace, presets) {
			continue
		}
		sd.DACL.RemoveACE(i)
		removed++
	}
	if removed == 0 {
		return 0, nil
	}

	if err := writeNTSD(cl, targetDN, sd.Marshal(), security.DACL_SECURITY_INFORMATION); err != nil {
		return 0, fmt.Errorf("write DACL on %s: %v", targetCN, err)
	}
	return removed, nil
}

// RightsPresetNames lists the valid rights preset names for WriteDACL /
// RemoveDACL (help text and error messages share it).
func RightsPresetNames() string {
	names := make([]string, 0, len(daclRightsPresets))
	for k := range daclRightsPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// lookupRightsPresets resolves a case-insensitive rights name to its ACE
// templates.
func lookupRightsPresets(rights string) ([]daclRightsPreset, error) {
	p, ok := daclRightsPresets[strings.ToLower(rights)]
	if !ok {
		return nil, fmt.Errorf("unknown rights %q (valid: %s)", rights, RightsPresetNames())
	}
	return p, nil
}

// buildRightACEs instantiates one ACE per preset entry for trustee sid.
func buildRightACEs(sid *security.SID, presets []daclRightsPreset, denied, inheritance bool) []*security.ACE {
	var flags uint8
	if inheritance {
		flags = security.CONTAINER_INHERIT_ACE | security.OBJECT_INHERIT_ACE
	}
	aces := make([]*security.ACE, 0, len(presets))
	for _, p := range presets {
		ace := &security.ACE{
			Type:  security.ACCESS_ALLOWED_ACE_TYPE,
			Flags: flags,
			Mask:  p.mask,
			SID:   sid,
		}
		if p.objectType != nil {
			ace.Type = security.ACCESS_ALLOWED_OBJECT_ACE_TYPE
			ace.ObjectType = *p.objectType
			ace.ObjectFlags = security.ACE_OBJECT_TYPE_PRESENT
		}
		if denied {
			if p.objectType != nil {
				ace.Type = security.ACCESS_DENIED_OBJECT_ACE_TYPE
			} else {
				ace.Type = security.ACCESS_DENIED_ACE_TYPE
			}
		}
		aces = append(aces, ace)
	}
	return aces
}

// aceMatchesAnyPreset reports whether ace grants at least the rights of one
// preset: the preset mask must be covered by the ACE's mask, and a preset
// object type must equal the ACE's (a standard ACE never matches an object
// preset — its ObjectType GUID is zero).
func aceMatchesAnyPreset(ace *security.ACE, presets []daclRightsPreset) bool {
	for _, p := range presets {
		if !maskCovers(ace.Mask, p.mask) {
			continue
		}
		if p.objectType != nil && ace.ObjectType != *p.objectType {
			continue
		}
		return true
	}
	return false
}

// maskCovers reports whether aceMask grants at least the rights of
// presetMask. Windows Server 2022 canonicalizes the DACL when an
// nTSecurityDescriptor is written: ACEs are re-sorted, duplicates merged,
// and GENERIC_ALL is stored as the AD full-control set (0xF01FF) — observed
// on the lab DC. GENERIC_ALL and FULL_CONTROL are therefore treated as
// covering each other, so a "genericall" removal still matches the
// canonicalized ACE (and vice versa). GENERIC_ALL is the only generic right
// in the presets.
func maskCovers(aceMask, presetMask uint32) bool {
	if aceMask&presetMask == presetMask {
		return true
	}
	return (presetMask == security.GENERIC_ALL && aceMask&security.FULL_CONTROL == security.FULL_CONTROL) ||
		(presetMask == security.FULL_CONTROL && aceMask&security.GENERIC_ALL == security.GENERIC_ALL)
}

// readNTSD reads the target's nTSecurityDescriptor under an SD-flags control
// selecting which parts the server returns (OWNER/GROUP/DACL — SACL needs
// SeSecurityPrivilege and is never requested). The search is base-scope via
// the raw connection: gopacket's SearchWithControls is whole-subtree, which
// would pull a container's entire subtree when the target is an OU.
func readNTSD(cl *ldap.Client, targetDN string, sdFlags int) (*security.SecurityDescriptor, error) {
	req := goldap.NewSearchRequest(
		targetDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{sdAttr},
		[]goldap.Control{ldap.NewControlMicrosoftSDFlags(sdFlags)},
	)
	res, err := cl.Conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", sdAttr, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("target %s not found", targetDN)
	}
	raw := res.Entries[0].GetRawAttributeValue(sdAttr)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is empty on %s", sdAttr, targetDN)
	}
	sd, err := security.ParseSecurityDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %v", sdAttr, err)
	}
	return sd, nil
}

// writeNTSD replaces nTSecurityDescriptor under an SD-flags control, so only
// the selected parts (DACL for dacledit, OWNER for owneredit) are applied —
// the rest of the descriptor is untouched server-side.
func writeNTSD(cl *ldap.Client, targetDN string, sd []byte, sdFlags int) error {
	err := cl.ModifyRaw(targetDN, goldap.ReplaceAttribute, sdAttr, sd,
		[]goldap.Control{ldap.NewControlMicrosoftSDFlags(sdFlags)})
	if err != nil {
		return mapSDError(err)
	}
	return nil
}

// mapSDError themes nTSecurityDescriptor write failures. The common case is
// LDAP Result Code 50 (INSUFF_ACCESS_RIGHTS, Win32 00000005) when the
// session user lacks WriteDACL/WriteOwner on the target.
func mapSDError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "Insufficient") || strings.Contains(msg, "00000005") {
		return fmt.Errorf("%s (access denied: WriteDACL/WriteOwner rights on the target required)", msg)
	}
	return err
}

// resolveObjectDN resolves any AD object (user, group, computer) by
// sAMAccountName to its DN. Machine accounts are found via a trailing-$
// fallback, so both "DC01" and "DC01$" work (rbcd.go's resolveAccountDN
// forces the $ and can't be reused for users/groups).
func resolveObjectDN(cl *ldap.Client, baseDN, sam string) (string, error) {
	names := []string{sam}
	if !strings.HasSuffix(sam, "$") {
		names = append(names, sam+"$")
	}
	for _, name := range names {
		res, err := cl.Search(baseDN,
			fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(name)),
			[]string{"distinguishedName"})
		if err != nil {
			return "", err
		}
		if len(res.Entries) > 0 {
			return res.Entries[0].DN, nil
		}
	}
	return "", fmt.Errorf("object %q not found", sam)
}

// sidInfo is a resolved trustee: sAMAccountName and DN, either of which may
// be empty (well-known SIDs have no domain object; deleted/foreign SIDs
// resolve to nothing).
type sidInfo struct {
	name string
	dn   string
}

// sidResolver resolves trustee SIDs to display names over the already-open
// LDAP channel: gopacket's well-known SID table first, then an objectSid
// search, then the well-known domain-RID table as a fallback for deleted
// objects. Results are cached — DACLs repeat the same trustees heavily.
type sidResolver struct {
	cl        *ldap.Client
	baseDN    string
	domainSID string
	cache     map[string]sidInfo
}

func newSIDResolver(cl *ldap.Client, baseDN string) *sidResolver {
	r := &sidResolver{cl: cl, baseDN: baseDN, cache: make(map[string]sidInfo)}
	r.domainSID = r.lookupDomainSID()
	return r
}

// resolve returns the cached-or-fresh sidInfo for a SID string.
func (r *sidResolver) resolve(sidStr string) sidInfo {
	if info, ok := r.cache[sidStr]; ok {
		return info
	}
	info := r.lookup(sidStr)
	r.cache[sidStr] = info
	return info
}

func (r *sidResolver) lookup(sidStr string) sidInfo {
	if name, ok := security.WellKnownSIDs[sidStr]; ok {
		return sidInfo{name: name}
	}
	if filter, err := sidSearchFilter(sidStr); err == nil {
		res, err := r.cl.Search(r.baseDN, filter, []string{"sAMAccountName"})
		if err == nil && len(res.Entries) > 0 {
			return sidInfo{
				name: res.Entries[0].GetAttributeValue("sAMAccountName"),
				dn:   res.Entries[0].DN,
			}
		}
	}
	// No live object (deleted account, foreign SID) — the RID table still
	// names the well-known domain groups (Domain Admins, ...).
	if r.domainSID != "" && strings.HasPrefix(sidStr, r.domainSID+"-") {
		if rid, err := strconv.ParseUint(sidStr[len(r.domainSID)+1:], 10, 32); err == nil {
			if name, ok := security.WellKnownRIDs[uint32(rid)]; ok {
				return sidInfo{name: name}
			}
		}
	}
	return sidInfo{}
}

// lookupDomainSID learns the domain SID for RID-table lookups, best-effort.
func (r *sidResolver) lookupDomainSID() string {
	res, err := r.cl.Search(r.baseDN, "(objectClass=domain)", []string{"objectSid"})
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	raw := res.Entries[0].GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return ""
	}
	sid, _, err := security.ParseSIDBytes(raw)
	if err != nil {
		return ""
	}
	return sid.String()
}

// sidSearchFilter builds an LDAP equality filter matching a binary objectSid
// (each byte \xx-escaped per RFC 4515).
func sidSearchFilter(sidStr string) (string, error) {
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range sid.Marshal() {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return "(objectSid=" + b.String() + ")", nil
}

// aceTypeName renders an ACE type byte, falling back to hex for types
// gopacket doesn't name.
func aceTypeName(t uint8) string {
	if name, ok := security.ACETypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", t)
}

// guidDisplay renders an object-ACE GUID as "Name (guid)" for GUIDs
// gopacket names (extended rights, property sets, schema classes), else the
// bare GUID.
func guidDisplay(g security.GUID) string {
	if name := security.GUIDToName(g); name != "Unknown" {
		return fmt.Sprintf("%s (%s)", name, g.String())
	}
	return g.String()
}
