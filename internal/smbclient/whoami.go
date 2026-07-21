package smbclient

import (
	"fmt"
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/lsarpc"
	"github.com/mandiant/gopacket/pkg/security"
)

// ResolvedGroup is one group membership of the session user: the group's SID
// always, plus its DOMAIN\name when LSA could map the SID (an empty Name
// means the DC returned SidTypeUnknown — e.g. a group from a forest trust
// the DC won't translate).
type ResolvedGroup struct {
	SID  string
	Name string // DOMAIN\name, "" when unresolvable
}

// WhoAmIInfo is the operator's whoami /groups view: the session user's
// DOMAIN\name and objectSid, plus every group in its token, sorted by name.
type WhoAmIInfo struct {
	User   string // DOMAIN\user
	SID    string
	Groups []ResolvedGroup
}

// WhoAmI answers "who am I and what am I in" for the session user. Over one
// transient LDAP channel it finds the session user's object by
// sAMAccountName under the domain NC and reads objectSid and tokenGroups —
// tokenGroups is the full group set of the user's token, including nested
// memberships, and a plain DC LDAP query serves it (the global-catalog-only
// tokenGroupsGlobalAndUniversal flavor is not needed). Reading your own
// tokenGroups needs no special rights on default AD: the account itself can
// read it (Authenticated Users get it via Pre-Windows 2000 Compatible Access
// or self-read). The SIDs then go to DOMAIN\name through the session's
// LSARPC pipe (the lookupsid path), batched at lookupBatchSize.
func (s *Session) WhoAmI() (*WhoAmIInfo, error) {
	if s.null || s.creds == nil || s.creds.Username == "" {
		return nil, fmt.Errorf("whoami needs an authenticated session — this connection is a null session")
	}

	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return nil, fmt.Errorf("naming context: %v", err)
	}

	res, err := cl.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(s.creds.Username)),
		[]string{"objectSid"})
	if err != nil {
		return nil, fmt.Errorf("search session user: %v", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("user %q not found under %s", s.creds.Username, baseDN)
	}
	entry := res.Entries[0]

	userSID, err := parseSIDAttr(entry.GetRawAttributeValue("objectSid"))
	if err != nil {
		return nil, fmt.Errorf("objectSid of %s: %v", s.creds.Username, err)
	}

	// tokenGroups comes from a SEPARATE base-scope read of the user's DN:
	// Samba refuses to serve the attribute on a subtree search
	// ("Cannot provide tokenGroups attribute, this is not a BASE search"),
	// while Windows serves it either way.
	tg, err := cl.SearchBase(entry.DN, "(objectClass=*)", []string{"tokenGroups"})
	if err != nil {
		return nil, fmt.Errorf("read tokenGroups: %v", err)
	}
	if len(tg.Entries) == 0 {
		return nil, fmt.Errorf("read tokenGroups: %s returned no entry", entry.DN)
	}
	groupSIDs, err := parseTokenGroups(tg.Entries[0].GetRawAttributeValues("tokenGroups"))
	if err != nil {
		return nil, fmt.Errorf("tokenGroups of %s: %v", s.creds.Username, err)
	}

	// One batched LSA translation for the user SID plus every group SID;
	// results are positional, so the map is keyed off the request strings.
	names, err := s.resolveSIDNames(append([]string{userSID}, groupSIDs...))
	if err != nil {
		return nil, err
	}

	info := &WhoAmIInfo{User: s.creds.Username, SID: userSID}
	if r, ok := names[userSID]; ok {
		info.User = qualifiedName(r)
	}
	for _, gs := range groupSIDs {
		g := ResolvedGroup{SID: gs}
		if r, ok := names[gs]; ok {
			g.Name = qualifiedName(r)
		}
		info.Groups = append(info.Groups, g)
	}
	sortResolvedGroups(info.Groups)
	return info, nil
}

// resolveSIDNames translates SIDs to DOMAIN\name over the session's LSARPC
// pipe in batches of lookupBatchSize (the lookupsid sweep's batching
// constant — a user's token rarely exceeds a handful of batches). SIDs the
// DC maps to SidTypeUnknown are left out of the result.
func (s *Session) resolveSIDNames(sids []string) (map[string]lsarpc.LookupResult, error) {
	pipe, err := s.client.OpenPipe("lsarpc")
	if err != nil {
		return nil, fmt.Errorf("open lsarpc pipe: %v", err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return nil, fmt.Errorf("bind lsarpc: %v", err)
	}

	lsa, err := lsarpc.NewLsaClient(rpc)
	if err != nil {
		return nil, fmt.Errorf("open LSA policy: %v", mapLSAError(err))
	}
	defer lsa.Close()

	out := make(map[string]lsarpc.LookupResult, len(sids))
	for start := 0; start < len(sids); start += lookupBatchSize {
		batch := sids[start:min(start+lookupBatchSize, len(sids))]
		results, err := lsa.LookupSids(batch)
		if err != nil {
			return nil, fmt.Errorf("resolve SIDs: %v", mapLSAError(err))
		}
		for i, r := range results {
			if r.SidType == lsarpc.SidTypeUnknown {
				continue
			}
			out[batch[i]] = r
		}
	}
	return out, nil
}

// parseSIDAttr decodes one binary LDAP SID attribute value (the objectSid
// wire encoding security.ParseSIDBytes reads) to its string form. Trailing
// bytes after the SID fail — a corrupt attribute is worse than an error.
func parseSIDAttr(v []byte) (string, error) {
	if len(v) == 0 {
		return "", fmt.Errorf("attribute is empty")
	}
	sid, n, err := security.ParseSIDBytes(v)
	if err != nil {
		return "", err
	}
	if n != len(v) {
		return "", fmt.Errorf("%d trailing bytes after SID", len(v)-n)
	}
	return sid.String(), nil
}

// parseTokenGroups decodes a tokenGroups LDAP attribute: each value is one
// binary SID in objectSid encoding. An absent attribute (user in no groups —
// not reachable in practice, Domain Users is always there) yields an empty
// list, not an error.
func parseTokenGroups(values [][]byte) ([]string, error) {
	sids := make([]string, 0, len(values))
	for i, v := range values {
		sid, err := parseSIDAttr(v)
		if err != nil {
			return nil, fmt.Errorf("value %d: %v", i, err)
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

// qualifiedName renders an LSA lookup as DOMAIN\name, tolerating an empty
// referencing domain (well-known SIDs the DC reports without one).
func qualifiedName(r lsarpc.LookupResult) string {
	if r.Domain == "" {
		return r.Name
	}
	return r.Domain + "\\" + r.Name
}

// sortResolvedGroups orders groups by name (case-insensitive — AD names
// are), with SIDs as the tie-break so unresolvable groups (empty Name) still
// order deterministically.
func sortResolvedGroups(groups []ResolvedGroup) {
	sort.Slice(groups, func(i, j int) bool {
		a, b := strings.ToLower(groups[i].Name), strings.ToLower(groups[j].Name)
		if a == b {
			return groups[i].SID < groups[j].SID
		}
		return a < b
	})
}
