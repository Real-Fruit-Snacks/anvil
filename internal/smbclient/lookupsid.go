package smbclient

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/lsarpc"
)

// lookupBatchSize caps each LsarLookupSids call. gopacket's tools/lookupsid
// uses 64; the MS-LSAT wire limit is 20480 entries per call, but small
// batches keep a full 500–4000 sweep to ~55 gentle round trips instead of a
// single 3500-SID hammer against the DC.
const lookupBatchSize = 64

// SidEntry is one security principal resolved by a SID brute-force sweep
// (LsarLookupSids). Unmapped RIDs never appear — only real principals.
type SidEntry struct {
	RID    uint32
	Domain string // referencing domain (e.g. HACKERBLUEPRINT)
	Name   string
	Type   string // SID_NAME_USE display string (e.g. "SidTypeUser")
}

// LookupSids brute-forces domain account names by RID over the existing
// SMB session's LSARPC pipe (no new connections), mirroring gopacket's
// tools/lookupsid: resolve the base domain SID, then translate
// domainSID-RID for every RID in the inclusive range [startRID, endRID]
// in batches of lookupBatchSize. Returns the resolved base domain SID and
// the principals found. A batch failure returns the entries gathered so
// far plus the error, so a themed denial mid-sweep still shows partial
// results and the session survives.
func (s *Session) LookupSids(startRID, endRID uint32) (domainSID string, entries []SidEntry, err error) {
	if startRID > endRID {
		return "", nil, fmt.Errorf("invalid RID range %d-%d", startRID, endRID)
	}

	pipe, err := s.client.OpenPipe("lsarpc")
	if err != nil {
		return "", nil, fmt.Errorf("open lsarpc pipe: %v", err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return "", nil, fmt.Errorf("bind lsarpc: %v", err)
	}

	// NewLsaClient opens the policy with POLICY_LOOKUP_NAMES|POLICY_VIEW_LOCAL
	// (OpenPolicy2). Anonymous sessions get STATUS_ACCESS_DENIED here on
	// Windows; Samba's lsarpc grants it.
	lsa, err := lsarpc.NewLsaClient(rpc)
	if err != nil {
		return "", nil, fmt.Errorf("open LSA policy: %v", mapLSAError(err))
	}
	defer lsa.Close()

	// Account domain first (tools/lookupsid's default; equals the AD domain
	// on a DC). Member servers report the local machine's account domain
	// there, so fall back to the primary (AD) domain when it comes back
	// empty or fails.
	_, domainSID, qerr := lsa.QueryDomainSID()
	if qerr != nil || domainSID == "" {
		_, domainSID, qerr = lsa.QueryPrimaryDomainSID()
	}
	if qerr != nil {
		return "", nil, fmt.Errorf("query domain SID: %v", mapLSAError(qerr))
	}
	if domainSID == "" {
		return "", nil, fmt.Errorf("server reported no domain SID (not a domain member?)")
	}

	for _, batch := range ridBatches(startRID, endRID, lookupBatchSize) {
		sids := make([]string, 0, batch[1]-batch[0]+1)
		for rid := batch[0]; rid <= batch[1]; rid++ {
			sids = append(sids, sidForRID(domainSID, rid))
		}
		results, err := lsa.LookupSids(sids)
		if err != nil {
			return domainSID, entries, fmt.Errorf("lookup RIDs %d-%d: %v", batch[0], batch[1], mapLSAError(err))
		}
		entries = append(entries, toSidEntries(results, batch[0])...)
	}
	return domainSID, entries, nil
}

// sidForRID appends a RID to a base domain SID string
// (S-1-5-21-...-1000).
func sidForRID(domainSID string, rid uint32) string {
	return fmt.Sprintf("%s-%d", domainSID, rid)
}

// ridBatches splits the inclusive RID range [start, end] into consecutive
// chunks of at most size RIDs. size == 0 (or start > end) yields no
// batches.
func ridBatches(start, end uint32, size uint32) [][2]uint32 {
	if size == 0 || start > end {
		return nil
	}
	var batches [][2]uint32
	for lo := start; ; lo += size {
		hi := lo + size - 1
		if hi > end || hi < lo { // hi < lo: uint32 wrap at the top of the range
			hi = end
		}
		batches = append(batches, [2]uint32{lo, hi})
		if hi == end {
			break
		}
	}
	return batches
}

// toSidEntries converts one batch of lsarpc lookup results, dropping
// unmapped SIDs (SidTypeUnknown) and stamping each survivor with its RID
// (results are positional: index i corresponds to startRID+i).
func toSidEntries(results []lsarpc.LookupResult, startRID uint32) []SidEntry {
	var out []SidEntry
	for i, r := range results {
		if r.SidType == lsarpc.SidTypeUnknown {
			continue
		}
		out = append(out, SidEntry{
			RID:    startRID + uint32(i),
			Domain: r.Domain,
			Name:   r.Name,
			Type:   r.SidTypeStr,
		})
	}
	return out
}

// mapLSAError themes the NTSTATUS codes an LSA sweep surfaces in practice
// (STATUS_ACCESS_DENIED from OpenPolicy2 on anonymous/restricted sessions)
// — the errors.go pattern, kept local so this feature stays self-contained.
func mapLSAError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "0xc0000022") { // STATUS_ACCESS_DENIED
		return fmt.Errorf("access denied")
	}
	return err
}
