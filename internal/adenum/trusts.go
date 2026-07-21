package adenum

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mandiant/gopacket/pkg/session"
)

// TrustRow is one domain trust: the trustedDomain object (TDO) for the
// peer named by trustPartner, with direction, type, and attribute flags
// already rendered for display.
type TrustRow struct {
	Name       string
	Direction  string
	Type       string
	Attributes string
}

// trustsFilter selects trusted domain objects. TDOs live under CN=System
// in the domain NC (MS-ADTS 6.1.6.7), so a subtree search from the default
// naming context finds them all. A single-domain forest has no TDOs, so
// the search returns zero entries rather than an error.
func trustsFilter() string {
	return "(objectClass=trustedDomain)"
}

// trustsAttributes are the four TDO attributes that describe a trust
// (MS-ADTS 6.1.6.7): peer name, direction, type, and attribute bitmask.
func trustsAttributes() []string {
	return []string{"trustPartner", "trustDirection", "trustType", "trustAttributes"}
}

// Trusts enumerates domain trusts via one transient LDAP connection to dc.
// Rows are sorted by trust partner name; a domain with no trusts yields an
// empty slice and nil error.
func Trusts(dc string, creds *session.Credentials) ([]TrustRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	results, err := client.Search(baseDN, trustsFilter(), trustsAttributes())
	if err != nil {
		return nil, err
	}

	rows := make([]TrustRow, 0, len(results.Entries))
	for _, entry := range results.Entries {
		rows = append(rows, TrustRow{
			Name:       entry.GetAttributeValue("trustPartner"),
			Direction:  renderTrustDirection(entry.GetAttributeValue("trustDirection")),
			Type:       renderTrustType(entry.GetAttributeValue("trustType")),
			Attributes: renderTrustAttributes(entry.GetAttributeValue("trustAttributes")),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

// renderTrustDirection maps MS-ADTS trustDirection (section 6.1.6.7.12) to
// a display token: 0=disabled, 1=inbound, 2=outbound, 3=bidirectional.
// Direction is relative to the queried domain — inbound means the local
// domain trusts the partner, so the partner's users can authenticate here.
// Values outside 0-3 are not defined by MS-ADTS and render as the number.
func renderTrustDirection(s string) string {
	switch s {
	case "0":
		return "disabled"
	case "1":
		return "inbound"
	case "2":
		return "outbound"
	case "3":
		return "bidirectional"
	default:
		return s
	}
}

// renderTrustType maps MS-ADTS trustType (section 6.1.6.7.15) to a display
// token: 1=downlevel (pre-AD, e.g. NT4 domain), 2=uplevel (AD domain),
// 3=mit (RFC4120 Kerberos realm), 4=dce (historical, unused by Windows),
// 5=aad (Azure AD). Undefined values render as the number.
func renderTrustType(s string) string {
	switch s {
	case "1":
		return "downlevel"
	case "2":
		return "uplevel"
	case "3":
		return "mit"
	case "4":
		return "dce"
	case "5":
		return "aad"
	default:
		return s
	}
}

// trustAttributeFlags are the commonly observed MS-ADTS trustAttributes
// bits (section 6.1.6.7.11), in ascending bit order — the display order.
// The higher MS-ADTS bits (RC4/AES key usage, TGT delegation policy, PIM)
// are rarely set and render as hex instead of a name.
var trustAttributeFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "non-transitive"},
	{0x00000002, "uplevel-only"},
	{0x00000004, "quarantined"}, // SID filtering (external trusts)
	{0x00000008, "forest-transitive"},
	{0x00000010, "cross-org"}, // selective authentication
	{0x00000020, "within-forest"},
	{0x00000040, "treat-as-external"},
}

// renderTrustAttributes renders the MS-ADTS trustAttributes bitmask as a
// comma-separated flag list. No bits set (or the attribute absent, which
// AD treats as zero) renders "none"; unnamed leftover bits render as one
// hex number after the named flags.
func renderTrustAttributes(s string) string {
	if s == "" {
		return "none"
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return s
	}
	if v == 0 {
		return "none"
	}
	names := make([]string, 0, len(trustAttributeFlags))
	rem := uint32(v)
	for _, f := range trustAttributeFlags {
		if rem&f.bit != 0 {
			names = append(names, f.name)
			rem &^= f.bit
		}
	}
	if rem != 0 {
		names = append(names, fmt.Sprintf("0x%08x", rem))
	}
	return strings.Join(names, ", ")
}
