package adenum

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mandiant/gopacket/pkg/session"
)

// TemplateRow is one AD CS certificate template (objectClass
// pKICertificateTemplate) from the Configuration naming context.
//
// EKUs carries the pKIExtendedKeyUsage OIDs mapped to friendly names;
// OIDs without a known mapping are kept raw. A template with no EKUs at
// all (an empty pKIExtendedKeyUsage — the built-in SubCA template ships
// that way) yields an empty slice, which is itself the finding: a cert
// with no EKU extension is unrestricted, equivalent to Any Purpose.
//
// Enrollment rights are deliberately absent: they live in the template's
// nTSecurityDescriptor (Enroll / AutoEnroll extended rights, WriteDacl,
// WriteOwner — the ESC4 surface) and resolving them means parsing the
// security descriptor and expanding the caller's group memberships, which
// is out of scope for this row contract.
type TemplateRow struct {
	CN                      string
	EKUs                    []string
	EnrolleeSuppliesSubject bool
	EnrollmentFlags         uint32
	NameFlags               uint32
}

// templatesBaseDN derives the Certificate Templates container from the
// default naming context: templates are forest-wide and live under the
// Configuration NC, not the domain NC, so the base is
// CN=Certificate Templates,CN=Public Key Services,CN=Services,
// CN=Configuration,<defaultNC> (same derivation Certipy/Certify use).
func templatesBaseDN(defaultNC string) string {
	return "CN=Certificate Templates,CN=Public Key Services,CN=Services," +
		"CN=Configuration," + defaultNC
}

// templatesFilter matches every certificate template object. All template
// objects are direct children of the container, but the subtree scope of
// the shared Search helper costs nothing here.
func templatesFilter() string {
	return "(objectClass=pKICertificateTemplate)"
}

// templatesAttributes requests the attack-relevant template attributes:
// the EKU list plus the two MS-CRTD flag attributes that drive ESC1
// triage. cn is the row identity (cn == name on template objects).
func templatesAttributes() []string {
	return []string{"cn", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"}
}

// CertificateTemplates enumerates AD CS certificate templates via one
// transient LDAP connection to dc, mirroring the Users pattern but
// searching the Configuration naming context (derived from the default
// NC) instead of the domain NC. Rows are sorted by CN.
func CertificateTemplates(dc string, creds *session.Credentials) ([]TemplateRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	results, err := client.Search(templatesBaseDN(baseDN), templatesFilter(), templatesAttributes())
	if err != nil {
		return nil, fmt.Errorf("certificate template search: %v", err)
	}

	rows := make([]TemplateRow, 0, len(results.Entries))
	for _, entry := range results.Entries {
		nameFlags := parseUint32Attr(entry.GetAttributeValue("msPKI-Certificate-Name-Flag"))
		rows = append(rows, TemplateRow{
			CN:                      entry.GetAttributeValue("cn"),
			EKUs:                    mapEKUs(entry.GetAttributeValues("pKIExtendedKeyUsage")),
			EnrolleeSuppliesSubject: enrolleeSuppliesSubject(nameFlags),
			EnrollmentFlags:         parseUint32Attr(entry.GetAttributeValue("msPKI-Enrollment-Flag")),
			NameFlags:               nameFlags,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CN < rows[j].CN })
	return rows, nil
}

// ekuNames maps the EKU OIDs seen on stock Windows templates (and the
// ESC-relevant ones) to friendly names. Standard id-kp values are RFC
// 5280, the PKINIT pair is RFC 4556, the 1.3.6.1.4.1.311.* values are
// Microsoft-private — verified against MS-CRTD and certipy's
// OID_TO_STR_MAP. Note Smart Card Logon is the Microsoft-private OID
// 1.3.6.1.4.1.311.20.2.2, not 1.3.6.1.5.5.7.3.14 (that id-kp value is
// eapOverLAN, RFC 4334) — it stays unmapped. Anything not listed here is
// reported as the raw OID.
var ekuNames = map[string]string{
	// RFC 5280 id-kp.
	"1.3.6.1.5.5.7.3.1": "Server Authentication",
	"1.3.6.1.5.5.7.3.2": "Client Authentication",
	"1.3.6.1.5.5.7.3.3": "Code Signing",
	"1.3.6.1.5.5.7.3.4": "Secure Email",
	"1.3.6.1.5.5.7.3.8": "Time Stamping",
	"1.3.6.1.5.5.7.3.9": "OCSP Signing",
	// RFC 5280 anyExtendedKeyUsage: no restriction on purpose.
	"2.5.29.37.0": "Any Purpose",
	// RFC 4556 PKINIT: both are accepted by the KDC for certificate logon.
	"1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
	"1.3.6.1.5.2.3.5": "KDC Authentication",
	// Microsoft-private, from the stock templates (CA Exchange, Key
	// Recovery Agent, Enrollment Agent, EFS, ...) and the ESC3-relevant
	// Certificate Request Agent.
	"1.3.6.1.4.1.311.20.2.1":   "Certificate Request Agent",
	"1.3.6.1.4.1.311.20.2.2":   "Smart Card Logon",
	"1.3.6.1.4.1.311.10.3.4":   "Encrypting File System",
	"1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
	"1.3.6.1.4.1.311.21.5":     "Private Key Archival",
	"1.3.6.1.4.1.311.21.6":     "Key Recovery Agent",
	"1.3.6.1.4.1.311.10.3.1":   "Microsoft Trust List Signing",
	"1.3.6.1.4.1.311.10.3.9":   "Root List Signer",
}

// mapEKUs maps a template's pKIExtendedKeyUsage OID list to friendly
// names, keeping the directory's value order. Unknown OIDs stay raw so
// custom application policies are not silently dropped. Empty input
// (the SubCA case) yields nil.
func mapEKUs(oids []string) []string {
	if len(oids) == 0 {
		return nil
	}
	names := make([]string, 0, len(oids))
	for _, oid := range oids {
		names = append(names, ekuName(oid))
	}
	return names
}

// ekuName resolves one EKU OID to its friendly name, or returns the raw
// OID when unmapped.
func ekuName(oid string) string {
	if name, ok := ekuNames[oid]; ok {
		return name
	}
	return oid
}

// enrolleeSuppliesSubject reports whether the template lets the requester
// supply the subject: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001) in
// msPKI-Certificate-Name-Flag (MS-CRTD 2.28). When set, the CSR's
// subjectAltName is honored, so with an authentication-capable EKU and
// enrollment rights the template is impersonation-capable — the ESC1
// condition from Specterops' "Certified Pre-Owned".
func enrolleeSuppliesSubject(nameFlags uint32) bool {
	return nameFlags&0x00000001 != 0
}

// parseUint32Attr parses an LDAP INTEGER attribute into a uint32 bitmask.
// AD stores these flag attributes with Integer syntax (signed 32-bit on
// the wire), so a value with the top bit set can arrive as a negative
// decimal string — parsing as int64 and converting to uint32 normalizes
// both representations. Unset or unparseable values yield 0.
func parseUint32Attr(s string) uint32 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return uint32(v)
}
