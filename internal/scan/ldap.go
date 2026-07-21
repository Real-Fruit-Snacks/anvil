package scan

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
)

// probeLDAP assesses LDAP posture on target: signing requirement (389),
// LDAPS channel binding (636), and the anonymous root DSE. Mirrors gopacket
// tools/CheckLDAPStatus, extended with root DSE enumeration via pkg/ldap.
//
// Timeout handling: pkg/ldap dials through gopacket's internal
// transport.Dialer, whose timeout is hardwired to the const
// transport.DefaultTimeout (30s) — pkg/transport exports no knob to change
// it (Options only carries Proxy). So the whole probe is bounded by a
// watchdog instead, and goldap's SetTimeout bounds bind/search ops once
// connected. Tradeoff: on watchdog expiry the probe goroutine is left
// running until the underlying dial/op returns (bounded by goldap's own
// 60s request timeout and OS TCP behavior).
func probeLDAP(target string, p389, p636 bool, timeout time.Duration) *LDAPInfo {
	done := make(chan *LDAPInfo, 1)
	go func() {
		done <- probeLDAPConns(target, p389, p636, timeout)
	}()

	watchdog := 4 * timeout
	if watchdog < 10*time.Second {
		watchdog = 10 * time.Second
	}

	select {
	case info := <-done:
		return info
	case <-time.After(watchdog):
		return &LDAPInfo{Probed: true, Error: fmt.Sprintf("timed out after %s", watchdog)}
	}
}

func probeLDAPConns(target string, p389, p636 bool, timeout time.Duration) *LDAPInfo {
	info := &LDAPInfo{Probed: true}

	var errs []string
	if p389 {
		if err := probeLDAPSigning(target, timeout, info); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if p636 {
		if err := probeLDAPSChannelBinding(target, timeout, info); err != nil {
			errs = append(errs, err.Error())
		}
	}
	info.Error = strings.Join(errs, "; ")
	return info
}

// probeLDAPSigning checks whether LDAP signing is enforced on port 389 and
// reads the root DSE anonymously.
func probeLDAPSigning(target string, timeout time.Duration, info *LDAPInfo) error {
	cl := ldap.NewClient(session.Target{Host: target, Port: 389}, &session.Credentials{})
	if err := cl.Connect(false); err != nil {
		return fmt.Errorf("389: %v", err)
	}
	defer cl.Close()
	cl.Conn.SetTimeout(timeout)

	// An anonymous unauthenticated bind fails with strongerAuthRequired when
	// signing is enforced.
	var bindErr error
	switch err := cl.Conn.UnauthenticatedBind(""); {
	case err == nil:
		info.SigningRequired = boolPtr(false)
	case isStrongerAuthError(err):
		info.SigningRequired = boolPtr(true)
	default:
		// Unrelated bind error: signing posture stays unknown.
		bindErr = err
	}

	// Root DSE (anonymous, no login). One base-object search pulls the whole
	// posture set: naming context, DC identity, functionality levels, SASL
	// mechanisms, and the schema NC (from which the forest root is derived).
	// Samba AD answers the same attribute set, so the probe behaves
	// identically against the lab and a Windows DC.
	if nc, err := cl.GetDefaultNamingContext(); err == nil {
		info.NamingContext = nc
	}
	res, err := cl.SearchBase("", "(objectClass=*)",
		[]string{"domainControllerFunctionality", "dnsHostName",
			"domainFunctionality", "forestFunctionality",
			"supportedSASLMechanisms", "schemaNamingContext"})
	if err == nil && len(res.Entries) > 0 {
		entry := res.Entries[0]
		info.DCFunctionality = entry.GetAttributeValue("domainControllerFunctionality")
		info.DNSHostName = entry.GetAttributeValue("dnsHostName")
		info.DomainFunctionality = functionalityLevel(entry.GetAttributeValue("domainFunctionality"))
		info.ForestFunctionality = functionalityLevel(entry.GetAttributeValue("forestFunctionality"))
		info.SASLMechanisms = entry.GetAttributeValues("supportedSASLMechanisms")
		info.ForestRoot = forestRootFromSchemaNC(entry.GetAttributeValue("schemaNamingContext"))
	}

	// A service answering on 389 that isn't LDAP (or isn't AD) connects fine
	// but yields nothing — say so instead of rendering an empty section.
	if info.SigningRequired == nil && info.NamingContext == "" &&
		info.DCFunctionality == "" && info.DNSHostName == "" &&
		info.DomainFunctionality == "" && info.ForestFunctionality == "" &&
		info.ForestRoot == "" && len(info.SASLMechanisms) == 0 {
		if bindErr != nil {
			return fmt.Errorf("389: no LDAP data returned (bind: %v)", bindErr)
		}
		return fmt.Errorf("389: no LDAP data returned (service may not be LDAP)")
	}
	return nil
}

// probeLDAPSChannelBinding infers the LDAPS channel-binding policy from the
// error returned by an NTLM bind with invalid credentials. pkg/ldap's
// Connect with port 636 and useTLS=true performs implicit TLS (LDAPS).
func probeLDAPSChannelBinding(target string, timeout time.Duration, info *LDAPInfo) error {
	cl := ldap.NewClient(session.Target{Host: target, Port: 636}, &session.Credentials{})
	if err := cl.Connect(true); err != nil {
		return fmt.Errorf("636: %v", err)
	}
	defer cl.Close()
	cl.Conn.SetTimeout(timeout)

	err := cl.Conn.NTLMBindWithHash("WORKGROUP", "invaliduser", "00000000000000000000000000000000")
	info.ChannelBinding = channelBindingStatus(err)
	if info.ChannelBinding == "" {
		return fmt.Errorf("636: unexpected bind response: %v", err)
	}
	return nil
}

// channelBindingStatus maps the NTLM bind error to a channel-binding policy:
// data 80090346 (SEC_E_BAD_BINDINGS) means "Always"; data 52e (invalid
// credentials) means the bind got far enough that CBT is "Never". An
// unrecognized error returns "" — the policy stays unknown rather than
// being misreported.
func channelBindingStatus(err error) string {
	if err == nil {
		return "Never"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "80090346"):
		return "Always"
	case strings.Contains(s, "52e") || strings.Contains(s, "Invalid Credentials"):
		return "Never"
	case strings.Contains(s, "Strong Auth Required") || strings.Contains(s, "strongerAuthRequired"):
		return "NTLM disabled on LDAPS"
	default:
		return ""
	}
}

func isStrongerAuthError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "strongerAuthRequired") ||
		strings.Contains(s, "Strong Auth Required") ||
		strings.Contains(strings.ToLower(s), "stronger")
}

// functionalityLevels maps the msDS-Behavior-Version values AD returns in
// the root DSE domainFunctionality / forestFunctionality attributes to
// product names (MS-ADTS DS_BEHAVIOR_* values, verified against Microsoft
// Learn). Microsoft never shipped a 2019 or 2022 functional level: Server
// 2016, 2019, and 2022 (plus the v1709/v1803/v1809 SAC releases) all
// report 7, so "2016" is the correct ceiling name for that value.
// Server 2025 reports 10 (Microsoft's functional-levels doc +
// DS_BEHAVIOR_WIN2025).
var functionalityLevels = map[int]string{
	0:  "2000",
	1:  "2003 interim",
	2:  "2003",
	3:  "2008",
	4:  "2008 R2",
	5:  "2012",
	6:  "2012 R2",
	7:  "2016",
	10: "2025",
}

// functionalityLevel renders a root-DSE functionality attribute as a
// product name. Known levels map to names; anything else — an unmapped
// newer level or a non-numeric value — renders as the raw attribute value
// rather than being dropped. Empty input stays empty so omitempty
// suppresses the field.
func functionalityLevel(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return v
	}
	if name, ok := functionalityLevels[n]; ok {
		return name
	}
	return v
}

// forestRootFromSchemaNC derives the forest root DNS name from the root
// DSE schemaNamingContext attribute: strip the fixed leading
// "CN=Schema,CN=Configuration," RDNs and convert the remaining DC= RDNs to
// dotted form (CN=Schema,CN=Configuration,DC=hackerblueprint,DC=local →
// hackerblueprint.local). Empty or malformed input yields "". RDN matching
// is case-insensitive and tolerates spaces after commas. DN-escaped
// characters are not unescaped: AD DNS labels cannot contain the
// characters escaping exists for, and anything unexpected is treated as
// malformed instead.
func forestRootFromSchemaNC(dn string) string {
	rdns := strings.Split(dn, ",")
	for i := range rdns {
		rdns[i] = strings.TrimSpace(rdns[i])
	}
	if len(rdns) < 3 ||
		!strings.EqualFold(rdns[0], "CN=Schema") ||
		!strings.EqualFold(rdns[1], "CN=Configuration") {
		return ""
	}
	labels := make([]string, 0, len(rdns)-2)
	for _, rdn := range rdns[2:] {
		if len(rdn) < 4 || !strings.EqualFold(rdn[:3], "DC=") {
			return ""
		}
		labels = append(labels, rdn[3:])
	}
	return strings.Join(labels, ".")
}

func boolPtr(b bool) *bool { return &b }
