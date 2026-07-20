package scan

import (
	"fmt"
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

	// Root DSE (anonymous, no login).
	if nc, err := cl.GetDefaultNamingContext(); err == nil {
		info.NamingContext = nc
	}
	res, err := cl.SearchBase("", "(objectClass=*)",
		[]string{"domainControllerFunctionality", "dnsHostName"})
	if err == nil && len(res.Entries) > 0 {
		info.DCFunctionality = res.Entries[0].GetAttributeValue("domainControllerFunctionality")
		info.DNSHostName = res.Entries[0].GetAttributeValue("dnsHostName")
	}

	// A service answering on 389 that isn't LDAP (or isn't AD) connects fine
	// but yields nothing — say so instead of rendering an empty section.
	if info.SigningRequired == nil && info.NamingContext == "" &&
		info.DCFunctionality == "" && info.DNSHostName == "" {
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

func boolPtr(b bool) *bool { return &b }
