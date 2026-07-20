package smbclient

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/utf16le"

	"anvil/internal/ui"
)

// AddComputer creates a machine account named name (normalized with a
// trailing $) with the given password. The account itself is created and
// keyed over SAMR on the EXISTING SMB session (no new dials); its
// dNSHostName and kerberos SPNs are then set over one transient LDAP
// channel (mirrors tools/addcomputer's SAMR + attribute flow). Any
// authenticated user can typically create up to 10 machine accounts
// (MS-DS-Machine-Account-Quota).
func (s *Session) AddComputer(name, password string) error {
	if err := s.createComputer(name, password); err != nil {
		return err
	}

	// Attributes over one transient LDAP channel: dNSHostName + kerberos
	// SPNs (userAccountControl is already set by SAMR's workstation-trust
	// create). Failure here leaves the account created but unadorned —
	// reported as its own error, not hidden.
	clean := strings.TrimSuffix(name, "$")
	if err := s.ldapComputerAttrs(clean, password); err != nil {
		return fmt.Errorf("%s$ created, but attribute setup failed: %v", clean, err)
	}
	return nil
}

// DeleteComputer removes a machine account via one transient LDAP channel
// (tools/addcomputer's delete path). Admin rights are typically required.
func (s *Session) DeleteComputer(name string) error {
	name = strings.TrimSuffix(name, "$")

	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return fmt.Errorf("naming context: %v", err)
	}
	computerDN := computerDNFor(name, baseDN)

	if err := cl.Delete(computerDN); err != nil {
		return fmt.Errorf("delete %s$ (admin required): %v", name, err)
	}
	return nil
}

// ldapComputerAttrs sets dNSHostName, the kerberos SPN set, enables the
// account, and sets the machine password (unicodePwd) on a fresh machine
// account. Runs over one transient LDAP channel — LDAPS (636) first since
// password writes need a secure channel, plain LDAP as a fallback (Samba
// accepts it; Windows refuses it).
func (s *Session) ldapComputerAttrs(name, password string) error {
	cl, cleanup, err := s.openLDAPS()
	if err != nil {
		ui.Debugf("ldapComputerAttrs: ldaps failed (%v), trying plain ldap", err)
		cl, cleanup, err = s.openLDAP()
	}
	if err != nil {
		return err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return fmt.Errorf("naming context: %v", err)
	}

	fqdn := name + "." + dnToDomain(baseDN)
	changes := []ldap.ModifyChange{
		{Operation: 0, AttrName: "dNSHostName", AttrVals: []string{fqdn}}, // AddAttribute = 0
		{Operation: 0, AttrName: "servicePrincipalName", AttrVals: []string{
			"HOST/" + name,
			"HOST/" + fqdn,
			"RestrictedKrbHost/" + name,
			"RestrictedKrbHost/" + fqdn,
		}},
		// SAMR creates the account ACCOUNTDISABLED|PASSWD_NOTREQD; once the
		// password is set, enable it (impacket's addcomputer sets plain
		// WORKSTATION_TRUST_ACCOUNT). Operation 2 = ReplaceAttribute.
		{Operation: 2, AttrName: "userAccountControl", AttrVals: []string{"4096"}},
		// unicodePwd must be the password wrapped in double quotes, UTF-16LE.
		{Operation: 2, AttrName: "unicodePwd", AttrVals: []string{string(utf16le.EncodeStringToBytes(`"` + password + `"`))}},
	}
	if err := cl.Modify(computerDNFor(name, baseDN), changes); err != nil {
		return err
	}
	return nil
}

// openLDAP establishes one transient LDAP channel with the session's
// credentials (UPN simple bind, Login() fallback — the roast pattern).
func (s *Session) openLDAP() (*ldap.Client, func(), error) {
	cl := ldap.NewClient(session.Target{Host: s.host}, s.creds)
	if err := cl.Connect(false); err != nil {
		cl.Close()
		return nil, nil, fmt.Errorf("ldap connect: %v", err)
	}
	loginUser := fmt.Sprintf("%s@%s", s.creds.Username, s.creds.Domain)
	if err := cl.LoginWithUser(loginUser); err != nil {
		if err := cl.Login(); err != nil {
			cl.Close()
			return nil, nil, fmt.Errorf("ldap bind (authenticated user required): %v", err)
		}
	}
	return cl, func() { cl.Close() }, nil
}

// openLDAPS is openLDAP over TLS (port 636) — needed for password writes.
func (s *Session) openLDAPS() (*ldap.Client, func(), error) {
	cl := ldap.NewClient(session.Target{Host: s.host, Port: 636}, s.creds)
	if err := cl.Connect(true); err != nil {
		cl.Close()
		return nil, nil, fmt.Errorf("ldaps connect: %v", err)
	}
	loginUser := fmt.Sprintf("%s@%s", s.creds.Username, s.creds.Domain)
	if err := cl.LoginWithUser(loginUser); err != nil {
		if err := cl.Login(); err != nil {
			cl.Close()
			return nil, nil, fmt.Errorf("ldaps bind (authenticated user required): %v", err)
		}
	}
	return cl, func() { cl.Close() }, nil
}

// computerDNFor builds the computer object's DN in the default Computers
// container.
func computerDNFor(name, baseDN string) string {
	return "CN=" + name + ",CN=Computers," + baseDN
}

// dnToDomain converts "DC=corp,DC=local" to "corp.local".
func dnToDomain(dn string) string {
	var parts []string
	for _, c := range strings.Split(dn, ",") {
		if strings.HasPrefix(strings.ToUpper(c), "DC=") {
			parts = append(parts, c[3:])
		}
	}
	return strings.Join(parts, ".")
}
