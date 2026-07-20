package smbclient

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/utf16le"

	"anvil/internal/ui"
)

// ChangePassword sets targetUser's password. When oldPassword is empty the
// password is reset (replace unicodePwd, requires reset rights); otherwise it
// is changed with knowledge of the old password (delete old value + add new,
// per MS-ADTS 3.1.1.3.1.5). LDAPS is preferred since Windows requires a
// secure channel for unicodePwd writes; when the TLS handshake fails (e.g.
// Samba presenting a certificate Go's x509 parser rejects), it falls back to
// plain LDAP, which Samba labs accept (ldapComputerAttrs does the same).
func (s *Session) ChangePassword(targetUser, newPassword, oldPassword string) error {
	cl, cleanup, err := s.openLDAPS()
	if err != nil {
		ui.Debugf("changepasswd: ldaps failed (%v), trying plain ldap", err)
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

	dn, err := resolveUserDN(cl, baseDN, targetUser)
	if err != nil {
		return err
	}

	var changes []ldap.ModifyChange
	if oldPassword == "" {
		// Admin reset: replace regardless of the old value.
		changes = []ldap.ModifyChange{
			{Operation: goldap.ReplaceAttribute, AttrName: "unicodePwd", AttrVals: []string{enc(newPassword)}},
		}
	} else {
		// Change with knowledge of the old password: delete old + add new in
		// a single modify request (MS-ADTS 3.1.1.3.1.5.2).
		changes = []ldap.ModifyChange{
			{Operation: goldap.DeleteAttribute, AttrName: "unicodePwd", AttrVals: []string{enc(oldPassword)}},
			{Operation: goldap.AddAttribute, AttrName: "unicodePwd", AttrVals: []string{enc(newPassword)}},
		}
	}
	if err := cl.Modify(dn, changes); err != nil {
		return fmt.Errorf("setting password for %s: %v", targetUser, mapPasswordError(err))
	}
	return nil
}

// enc encodes a password for the unicodePwd attribute: the password wrapped
// in double quotes, UTF-16LE.
func enc(password string) string {
	return string(utf16le.EncodeStringToBytes(`"` + password + `"`))
}

// resolveUserDN finds a user's DN by sAMAccountName (resolveAccountDN in
// rbcd.go forces a trailing $, so it cannot be reused for users).
func resolveUserDN(cl *ldap.Client, baseDN, sam string) (string, error) {
	res, err := cl.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(sam)),
		[]string{"distinguishedName"})
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("user %q not found", sam)
	}
	return res.Entries[0].DN, nil
}

// mapPasswordError translates common LDAP password-write failures into
// actionable messages. Windows LDAP error text can carry embedded NUL and
// other control bytes (observed on Server 2022) — strip them before the
// message reaches the terminal. Note that a change-with-old reports BOTH a
// policy violation (0000052D: complexity/history/minimum age) and an
// incorrect old password (00000056) as "Constraint Violation", so the
// Win32 code, not the result-code name, decides the hint.
func mapPasswordError(err error) error {
	msg := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, err.Error())
	switch {
	case strings.Contains(msg, "00000056"):
		return fmt.Errorf("%s (the old password is incorrect)", msg)
	case strings.Contains(msg, "0000052D"):
		return fmt.Errorf("%s (rejected by domain password policy — complexity/history, minimum password age, or an incorrect old password)", msg)
	case strings.Contains(msg, "Constraint Violation"):
		return fmt.Errorf("%s (the password likely does not meet the domain's password policy)", msg)
	case strings.Contains(msg, "Insufficient") || strings.Contains(msg, "00000005"):
		return fmt.Errorf("%s (insufficient rights: an admin reset is required to set another user's password)", msg)
	case msg == err.Error():
		return err // nothing to strip or map — passthrough
	default:
		return fmt.Errorf("%s", msg)
	}
}
