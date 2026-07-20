package adenum

import (
	"github.com/mandiant/gopacket/pkg/session"
)

// UserRow is one enumerated domain user.
type UserRow struct {
	Name       string
	Display    string
	AdminCount string
	PwdLastSet string
	LastLogon  string
}

// usersFilter mirrors tools/GetADUsers -all: every user object,
// including disabled accounts and users with no mail address (an enum
// command should not silently drop those).
func usersFilter() string {
	return "(&(sAMAccountName=*)(objectCategory=user))"
}

// usersAttributes mirrors tools/GetADUsers, with mail swapped for
// displayName and adminCount (the UserRow contract carries Display and
// AdminCount instead of an email column).
func usersAttributes() []string {
	return []string{"sAMAccountName", "displayName", "adminCount", "pwdLastSet", "lastLogon"}
}

// Users enumerates domain users via one transient LDAP connection to dc.
// Machine accounts are excluded by the objectCategory=user filter.
func Users(dc string, creds *session.Credentials) ([]UserRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	results, err := client.Search(baseDN, usersFilter(), usersAttributes())
	if err != nil {
		return nil, err
	}

	rows := make([]UserRow, 0, len(results.Entries))
	for _, entry := range results.Entries {
		rows = append(rows, UserRow{
			Name:       entry.GetAttributeValue("sAMAccountName"),
			Display:    entry.GetAttributeValue("displayName"),
			AdminCount: entry.GetAttributeValue("adminCount"),
			PwdLastSet: formatFileTime(entry.GetAttributeValue("pwdLastSet")),
			LastLogon:  formatFileTime(entry.GetAttributeValue("lastLogon")),
		})
	}
	return rows, nil
}
