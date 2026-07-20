package adenum

import (
	"fmt"

	"github.com/mandiant/gopacket/pkg/session"
)

// ComputerRow is one enumerated domain computer.
type ComputerRow struct {
	Name    string
	DNSHost string
	OS      string
}

// computersFilter mirrors tools/GetADComputers exactly.
func computersFilter() string {
	return "(&(objectCategory=computer)(objectClass=computer))"
}

// computersAttributes mirrors tools/GetADComputers exactly.
func computersAttributes() []string {
	return []string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion"}
}

// Computers enumerates domain computers via one transient LDAP
// connection to dc. Like tools/GetADComputers it pages (100 per page).
func Computers(dc string, creds *session.Credentials) ([]ComputerRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	results, err := client.SearchWithPaging(baseDN, computersFilter(), computersAttributes(), 100)
	if err != nil {
		return nil, err
	}

	rows := make([]ComputerRow, 0, len(results.Entries))
	for _, entry := range results.Entries {
		osName := entry.GetAttributeValue("operatingSystem")
		if osVer := entry.GetAttributeValue("operatingSystemVersion"); osVer != "" {
			osName = fmt.Sprintf("%s (%s)", osName, osVer)
		}
		rows = append(rows, ComputerRow{
			Name:    entry.GetAttributeValue("sAMAccountName"),
			DNSHost: entry.GetAttributeValue("dNSHostName"),
			OS:      osName,
		})
	}
	return rows, nil
}
