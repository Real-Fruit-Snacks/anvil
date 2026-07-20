// Package adenum implements Active Directory enumeration over LDAP:
// domain users, computers, delegation, and LAPS. Each query opens one
// transient LDAP connection, binds (UPN simple bind, NTLM fallback like
// internal/roast), searches under the default naming context, and
// closes. Filters and attribute lists mirror gopacket's tools/GetAD*
// tools (themselves mirroring Impacket's GetADUsers.py /
// GetADComputers.py).
package adenum

import (
	"fmt"
	"strconv"
	"time"

	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
)

// connect opens one LDAP connection to dc, binds, and returns the client
// plus the default naming context. The caller owns the client and must
// close it. Bind mirrors internal/roast: UPN simple bind first, then
// Login() (DOMAIN\user, NTLM hash, or Kerberos) as fallback.
func connect(dc string, creds *session.Credentials) (*ldap.Client, string, error) {
	client := ldap.NewClient(session.Target{Host: dc}, creds)
	if err := client.Connect(false); err != nil {
		client.Close()
		return nil, "", fmt.Errorf("ldap connect: %v", err)
	}
	loginUser := creds.Username
	if creds.Domain != "" {
		loginUser = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	}
	if err := client.LoginWithUser(loginUser); err != nil {
		if err := client.Login(); err != nil {
			client.Close()
			return nil, "", fmt.Errorf("ldap bind (authenticated user required): %v", err)
		}
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		client.Close()
		return nil, "", fmt.Errorf("naming context: %v", err)
	}
	return client, baseDN, nil
}

// formatFileTime converts a Windows FILETIME string (100-nanosecond
// intervals since 1601-01-01) to a human-readable timestamp, matching
// Impacket's getUnixTime(). Copied from tools/GetADUsers.
func formatFileTime(s string) string {
	if s == "" || s == "0" {
		return "<never>"
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "N/A"
	}
	// Convert Windows FILETIME to Unix timestamp: subtract the epoch
	// difference (1601-01-01 to 1970-01-01) in 100ns intervals, then
	// convert to nanoseconds.
	const epochDiff = 116444736000000000
	unixNano := (ft - epochDiff) * 100
	t := time.Unix(0, unixNano)
	return t.Format("2006-01-02 15:04:05")
}
