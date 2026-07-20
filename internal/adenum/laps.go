package adenum

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/session"
)

// LAPSRow is one computer's readable LAPS password. Expiry is formatted
// "2006-01-02 15:04:05", or "N/A" when the expiry attribute is unset.
type LAPSRow struct {
	Host     string
	Password string
	Expiry   string
}

// lapsFilter mirrors the query in gopacket's tools/GetLAPSPassword: any
// computer carrying a LAPS v1 (ms-Mcs-AdmPwd) or v2 (msLAPS-Password /
// msLAPS-EncryptedPassword) attribute.
func lapsFilter() string {
	return "(&(objectCategory=computer)(objectClass=computer)" +
		"(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))"
}

// lapsAttrs mirrors tools/GetLAPSPassword's attribute list.
var lapsAttrs = []string{
	"sAMAccountName",
	"ms-Mcs-AdmPwd",                 // LAPS v1 password
	"ms-Mcs-AdmPwdExpirationTime",   // LAPS v1 expiration
	"msLAPS-Password",               // LAPS v2 plaintext (JSON)
	"msLAPS-EncryptedPassword",      // LAPS v2 encrypted
	"msLAPS-PasswordExpirationTime", // LAPS v2 expiration
}

// LAPS reads LAPS passwords for all computers on the DC over LDAP, mirroring
// gopacket's tools/GetLAPSPassword. LAPS v1 (ms-Mcs-AdmPwd) and LAPS v2
// plaintext (msLAPS-Password, JSON) come back directly. LAPS v2 encrypted
// blobs (msLAPS-EncryptedPassword) need MS-GKDI decryption, which anvil does
// not implement — the row is kept with a placeholder password so the host is
// still reported.
func LAPS(dc string, creds *session.Credentials) ([]LAPSRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res, err := client.SearchWithPaging(baseDN, lapsFilter(), lapsAttrs, 100)
	if err != nil {
		return nil, fmt.Errorf("LAPS search: %v", err)
	}

	var rows []LAPSRow
	for _, entry := range res.Entries {
		host := entry.GetAttributeValue("sAMAccountName")

		// LAPS v1.
		if pwd := entry.GetAttributeValue("ms-Mcs-AdmPwd"); pwd != "" {
			rows = append(rows, LAPSRow{
				Host:     host,
				Password: pwd,
				Expiry:   formatLAPSExpiry(entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")),
			})
			continue
		}

		// LAPS v2 plaintext (JSON).
		if j := entry.GetAttributeValue("msLAPS-Password"); j != "" {
			_, pwd, _ := parseLAPSv2JSON(j)
			rows = append(rows, LAPSRow{
				Host:     host,
				Password: pwd,
				Expiry:   formatLAPSExpiry(entry.GetAttributeValue("msLAPS-PasswordExpirationTime")),
			})
			continue
		}

		// LAPS v2 encrypted — GKDI decryption not implemented.
		if enc := entry.GetRawAttributeValue("msLAPS-EncryptedPassword"); len(enc) > 0 {
			rows = append(rows, LAPSRow{
				Host:     host,
				Password: "[encrypted LAPSv2 password]",
				Expiry:   formatLAPSExpiry(entry.GetAttributeValue("msLAPS-PasswordExpirationTime")),
			})
		}
	}
	return rows, nil
}

// parseLAPSv2JSON parses the LAPS v2 JSON payload
// ({"n":"Administrator","t":"...","p":"password"}) into username and
// password. A streaming decoder reads exactly one value, tolerating the
// trailing metadata Windows LAPS appends after the object.
func parseLAPSv2JSON(s string) (username, password string, ok bool) {
	var data struct {
		N string `json:"n"` // username
		T string `json:"t"` // timestamp
		P string `json:"p"` // password
	}
	if err := json.NewDecoder(strings.NewReader(s)).Decode(&data); err != nil {
		return "", "", false
	}
	return data.N, data.P, true
}

// formatLAPSExpiry converts a Windows FILETIME decimal string to
// "2006-01-02 15:04:05" (local time), or "N/A" when unset, zero, or
// unparseable. Mirrors tools/GetLAPSPassword's formatWindowsTime.
func formatLAPSExpiry(fileTimeStr string) string {
	if fileTimeStr == "" || fileTimeStr == "0" {
		return "N/A"
	}

	var fileTime int64
	fmt.Sscanf(fileTimeStr, "%d", &fileTime)
	if fileTime == 0 {
		return "N/A"
	}

	// FILETIME counts 100-ns intervals since 1601-01-01.
	const windowsEpochDiff = 116444736000000000
	unixNano := (fileTime - windowsEpochDiff) * 100
	return time.Unix(0, unixNano).Format("2006-01-02 15:04:05")
}
