// Package lsa parses and decrypts LSA secrets and cached domain logons
// (MSCashV2) from SECURITY+SYSTEM registry hive bytes, secretsdump-style.
// It is pure (no I/O, no network): all hive access happens via gopacket's
// pkg/registry on caller-supplied bytes.
package lsa

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/registry"
)

// Secret is one decrypted LSA secret.
type Secret struct {
	Name  string
	Value []byte
}

// CachedLogon is one MSCashV2 cached domain logon.
type CachedLogon struct {
	Domain string
	User   string
	Hash   []byte // MSCashV2 material as stored (the crackable form)
}

// DPAPIKeys are the DPAPI machine/user keys from the DPAPI_SYSTEM secret.
type DPAPIKeys struct {
	MachineKey []byte
	UserKey    []byte
}

// DPAPI returns the raw DPAPI machine and user masterkeys, if the SECURITY
// hive had a DPAPI_SYSTEM secret. Rendered output (Lines) is unchanged;
// this just exposes the bytes for blob decryption.
func (r *Result) DPAPI() (machineKey, userKey []byte, ok bool) {
	if r.dpapi == nil {
		return nil, nil, false
	}
	return r.dpapi.MachineKey, r.dpapi.UserKey, true
}

// Result is everything extracted from a SECURITY hive. Missing pieces (no
// cached logons, no machine account secret, no DPAPI keys) are not errors.
type Result struct {
	Secrets       []Secret
	CachedLogons  []CachedLogon
	Domain        string // NetBIOS domain name
	DNSDomain     string
	ComputerName  string
	machineSecret []byte
	dpapi         *DPAPIKeys
}

// Dump parses SYSTEM and SECURITY hive bytes, derives the boot key from
// SYSTEM, and decrypts LSA secrets and cached domain logons from SECURITY.
func Dump(systemData, securityData []byte) (*Result, error) {
	systemHive, err := registry.Open(systemData)
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM hive: %v", err)
	}
	secHive, err := registry.Open(securityData)
	if err != nil {
		return nil, fmt.Errorf("parse SECURITY hive: %v", err)
	}

	bootKey, err := registry.GetBootKey(systemHive)
	if err != nil {
		return nil, fmt.Errorf("derive boot key: %v", err)
	}

	res := &Result{}
	if di, err := registry.GetDomainInfo(secHive); err == nil {
		res.Domain = di.NetBIOSName
		res.DNSDomain = di.DNSDomainName
		res.ComputerName = di.ComputerName
	}

	secrets, err := registry.DumpLSASecrets(secHive, bootKey)
	if err != nil {
		return nil, fmt.Errorf("dump LSA secrets: %v", err)
	}
	for _, s := range secrets {
		if len(s.Value) == 0 {
			continue
		}
		res.Secrets = append(res.Secrets, Secret{Name: s.Name, Value: s.Value})
		if strings.Contains(s.Name, "$MACHINE.ACC") {
			res.machineSecret = s.Value
		}
		if s.Name == "DPAPI_SYSTEM" {
			if keys := registry.ParseDPAPISecret(s.Value); keys != nil {
				res.dpapi = &DPAPIKeys{MachineKey: keys.MachineKey, UserKey: keys.UserKey}
			}
		}
	}

	creds, err := registry.DumpCachedCredentials(secHive, bootKey)
	if err != nil {
		return nil, fmt.Errorf("dump cached credentials: %v", err)
	}
	for _, c := range creds {
		if c.Username == "" {
			continue
		}
		res.CachedLogons = append(res.CachedLogons, CachedLogon{
			Domain: c.Domain,
			User:   c.Username,
			Hash:   c.EncryptedHash,
		})
	}
	return res, nil
}

// FormatCached renders one cached logon as DOMAIN/user:hash
// (tools/secretsdump's format).
func FormatCached(c CachedLogon) string {
	return fmt.Sprintf("%s/%s:%s", c.Domain, c.User, hex.EncodeToString(c.Hash))
}

// Lines renders the LSA secrets output (secretsdump format): machine
// account keys, DPAPI keys, and remaining secrets as name:hex.
func (r *Result) Lines() []string {
	var lines []string
	lines = append(lines, r.machineAccountLines()...)
	if r.dpapi != nil {
		lines = append(lines,
			fmt.Sprintf("dpapi_machinekey:0x%s", hex.EncodeToString(r.dpapi.MachineKey)),
			fmt.Sprintf("dpapi_userkey:0x%s", hex.EncodeToString(r.dpapi.UserKey)))
	}
	for _, s := range r.Secrets {
		if strings.Contains(s.Name, "$MACHINE.ACC") || s.Name == "DPAPI_SYSTEM" {
			continue // covered by the dedicated renderings above
		}
		lines = append(lines, fmt.Sprintf("%s:%s", s.Name, hex.EncodeToString(s.Value)))
	}
	return lines
}

// machineAccountLines derives the machine account key lines from the
// $MACHINE.ACC secret (tools/secretsdump's format), or nil if absent.
func (r *Result) machineAccountLines() []string {
	if r.machineSecret == nil {
		return nil
	}
	computer := r.ComputerName
	if computer == "" {
		computer = "UNKNOWN"
	}
	keys := registry.DeriveMachineAccountKeys(r.machineSecret, r.DNSDomain, computer)
	prefix := r.Domain + `\` + computer + "$"

	var lines []string
	if keys.AES256Key != nil {
		lines = append(lines, fmt.Sprintf("%s:aes256-cts-hmac-sha1-96:%s", prefix, hex.EncodeToString(keys.AES256Key)))
	}
	if keys.AES128Key != nil {
		lines = append(lines, fmt.Sprintf("%s:aes128-cts-hmac-sha1-96:%s", prefix, hex.EncodeToString(keys.AES128Key)))
	}
	if keys.DESKey != nil {
		lines = append(lines, fmt.Sprintf("%s:des-cbc-md5:%s", prefix, hex.EncodeToString(keys.DESKey)))
	}
	lines = append(lines, fmt.Sprintf("%s:plain_password_hex:%s", prefix, hex.EncodeToString(r.machineSecret)))
	if keys.NTHash != nil {
		lines = append(lines, fmt.Sprintf("%s:aad3b435b51404eeaad3b435b51404ee:%s:::",
			prefix, hex.EncodeToString(keys.NTHash)))
	}
	return lines
}
