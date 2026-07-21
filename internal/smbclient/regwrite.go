package smbclient

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
	"github.com/mandiant/gopacket/pkg/utf16le"
)

// Registry write support (MS-RRP BaseRegSetValue/DeleteValue/CreateKey/
// DeleteKey) over the same winreg pipe registry.go reads through — the pipe
// rides the session's IPC$ tree connect, so no new channel is opened. All
// writes need local admin on the target (the RemoteRegistry ACL grants
// Administrators full control of HKLM); failures surface through
// mapRegWriteError.
//
// Note on CurrentControlSet: it is a link to ControlSet00x resolved
// server-side, so writes under it (e.g. PortProxy in portfwd.go) land on
// the live control set without any client-side resolution.

// RegSetValue writes valueName under keyPath (HIVE\path), packing data per
// valType. The key must already exist — create it with RegCreateKey first
// (matches Impacket reg.py, which refuses to create keys implicitly).
// valueName "" addresses the key's default value (@). Data formats:
// REG_SZ/REG_EXPAND_SZ take the string as-is; REG_DWORD/REG_QWORD take
// decimal or 0x-hex; REG_BINARY takes hex pairs (spaces ignored);
// REG_MULTI_SZ takes items separated by '|'. MS-RRP caps value data at
// 1 MB (ERROR_INVALID_PARAMETER beyond it); this client-side surface does
// not need the guard.
func (s *Session) RegSetValue(keyPath, valueName string, valType uint32, data string) error {
	packed, err := packRegValue(valType, data)
	if err != nil {
		return err
	}

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, keyPath)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	if err := winreg.BaseRegSetValue(rpc, hKey, valueName, valType, packed); err != nil {
		return mapRegWriteError(err)
	}
	return nil
}

// RegDeleteValue removes valueName from keyPath. A missing value is an
// error (Windows: ERROR_FILE_NOT_FOUND), themed by mapRegWriteError.
func (s *Session) RegDeleteValue(keyPath, valueName string) error {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, keyPath)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	if err := winreg.BaseRegDeleteValue(rpc, hKey, valueName); err != nil {
		return mapRegWriteError(err)
	}
	return nil
}

// RegCreateKey creates keyPath, including any missing intermediate keys
// (BaseRegCreateKey creates the whole remaining path in one call, like
// RegCreateKeyEx). Existing keys are simply opened and closed — the call
// is idempotent.
func (s *Session) RegCreateKey(keyPath string) error {
	hive, subKey := splitHive(keyPath)
	if subKey == "" {
		return fmt.Errorf("cannot create a bare hive root (%s)", hive)
	}

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	root, err := openHive(rpc, hive)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, root)

	hKey, err := winreg.BaseRegCreateKey(rpc, root, subKey, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		return mapRegWriteError(err)
	}
	winreg.BaseRegCloseKey(rpc, hKey)
	return nil
}

// RegDeleteKey removes keyPath. Windows refuses to delete a key that still
// has subkeys (BaseRegDeleteKey is the pre-Vista RegDeleteKey semantics —
// it returns ERROR_ACCESS_DENIED, rendered by mapRegWriteError), so delete
// nested trees leaf-first. Values on the key do not block deletion; they
// are removed with it.
func (s *Session) RegDeleteKey(keyPath string) error {
	hive, subKey := splitHive(keyPath)
	if subKey == "" {
		return fmt.Errorf("refusing to delete a bare hive root (%s)", hive)
	}

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	// BaseRegDeleteKey operates relative to the PARENT handle: split off
	// the leaf, open the parent (a top-level key deletes relative to the
	// hive root itself), then delete by leaf name.
	leaf := subKey
	parent, err := openHive(rpc, hive)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, parent)

	if i := strings.LastIndex(subKey, `\`); i >= 0 {
		leaf = subKey[i+1:]
		p, err := winreg.BaseRegOpenKey(rpc, parent, subKey[:i], 0, winreg.MAXIMUM_ALLOWED)
		if err != nil {
			return mapRegWriteError(err)
		}
		defer winreg.BaseRegCloseKey(rpc, p)
		parent = p
	}

	if err := winreg.BaseRegDeleteKey(rpc, parent, leaf); err != nil {
		return mapRegWriteError(err)
	}
	return nil
}

// RegSearchHit is one case-insensitive substring match from RegSearch: a
// subkey whose name matched (ValueName ""), or a value whose name matched
// under Path (ValueType carries its REG_* type).
type RegSearchHit struct {
	Path      string // full path of the matching key, or of the key holding the value
	ValueName string // "" for key-name matches
	ValueType uint32 // REG_* type; meaningful only when ValueName != ""
}

// RegSearch walks the tree under root (HIVE\path) looking for pattern as a
// case-insensitive substring of key names and value names — value DATA is
// not matched. maxDepth bounds descent: 0 searches only root's values and
// immediate subkey names, 1 descends one level, and so on; a negative
// maxDepth is unlimited (dangerous on large trees — every key is an RPC
// round trip). limit caps returned hits; <= 0 means no cap. Keys that deny
// access are skipped silently — parts of HKLM (SAM, SECURITY subkeys)
// refuse even Administrators, and aborting the whole search on the first
// denial would make it useless.
func (s *Session) RegSearch(root, pattern string, maxDepth, limit int) ([]RegSearchHit, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty search pattern")
	}

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, root)
	if err != nil {
		return nil, mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	needle := strings.ToLower(pattern)
	var hits []RegSearchHit
	searchKey(rpc, hKey, strings.TrimSuffix(root, `\`), needle, 0, maxDepth, limit, &hits)
	return hits, nil
}

// searchKey is the recursive walk. Returns false once limit is reached so
// the whole stack unwinds without further RPC calls.
func searchKey(rpc *dcerpc.Client, hKey []byte, path, needle string, depth, maxDepth, limit int, hits *[]RegSearchHit) bool {
	info, err := winreg.BaseRegQueryInfoKey(rpc, hKey)
	if err != nil {
		return true // unreadable key — skip, keep searching elsewhere
	}

	// Value-name matches at this key. MaxValueDataLen comes from
	// QueryInfoKey: passing a small buffer here makes Windows answer
	// ERROR_MORE_DATA for any larger value, which gopacket surfaces as an
	// error and would silently end the value loop.
	for i := uint32(0); i < info.Values; i++ {
		name, valType, _, err := winreg.BaseRegEnumValue(rpc, hKey, i, info.MaxValueNameLen+1, info.MaxValueDataLen)
		if err != nil {
			break
		}
		if strings.Contains(strings.ToLower(name), needle) {
			*hits = append(*hits, RegSearchHit{Path: path, ValueName: name, ValueType: valType})
			if limit > 0 && len(*hits) >= limit {
				return false
			}
		}
	}

	// Subkey name matches, then descend within the depth bound.
	for i := uint32(0); i < info.SubKeys; i++ {
		name, _, err := winreg.BaseRegEnumKey(rpc, hKey, i)
		if err != nil {
			break
		}
		subPath := path + `\` + name
		if strings.Contains(strings.ToLower(name), needle) {
			*hits = append(*hits, RegSearchHit{Path: subPath})
			if limit > 0 && len(*hits) >= limit {
				return false
			}
		}
		if maxDepth >= 0 && depth >= maxDepth {
			continue // name matched above, but too deep to open
		}
		sub, err := winreg.BaseRegOpenKey(rpc, hKey, name, 0, winreg.KEY_READ)
		if err != nil {
			continue // access denied (SAM/SECURITY subkeys) — skip
		}
		cont := searchKey(rpc, sub, subPath, needle, depth+1, maxDepth, limit, hits)
		winreg.BaseRegCloseKey(rpc, sub)
		if !cont {
			return false
		}
	}
	return true
}

// packRegValue renders the string form of a value into the wire bytes for
// its REG_* type. String types are UTF-16LE with the terminating NUL the
// registry stores (RegSetValueEx semantics — the NUL is part of cbData);
// REG_MULTI_SZ is NUL-separated items with a double-NUL terminator.
// Numbers accept decimal or 0x-prefixed hex; bare leading-zero decimals
// stay decimal (strconv base 0 would misread "010" as octal).
func packRegValue(valType uint32, data string) ([]byte, error) {
	switch valType {
	case winreg.REG_SZ, winreg.REG_EXPAND_SZ:
		return append(utf16le.EncodeStringToBytes(data), 0, 0), nil
	case winreg.REG_DWORD, winreg.REG_QWORD:
		bits := 32
		if valType == winreg.REG_QWORD {
			bits = 64
		}
		s := strings.TrimSpace(data)
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			base, s = 16, s[2:]
		}
		n, err := strconv.ParseUint(s, base, bits)
		if err != nil {
			return nil, fmt.Errorf("%s data %q is not a valid %d-bit number (decimal or 0x-hex)",
				RegTypeName(valType), data, bits)
		}
		buf := make([]byte, bits/8)
		if bits == 32 {
			binary.LittleEndian.PutUint32(buf, uint32(n))
		} else {
			binary.LittleEndian.PutUint64(buf, n)
		}
		return buf, nil
	case winreg.REG_BINARY:
		s := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, data)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("REG_BINARY data must be hex pairs (spaces allowed): %v", err)
		}
		return b, nil
	case winreg.REG_MULTI_SZ:
		// Items separated by '|': commas are common inside real registry
		// strings (DNs, paths with options), pipes are not.
		var out []byte
		for _, item := range strings.Split(data, "|") {
			out = append(out, utf16le.EncodeStringToBytes(item)...)
			out = append(out, 0, 0)
		}
		return append(out, 0, 0), nil
	default:
		return nil, fmt.Errorf("unsupported type %d (supported: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ)", valType)
	}
}

// RegTypeFromName maps a REG_* name to its type code, case-insensitively,
// with or without the REG_ prefix. The reverse mapping is RegTypeName.
func RegTypeFromName(name string) (uint32, error) {
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(name), "REG_")) {
	case "SZ":
		return winreg.REG_SZ, nil
	case "EXPAND_SZ":
		return winreg.REG_EXPAND_SZ, nil
	case "BINARY":
		return winreg.REG_BINARY, nil
	case "DWORD":
		return winreg.REG_DWORD, nil
	case "QWORD":
		return winreg.REG_QWORD, nil
	case "MULTI_SZ":
		return winreg.REG_MULTI_SZ, nil
	default:
		return 0, fmt.Errorf("unknown registry type %q (supported: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ)", name)
	}
}

// RegTypeName renders a REG_* type code for display (REG_DWORD, ...).
// Unknown codes render as their number.
func RegTypeName(t uint32) string {
	switch t {
	case winreg.REG_SZ:
		return "REG_SZ"
	case winreg.REG_EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case winreg.REG_BINARY:
		return "REG_BINARY"
	case winreg.REG_DWORD:
		return "REG_DWORD"
	case winreg.REG_QWORD:
		return "REG_QWORD"
	case winreg.REG_MULTI_SZ:
		return "REG_MULTI_SZ"
	default:
		return fmt.Sprintf("REG_%d", t)
	}
}

// mapRegWriteError themes the Win32 status codes gopacket's winreg flattens
// into its error strings ("BaseRegSetValue(x) failed: 0x00000005"). Kept
// feature-local (shared errors.go's Describe already handles the generic
// 0x00000005 case; this adds the write-path context).
func mapRegWriteError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x00000005"):
		// ERROR_ACCESS_DENIED — also what Windows returns when deleting a
		// key that still has subkeys (legacy BaseRegDeleteKey semantics).
		return fmt.Errorf("%s (access denied — registry writes need local admin; on delete, the key must have no subkeys)", msg)
	case strings.Contains(msg, "0x00000002"):
		return fmt.Errorf("%s (key or value not found)", msg)
	case strings.Contains(msg, "0x00000057"):
		return fmt.Errorf("%s (invalid parameter)", msg)
	case strings.Contains(msg, "0x000006f7"):
		// EPT_S_NOT_REGISTERED — Samba's winreg has no RRP backend.
		return fmt.Errorf("%s (not supported on this server)", msg)
	}
	return err
}
