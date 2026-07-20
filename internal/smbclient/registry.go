package smbclient

import (
	"fmt"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
)

// RegValue is one registry value.
type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

// RegQuery lists subkeys and values under keyPath (HIVE\path), read-only,
// via the winreg pipe on the existing session's IPC$ (no new connections).
func (s *Session) RegQuery(keyPath string) (subkeys []string, values []RegValue, err error) {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, keyPath)
	if err != nil {
		return nil, nil, err
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	info, err := winreg.BaseRegQueryInfoKey(rpc, hKey)
	if err != nil {
		return nil, nil, err
	}

	for i := uint32(0); i < info.Values; i++ {
		name, valType, data, err := winreg.BaseRegEnumValue(rpc, hKey, i, info.MaxValueNameLen+1, info.MaxValueDataLen)
		if err != nil {
			break // enum end (or per-value failure; return what we have)
		}
		values = append(values, RegValue{Name: name, Type: valType, Data: data})
	}

	for i := uint32(0); i < info.SubKeys; i++ {
		name, _, err := winreg.BaseRegEnumKey(rpc, hKey, i)
		if err != nil {
			break
		}
		subkeys = append(subkeys, name)
	}
	return subkeys, values, nil
}

// RegQueryValue reads one value under keyPath.
func (s *Session) RegQueryValue(keyPath, valueName string) (*RegValue, error) {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, keyPath)
	if err != nil {
		return nil, err
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	valType, data, err := winreg.BaseRegQueryValue(rpc, hKey, valueName)
	if err != nil {
		return nil, err
	}
	return &RegValue{Name: valueName, Type: valType, Data: data}, nil
}

// RegSave exports keyPath to remoteFile on the TARGET's filesystem via
// BaseRegSaveKey (the file is written server-side, not to a share). Hive
// saves (SAM, SECURITY, ...) require admin + backup privilege on the
// target; denials surface as errors. openRegPath uses MAXIMUM_ALLOWED,
// matching tools/reg's save flow.
func (s *Session) RegSave(keyPath, remoteFile string) error {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, keyPath)
	if err != nil {
		return err
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	return winreg.BaseRegSaveKey(rpc, hKey, remoteFile)
}

// openWinreg opens and binds the winreg pipe. cleanup closes the pipe.
// The RemoteRegistry service is demand-start: the first pipe open after
// boot/idle can race the listener registration ("an instance of a named
// pipe cannot be found in the listening state") — retry once after a beat.
func (s *Session) openWinreg() (*dcerpc.Client, func(), error) {
	pipe, err := s.client.OpenPipe("winreg")
	if err != nil && strings.Contains(err.Error(), "listening state") {
		time.Sleep(1500 * time.Millisecond)
		pipe, err = s.client.OpenPipe("winreg")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open winreg pipe: %v", err)
	}
	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(winreg.UUID, winreg.MajorVersion, winreg.MinorVersion); err != nil {
		pipe.Close()
		return nil, nil, fmt.Errorf("bind winreg: %v", err)
	}
	return rpc, func() { pipe.Close() }, nil
}

// openRegPath opens HIVE\sub\key with MAXIMUM_ALLOWED (mirrors tools/reg).
// Hive names are case-insensitive; HKCC has no OpenCurrentConfig in
// pkg/winreg and errors cleanly.
func openRegPath(rpc *dcerpc.Client, keyPath string) ([]byte, error) {
	hive, subKey := splitHive(keyPath)

	root, err := openHive(rpc, hive)
	if err != nil {
		return nil, err
	}
	if subKey == "" {
		return root, nil
	}

	hKey, err := winreg.BaseRegOpenKey(rpc, root, subKey, 0, winreg.MAXIMUM_ALLOWED)
	winreg.BaseRegCloseKey(rpc, root)
	if err != nil {
		return nil, err
	}
	return hKey, nil
}

func splitHive(keyPath string) (hive, subKey string) {
	parts := strings.SplitN(keyPath, `\`, 2)
	hive = strings.ToUpper(parts[0])
	if len(parts) > 1 {
		subKey = parts[1]
	}
	return hive, subKey
}

func openHive(rpc *dcerpc.Client, hive string) ([]byte, error) {
	switch hive {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return winreg.OpenLocalMachine(rpc, winreg.MAXIMUM_ALLOWED)
	case "HKCU", "HKEY_CURRENT_USER":
		return winreg.OpenCurrentUser(rpc, winreg.MAXIMUM_ALLOWED)
	case "HKCR", "HKEY_CLASSES_ROOT":
		return winreg.OpenClassesRoot(rpc, winreg.MAXIMUM_ALLOWED)
	case "HKU", "HKEY_USERS":
		return winreg.OpenUsers(rpc, winreg.MAXIMUM_ALLOWED)
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return nil, fmt.Errorf("HKCC is not supported (pkg/winreg has no OpenCurrentConfig)")
	default:
		return nil, fmt.Errorf("unknown hive %q (use HKLM, HKCU, HKCR, HKU, HKCC)", hive)
	}
}
