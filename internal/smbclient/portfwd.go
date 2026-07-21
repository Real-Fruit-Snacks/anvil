package smbclient

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
)

// portFwdKey is the PortProxy rule store: one REG_SZ value per rule, named
// "<listenaddr>/<listenport>" with data "<connectaddr>/<connectport>" —
// the same layout `netsh interface portproxy add v4tov4` writes.
const portFwdKey = `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

// PortFwdRule is one IPHelper (PortProxy) v4tov4 relay: connections to
// ListenAddr:ListenPort on the target are relayed to ConnectAddr:ConnectPort.
type PortFwdRule struct {
	ListenAddr  string
	ListenPort  int
	ConnectAddr string
	ConnectPort int
}

// String renders the rule as "listen -> connect" for display.
func (r PortFwdRule) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", r.ListenAddr, r.ListenPort, r.ConnectAddr, r.ConnectPort)
}

// PortFwdList returns the v4tov4 portproxy rules on the target. A machine
// whose PortProxy key was never created yields an empty list, not an
// error. Values that don't parse as addr/port pairs are skipped (nothing
// but netsh or this tool should write there, but a malformed entry must
// not break listing the rest).
func (s *Session) PortFwdList() ([]PortFwdRule, error) {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, portFwdKey)
	if err != nil {
		if strings.Contains(err.Error(), "0x00000002") {
			return nil, nil // key absent = portproxy never configured = no rules
		}
		return nil, mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	info, err := winreg.BaseRegQueryInfoKey(rpc, hKey)
	if err != nil {
		if strings.Contains(err.Error(), "0x000006f7") {
			// EPT_S_NOT_REGISTERED — Samba's winreg lacks
			// BaseRegQueryInfoKey; enumerate without its count/buffer hints.
			rules := portFwdEnumValues(rpc, hKey, 256, 16383, 1<<20)
			return rules, nil
		}
		return nil, mapRegWriteError(err)
	}

	rules := portFwdEnumValues(rpc, hKey, info.Values, info.MaxValueNameLen+1, info.MaxValueDataLen)
	return rules, nil
}

// portFwdEnumValues index-walks BaseRegEnumValue, parsing each value as a
// portproxy rule and returning them sorted. The walk stops at the first
// enum error (0x00000002 = no more values; an unregistered op on Samba =
// treat what we have as the whole store). Malformed entries are skipped —
// nothing but netsh or this tool should write there, but a bad entry must
// not break listing the rest.
func portFwdEnumValues(rpc *dcerpc.Client, hKey []byte, count, nameLen, dataLen uint32) []PortFwdRule {
	var rules []PortFwdRule
	for i := uint32(0); i < count; i++ {
		name, _, data, err := winreg.BaseRegEnumValue(rpc, hKey, i, nameLen, dataLen)
		if err != nil {
			break
		}
		rule, err := parsePortFwdRule(name, utf16String(data))
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].ListenAddr != rules[j].ListenAddr {
			return rules[i].ListenAddr < rules[j].ListenAddr
		}
		return rules[i].ListenPort < rules[j].ListenPort
	})
	return rules
}

// PortFwdAdd installs a v4tov4 relay rule: listen and connect are
// "host:port" pairs (IPv4 — the v4tov4 tree only relays IPv4). The
// PortProxy key path is created when missing.
//
// IMPORTANT — activation: the rules are read by the IP Helper service
// (iphlpsvc), not by the registry write itself. `netsh interface
// portproxy` cycles the service internally; a raw registry write (what
// this does) only takes effect once iphlpsvc is restarted or the box
// reboots on several Windows versions (observed on Server 2022). The rule
// survives reboots, so it is also a persistence-flavored primitive — clean
// it up with PortFwdRemove.
func (s *Session) PortFwdAdd(listen, connect string) error {
	rule, err := parseListenConnect(listen, connect)
	if err != nil {
		return err
	}
	name, data := formatPortFwdRule(rule)
	packed, _ := packRegValue(winreg.REG_SZ, data) // REG_SZ packing cannot fail

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	hive, subKey := splitHive(portFwdKey)
	root, err := openHive(rpc, hive)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, root)

	// BaseRegCreateKey creates the whole missing path (PortProxy\v4tov4\tcp)
	// or opens the existing key — same call netsh's store ends up in.
	hKey, err := winreg.BaseRegCreateKey(rpc, root, subKey, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	if err := winreg.BaseRegSetValue(rpc, hKey, name, winreg.REG_SZ, packed); err != nil {
		return mapRegWriteError(err)
	}
	return nil
}

// PortFwdRemove deletes the rule listening on listen ("host:port"). A rule
// that does not exist is an error (Windows: ERROR_FILE_NOT_FOUND).
func (s *Session) PortFwdRemove(listen string) error {
	addr, port, err := splitHostPortChecked(listen)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s/%d", addr, port)

	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, portFwdKey)
	if err != nil {
		return mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	if err := winreg.BaseRegDeleteValue(rpc, hKey, name); err != nil {
		return mapRegWriteError(err)
	}
	return nil
}

// PortFwdClear deletes every rule under the v4tov4 key and returns how
// many were removed. Value names are collected before any deletion —
// deleting mid-enumeration would shift the indexes. The (then empty) key
// itself is left in place, matching `netsh interface portproxy reset`.
func (s *Session) PortFwdClear() (int, error) {
	rpc, cleanup, err := s.openWinreg()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	hKey, err := openRegPath(rpc, portFwdKey)
	if err != nil {
		if strings.Contains(err.Error(), "0x00000002") {
			return 0, nil // no key = nothing to clear
		}
		return 0, mapRegWriteError(err)
	}
	defer winreg.BaseRegCloseKey(rpc, hKey)

	info, err := winreg.BaseRegQueryInfoKey(rpc, hKey)
	if err != nil {
		return 0, mapRegWriteError(err)
	}

	var names []string
	for i := uint32(0); i < info.Values; i++ {
		// MaxValueDataLen, not a small buffer: too-small lpData makes
		// Windows answer ERROR_MORE_DATA, ending the enum loop early.
		name, _, _, err := winreg.BaseRegEnumValue(rpc, hKey, i, info.MaxValueNameLen+1, info.MaxValueDataLen)
		if err != nil {
			break
		}
		names = append(names, name)
	}

	var removed int
	for _, name := range names {
		if err := winreg.BaseRegDeleteValue(rpc, hKey, name); err != nil {
			return removed, fmt.Errorf("cleared %d rules, then failed on %s: %v", removed, name, mapRegWriteError(err))
		}
		removed++
	}
	return removed, nil
}

// parseListenConnect validates the user-facing "host:port" pair into a
// rule. Kept pure so the argument checking is unit-testable without a
// session.
func parseListenConnect(listen, connect string) (PortFwdRule, error) {
	la, lp, err := splitHostPortChecked(listen)
	if err != nil {
		return PortFwdRule{}, fmt.Errorf("listen: %v", err)
	}
	ca, cp, err := splitHostPortChecked(connect)
	if err != nil {
		return PortFwdRule{}, fmt.Errorf("connect: %v", err)
	}
	return PortFwdRule{ListenAddr: la, ListenPort: lp, ConnectAddr: ca, ConnectPort: cp}, nil
}

// splitHostPortChecked splits "host:port" and rejects empty hosts and
// out-of-range ports. IPv4 is what the v4tov4 tree relays; the address is
// not forced through IP parsing because the resolver side of iphlpsvc
// tolerates what netsh writes — but an empty host is never valid.
func splitHostPortChecked(hostport string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not host:port: %v", hostport, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("empty listen/connect address (use 0.0.0.0 for all interfaces)")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q (want 1-65535)", portStr)
	}
	return host, port, nil
}

// parsePortFwdRule parses the on-registry representation: value NAME
// "listenaddr/listenport", value DATA (already UTF-16-decoded)
// "connectaddr/connectport".
func parsePortFwdRule(name, data string) (PortFwdRule, error) {
	la, lp, err := splitFwdEndpoint(name)
	if err != nil {
		return PortFwdRule{}, fmt.Errorf("rule name %q: %v", name, err)
	}
	ca, cp, err := splitFwdEndpoint(data)
	if err != nil {
		return PortFwdRule{}, fmt.Errorf("rule data %q: %v", data, err)
	}
	return PortFwdRule{ListenAddr: la, ListenPort: lp, ConnectAddr: ca, ConnectPort: cp}, nil
}

// formatPortFwdRule renders a rule into its registry value name and data.
func formatPortFwdRule(r PortFwdRule) (name, data string) {
	return fmt.Sprintf("%s/%d", r.ListenAddr, r.ListenPort),
		fmt.Sprintf("%s/%d", r.ConnectAddr, r.ConnectPort)
}

// splitFwdEndpoint splits the registry "addr/port" form (LastIndex, not
// net.SplitHostPort — the separator is '/', and v4 addrs carry no colon).
func splitFwdEndpoint(s string) (string, int, error) {
	i := strings.LastIndex(s, "/")
	if i <= 0 || i == len(s)-1 {
		return "", 0, fmt.Errorf("not in addr/port form")
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", s[i+1:])
	}
	return s[:i], port, nil
}

// utf16String decodes a REG_SZ/REG_EXPAND_SZ blob (UTF-16LE, NUL
// terminated) back to a Go string. The trailing NUL is stripped; embedded
// NULs (REG_MULTI_SZ) are not expected in the PortProxy store.
func utf16String(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
