package smbclient

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc/winreg"
)

// portFwdTcpip6Key holds the IPv6 transition stack configuration.
// DisabledComponents (REG_DWORD bitmask) lives here; the value exists only
// once an admin has changed it — absent means the default 0, every
// component enabled.
const portFwdTcpip6Key = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`

// portFwdHelperService is the IP Helper service, owner of the portproxy
// relay engine: it reads the PortProxy registry rules (portfwd.go) only at
// service start.
const portFwdHelperService = "iphlpsvc"

// PortFwdStep is one activation/deactivation step's outcome.
type PortFwdStep struct {
	Name   string // "ipv6 check" | "firewall rule" | "iphlpsvc restart"
	Detail string // free-form result, e.g. "rule anv-portfwd-8445 added"
	Err    error  // nil on success
}

// PortFwdFirewallRuleName renders the firewall rule name for a listen
// endpoint: "anv-portfwd-<port>". Only the port matters — one inbound
// allow per listen port is what the relay needs regardless of the address
// it binds, and the name must come out identical between add and delete.
//
// listen is normally "host:port"; the host part is ignored, so bracketed
// IPv6 forms work too. A bare numeric port ("8445") is accepted as a
// convenience. Malformed input degrades to the text after the last colon
// (or the whole string when there is none): deterministic, never an error
// — this function only names endpoints; parseListenConnect (portfwd.go) is
// what keeps invalid ones off the wire.
func PortFwdFirewallRuleName(listen string) string {
	port := listen
	if _, p, err := net.SplitHostPort(listen); err == nil {
		port = p
	} else if i := strings.LastIndex(listen, ":"); i >= 0 && i < len(listen)-1 {
		port = listen[i+1:]
	}
	return "anv-portfwd-" + port
}

// PortFwdActivate brings a freshly written v4tov4 portproxy rule live. The
// shell has already stored the rule with PortFwdAdd (which documents why a
// bare registry write is inert until iphlpsvc cycles); this performs the
// three remaining activation steps. Every step runs even when an earlier
// one failed — partial failure must surface in the shell's output, never
// abort the sequence — so the returned slice always holds all three steps
// in order: ipv6 check, firewall rule, iphlpsvc restart.
//
// Why these steps, on real Windows:
//   - portproxy rides the IPv6 transition stack: the relay is terminated
//     through that stack, so DisabledComponents=0xff (all transition
//     components off) leaves a configured relay inert. The check reads the
//     value to name that condition instead of letting the rule fail
//     silently. Samba has no Tcpip6 key, so there the read error itself is
//     the reported finding.
//   - `netsh interface portproxy` does NOT open the firewall: it writes the
//     registry rule and cycles iphlpsvc, nothing more. The inbound allow
//     for the listen port is added separately here via the Exec channel
//     (netsh advfirewall over TSCH, as LocalSystem — no winrm needed).
//   - iphlpsvc reads the PortProxy rules only at service start; cycling the
//     service activates the new rule without a reboot.
//
// connect is the rule's relay target, kept in the signature for symmetry
// with the shell's add flow; the steps themselves need only the listen
// port, because the registry value written by PortFwdAdd already binds
// listen to connect.
func (s *Session) PortFwdActivate(connect string, listenPort int) []PortFwdStep {
	// Derive the name through an empty-host listen form so the rule prefix
	// has exactly one definition (PortFwdFirewallRuleName).
	ruleName := PortFwdFirewallRuleName(fmt.Sprintf(":%d", listenPort))
	return []PortFwdStep{
		s.portFwdIPv6Check(),
		s.portFwdFirewallRule(ruleName, listenPort, true),
		s.portFwdRestartHelper(),
	}
}

// PortFwdDeactivate tears a relay down after the shell has removed the
// registry rule with PortFwdRemove: the firewall allow is deleted and
// iphlpsvc is cycled. The restart matters just as much as at activation —
// the rules are read only at service start, so a rule deleted from the
// registry keeps relaying until the service cycles. There is no ipv6 step:
// a relay being removed cannot be inert. Both steps always run and both
// outcomes are returned, in order.
func (s *Session) PortFwdDeactivate(listenPort int) []PortFwdStep {
	ruleName := PortFwdFirewallRuleName(fmt.Sprintf(":%d", listenPort))
	return []PortFwdStep{
		s.portFwdFirewallRule(ruleName, listenPort, false),
		s.portFwdRestartHelper(),
	}
}

// portFwdIPv6Check reads DisabledComponents to detect the one configuration
// that silently kills portproxy: 0xff disables the whole IPv6 transition
// stack the v4tov4 relay is built on. Read failures split two ways: on
// stock Windows the VALUE is normally absent (the key exists, the default
// is 0 — IPv6 fully enabled), which is a pass, while Samba lacks the whole
// Tcpip6 key, which stays a warning. The two are told apart by the winreg
// error text: BaseRegQueryValue ... 0x00000002 is the missing-value case,
// BaseRegOpenKey is the missing-key one. A successful read is informational
// only — even 0xff carries a nil Err, because activation can still proceed
// and the shell just needs the warning visible in Detail.
func (s *Session) portFwdIPv6Check() PortFwdStep {
	step := PortFwdStep{Name: "ipv6 check"}
	val, err := s.RegQueryValue(portFwdTcpip6Key, "DisabledComponents")
	if err != nil {
		if strings.Contains(err.Error(), "BaseRegQueryValue") &&
			strings.Contains(err.Error(), "0x00000002") {
			step.Detail = "DisabledComponents absent (default 0 — IPv6 enabled)"
			return step
		}
		step.Err = err
		return step
	}
	// The value is documented REG_DWORD; anything else (or a short blob)
	// cannot be interpreted as the bitmask, so it is a read anomaly, not a
	// finding.
	if val.Type != winreg.REG_DWORD || len(val.Data) < 4 {
		step.Err = fmt.Errorf("DisabledComponents: want REG_DWORD, got %s (%d bytes)",
			RegTypeName(val.Type), len(val.Data))
		return step
	}
	v := binary.LittleEndian.Uint32(val.Data)
	step.Detail = fmt.Sprintf("DisabledComponents=0x%02x", v)
	if v == 0xff {
		step.Detail = "DisabledComponents=0xff (IPv6 disabled — portproxy inert)"
	}
	return step
}

// portFwdFirewallRule adds (add=true) or deletes the inbound allow for the
// relay's listen port: `netsh interface portproxy` never touches the
// firewall, so the allow is managed separately here through the Exec
// channel. Caveat carried over from exec.go: Exec surfaces scheduler and
// transport failures, but netsh's own exit code is lost to the output
// redirect — a rule netsh rejected still reads as success in Detail.
// Exec's cleanup warnings (leftover task/output file) have no channel in
// the step contract and are dropped.
func (s *Session) portFwdFirewallRule(ruleName string, port int, add bool) PortFwdStep {
	step := PortFwdStep{Name: "firewall rule"}
	cmd := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, ruleName)
	if add {
		cmd = fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%d`, ruleName, port)
	}
	if _, _, err := s.Exec(cmd); err != nil {
		step.Err = err
		return step
	}
	if add {
		step.Detail = fmt.Sprintf("rule %s added", ruleName)
	} else {
		step.Detail = fmt.Sprintf("rule %s deleted", ruleName)
	}
	return step
}

// portFwdRestartHelper cycles iphlpsvc so it re-reads the PortProxy rules.
// Stop-then-start, never a single restart control (SCMR has no such op);
// when the stop fails the start is not attempted — the service still runs
// with the old rule set, and the stop error is the finding to report.
func (s *Session) portFwdRestartHelper() PortFwdStep {
	step := PortFwdStep{Name: "iphlpsvc restart"}
	if err := s.StopService(portFwdHelperService); err != nil {
		step.Err = err
		return step
	}
	if err := s.StartService(portFwdHelperService); err != nil {
		step.Err = err
		return step
	}
	step.Detail = "restarted"
	return step
}
