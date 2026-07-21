package smbclient

import "testing"

// Only the pure naming helper is unit-tested here. The step orchestration
// (PortFwdActivate / PortFwdDeactivate) has no hermetic seam: every step is
// a live RPC on an authenticated session (winreg read, TSCH exec, SCMR
// stop/start), the package has no transport interface to substitute, and
// faking Session would test the fake rather than the orchestration — the
// steps are exercised against real targets by testenv/scripts/e2e.sh
// instead.

// TestPortFwdFirewallRuleName pins the naming contract: the name derives
// from the port alone (the host is irrelevant to the inbound allow), a
// bare port is accepted, and malformed input degrades to a deterministic
// name rather than an error — validation is parseListenConnect's job
// (portfwd.go), not the namer's.
func TestPortFwdFirewallRuleName(t *testing.T) {
	cases := []struct {
		name   string
		listen string
		want   string
	}{
		{"ipv4 host:port", "10.0.0.1:8445", "anv-portfwd-8445"},
		{"wildcard listen", "0.0.0.0:443", "anv-portfwd-443"},
		{"empty host keeps the port", ":8445", "anv-portfwd-8445"},
		{"bracketed ipv6 host ignored", "[::1]:8445", "anv-portfwd-8445"},
		{"bare port accepted", "8445", "anv-portfwd-8445"},
		// Out of range is still named: this function never validates —
		// PortFwdAdd rejects the listen before any rule is named after it.
		{"out of range port named anyway", "10.0.0.1:99999", "anv-portfwd-99999"},
		// SplitHostPort splits on the colon without numeric checks.
		{"non-numeric port passes through", "host:notaport", "anv-portfwd-notaport"},
		// Fallbacks when no host:port split exists: text after the last
		// colon, or the whole string when there is none. Degenerate but
		// deterministic.
		{"bare ipv6 degrades to last segment", "::1", "anv-portfwd-1"},
		{"no colon degrades to whole string", "hostonly", "anv-portfwd-hostonly"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PortFwdFirewallRuleName(c.listen); got != c.want {
				t.Errorf("PortFwdFirewallRuleName(%q) = %q, want %q", c.listen, got, c.want)
			}
		})
	}
}
