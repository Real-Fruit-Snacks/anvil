package scan

import "testing"

func TestServiceName(t *testing.T) {
	cases := []struct {
		port int
		want string
	}{
		{53, "dns"},
		{88, "kerberos"},
		{445, "smb"},
		{3268, "gc"},
		{5985, "winrm"},
		{5986, "winrm-ssl"},
		{9999, "unknown"},
		{0, "unknown"},
	}
	for _, c := range cases {
		if got := ServiceName(c.port); got != c.want {
			t.Errorf("ServiceName(%d) = %q, want %q", c.port, got, c.want)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	if len(DefaultPorts) != 14 {
		t.Errorf("DefaultPorts has %d entries, want 14", len(DefaultPorts))
	}
	want := map[int]string{
		53: "dns", 88: "kerberos", 135: "msrpc", 139: "netbios-ssn",
		389: "ldap", 445: "smb", 464: "kpasswd", 636: "ldaps",
		1433: "mssql", 3268: "gc", 3269: "gc-ssl", 3389: "rdp",
		5985: "winrm", 5986: "winrm-ssl",
	}
	seen := map[int]bool{}
	for _, d := range DefaultPorts {
		if want[d.Port] != d.Service {
			t.Errorf("port %d: service %q, want %q", d.Port, d.Service, want[d.Port])
		}
		seen[d.Port] = true
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("port %d missing from DefaultPorts", p)
		}
	}
}

// hintProfile builds a profile with the given open ports and SMB state.
func hintProfile(openPorts []int, smb *SMBInfo) (*TargetProfile, func(int) bool) {
	p := &TargetProfile{SMB: smb}
	for _, port := range []int{88, 389, 445, 1433, 3268, 5985, 5986} {
		open := false
		for _, op := range openPorts {
			if op == port {
				open = true
				break
			}
		}
		p.Ports = append(p.Ports, PortResult{Port: port, Service: ServiceName(port), Open: open})
	}
	open := func(port int) bool {
		for _, pr := range p.Ports {
			if pr.Port == port {
				return pr.Open
			}
		}
		return false
	}
	return p, open
}

func TestBuildHints(t *testing.T) {
	t.Run("domain controller", func(t *testing.T) {
		p, open := hintProfile([]int{88, 389, 3268}, nil)
		hints := buildHints(p, open)
		if len(hints) != 1 || hints[0] != "likely domain controller (kerberos + ldap + gc open)" {
			t.Errorf("hints = %v", hints)
		}
	})

	t.Run("no dc hint when gc closed", func(t *testing.T) {
		p, open := hintProfile([]int{88, 389}, nil)
		if hints := buildHints(p, open); len(hints) != 0 {
			t.Errorf("hints = %v, want none", hints)
		}
	})

	t.Run("relay candidate", func(t *testing.T) {
		p, open := hintProfile([]int{445}, &SMBInfo{Probed: true, Dialect: "SMB 3.1.1", SigningRequired: false})
		hints := buildHints(p, open)
		if len(hints) != 1 || hints[0] != "SMB signing not required (relay candidate)" {
			t.Errorf("hints = %v", hints)
		}
	})

	t.Run("no relay when signing required", func(t *testing.T) {
		p, open := hintProfile([]int{445}, &SMBInfo{Probed: true, Dialect: "SMB 3.1.1", SigningRequired: true})
		if hints := buildHints(p, open); len(hints) != 0 {
			t.Errorf("hints = %v, want none", hints)
		}
	})

	t.Run("no relay when probe failed", func(t *testing.T) {
		p, open := hintProfile([]int{445}, &SMBInfo{Probed: true, Error: "boom"})
		if hints := buildHints(p, open); len(hints) != 0 {
			t.Errorf("hints = %v, want none", hints)
		}
	})

	t.Run("no relay when dialect unknown", func(t *testing.T) {
		p, open := hintProfile([]int{445}, &SMBInfo{Probed: true})
		if hints := buildHints(p, open); len(hints) != 0 {
			t.Errorf("hints = %v, want none", hints)
		}
	})

	t.Run("mssql and winrm", func(t *testing.T) {
		p, open := hintProfile([]int{1433, 5985, 5986}, nil)
		hints := buildHints(p, open)
		if len(hints) != 2 || hints[0] != "MSSQL present" || hints[1] != "WinRM present" {
			t.Errorf("hints = %v", hints)
		}
	})
}
