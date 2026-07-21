package scan

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// PortDef pairs a TCP port with its AD-recon service label.
type PortDef struct {
	Port    int
	Service string
}

// DefaultPorts is the phase-1 target set.
var DefaultPorts = []PortDef{
	{53, "dns"},
	{80, "http"},
	{88, "kerberos"},
	{135, "msrpc"},
	{139, "netbios-ssn"},
	{389, "ldap"},
	{443, "https"},
	{445, "smb"},
	{464, "kpasswd"},
	{636, "ldaps"},
	{1433, "mssql"},
	{3268, "gc"},
	{3269, "gc-ssl"},
	{3389, "rdp"},
	{5985, "winrm"},
	{5986, "winrm-ssl"},
}

// ServiceName returns the AD-recon service label for a port, or "unknown".
func ServiceName(port int) string {
	for _, d := range DefaultPorts {
		if d.Port == port {
			return d.Service
		}
	}
	return "unknown"
}

// scanPorts TCP-connects every port concurrently (bounded worker pool) and
// returns results sorted by port number.
func scanPorts(target string, defs []PortDef, timeout time.Duration) []PortResult {
	const maxWorkers = 64

	jobs := make(chan PortDef, len(defs))
	results := make(chan PortResult, len(defs))

	workers := maxWorkers
	if len(defs) < workers {
		workers = len(defs)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				addr := net.JoinHostPort(target, strconv.Itoa(d.Port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				open := err == nil
				if open {
					conn.Close()
				}
				results <- PortResult{Port: d.Port, Service: d.Service, Open: open}
			}
		}()
	}

	for _, d := range defs {
		jobs <- d
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]PortResult, 0, len(defs))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
