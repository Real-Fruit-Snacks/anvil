package scan

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/epmapper"
)

// probeRPC dumps the RPC endpoint mapper on target:port without
// authentication (mirrors gopacket tools/rpcdump via TCP).
func probeRPC(target string, port int, timeout time.Duration) *RPCInfo {
	info := &RPCInfo{Probed: true, Port: port}
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		info.Error = fmt.Sprintf("connect: %v", err)
		return info
	}
	defer conn.Close()

	// Bound the whole dump; a large endpoint list takes several round trips.
	deadline := 4 * timeout
	if deadline < 10*time.Second {
		deadline = 10 * time.Second
	}
	conn.SetDeadline(time.Now().Add(deadline))

	client := dcerpc.NewClientTCP(dcerpc.NewTCPTransport(conn))
	if err := client.Bind(epmapper.UUID, epmapper.MajorVersion, epmapper.MinorVersion); err != nil {
		info.Error = fmt.Sprintf("bind: %v", err)
		return info
	}

	eps, err := epmapper.NewEpmClient(client).Lookup()
	if err != nil {
		info.Error = fmt.Sprintf("lookup: %v", err)
		return info
	}

	for _, ep := range eps {
		annotation := ep.Annotation
		if annotation == "" {
			// The ept_entry_t annotation is server-supplied and most
			// endpoints leave it empty (Samba annotates almost nothing;
			// Windows annotates only a few, e.g. "Spooler function
			// endpoint"). Fall back to the well-known UUID dictionary so
			// the AD-relevant interfaces are still named — but never
			// replace an annotation the EPM itself returned.
			if a, ok := UUIDAnnotation(ep.UUID); ok {
				annotation = a
			}
		}
		info.Endpoints = append(info.Endpoints, Endpoint{
			UUID:       ep.UUID,
			Version:    ep.Version,
			Annotation: annotation,
			Protocol:   ep.Protocol,
			Provider:   ep.Provider,
			Bindings:   ep.Bindings,
		})
	}
	return info
}
