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
		info.Endpoints = append(info.Endpoints, Endpoint{
			UUID:       ep.UUID,
			Version:    ep.Version,
			Annotation: ep.Annotation,
			Protocol:   ep.Protocol,
			Provider:   ep.Provider,
			Bindings:   ep.Bindings,
		})
	}
	return info
}
