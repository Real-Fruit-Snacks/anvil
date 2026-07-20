// Package scan implements anvil's unauthenticated target profiler.
package scan

import "time"

// PortResult is the reachability verdict for one TCP port.
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
}

// SMBInfo is the unauthenticated SMB fingerprint.
type SMBInfo struct {
	Probed          bool   `json:"probed"`
	Error           string `json:"error,omitempty"`
	SMB1Enabled     bool   `json:"smb1Enabled"`
	Dialect         string `json:"dialect,omitempty"`
	SigningEnabled  bool   `json:"signingEnabled"`
	SigningRequired bool   `json:"signingRequired"`
	OSVersion       string `json:"osVersion,omitempty"`
	NBDomain        string `json:"nbDomain,omitempty"`
	NBComputer      string `json:"nbComputer,omitempty"`
	DNSComputer     string `json:"dnsComputer,omitempty"`
	DNSDomain       string `json:"dnsDomain,omitempty"`
}

// Endpoint mirrors one RPC endpoint mapper entry.
type Endpoint struct {
	UUID       string   `json:"uuid"`
	Version    string   `json:"version"`
	Annotation string   `json:"annotation"`
	Protocol   string   `json:"protocol"`
	Provider   string   `json:"provider"`
	Bindings   []string `json:"bindings,omitempty"`
}

// RPCInfo is the endpoint mapper dump.
type RPCInfo struct {
	Probed    bool       `json:"probed"`
	Port      int        `json:"port"`
	Error     string     `json:"error,omitempty"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

// LDAPInfo is the LDAP posture: signing (389), channel binding (636), root DSE.
type LDAPInfo struct {
	Probed          bool   `json:"probed"`
	Error           string `json:"error,omitempty"`
	SigningRequired *bool  `json:"signingRequired,omitempty"`
	ChannelBinding  string `json:"channelBinding,omitempty"`
	NamingContext   string `json:"namingContext,omitempty"`
	DCFunctionality string `json:"domainControllerFunctionality,omitempty"`
	DNSHostName     string `json:"dnsHostName,omitempty"`
}

// TargetProfile is the assembled result of a scan run.
type TargetProfile struct {
	Target    string       `json:"target"`
	ScannedAt time.Time    `json:"scannedAt"`
	Ports     []PortResult `json:"ports"`
	SMB       *SMBInfo     `json:"smb,omitempty"`
	RPC       *RPCInfo     `json:"rpc,omitempty"`
	LDAP      *LDAPInfo    `json:"ldap,omitempty"`
	Hints     []string     `json:"hints,omitempty"`
}
