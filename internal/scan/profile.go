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
	// SkewSeconds is the server's clock minus the local clock, taken from
	// the SMB2 NEGOTIATE response's SystemTime. Nil when no negotiate
	// succeeded. |skew| over 5 minutes breaks kerberos.
	SkewSeconds *int64 `json:"clockSkewSeconds,omitempty"`
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
	// Root-DSE extras (same connection): functionality levels mapped to
	// product names where known, SASL mechanisms, and the forest root
	// derived from schemaNamingContext.
	DomainFunctionality string   `json:"domainFunctionality,omitempty"`
	ForestFunctionality string   `json:"forestFunctionality,omitempty"`
	SASLMechanisms      []string `json:"saslMechanisms,omitempty"`
	ForestRoot          string   `json:"forestRoot,omitempty"`
}

// KerberosInfo is the unauthenticated KDC probe: one AS-REQ for a
// deliberately nonexistent principal; the KRB-ERROR reply confirms the
// service and carries the realm.
type KerberosInfo struct {
	Probed   bool   `json:"probed"`
	Error    string `json:"error,omitempty"`
	Realm    string `json:"realm,omitempty"`
	KDCReply string `json:"kdcReply,omitempty"` // symbolic error name, e.g. KDC_ERR_C_PRINCIPAL_UNKNOWN
}

// NullSessionInfo is the anonymous share-enumeration attempt.
type NullSessionInfo struct {
	Probed bool     `json:"probed"`
	Error  string   `json:"error,omitempty"`
	Shares []string `json:"shares,omitempty"`
	// SigningBlocked is true when the target accepted the null logon but
	// the client's mandatory signing (hardwired in pkg/smb) stopped the
	// session — the target's null-session acceptance is itself a finding.
	SigningBlocked bool `json:"signingBlocked,omitempty"`
}

// TLSCertInfo is the leaf certificate one TLS service presents.
type TLSCertInfo struct {
	Port      int       `json:"port"`
	SubjectCN string    `json:"subjectCN,omitempty"`
	IssuerCN  string    `json:"issuerCN,omitempty"`
	SANs      []string  `json:"sans,omitempty"`
	NotAfter  time.Time `json:"notAfter"`
	Expired   bool      `json:"expired,omitempty"`
	DaysLeft  int       `json:"daysLeft"`
}

// TLSInfo is the certificate harvest across the TLS services (636, 3389,
// 5986): one entry per open TLS port. Certificates are captured, not
// trust-validated (self-signed/AD-internal PKI is the norm) — only
// identity and validity dates are reported.
type TLSInfo struct {
	Probed bool          `json:"probed"`
	Error  string        `json:"error,omitempty"`
	Certs  []TLSCertInfo `json:"certs,omitempty"`
}

// ADCSInfo is the AD Certificate Services web-enrollment check: an
// unauthenticated GET of /certsrv/ over HTTP/S. A 401 challenging with
// NTLM means the web enrollment endpoint is present — the ESC8 relay
// target.
type ADCSInfo struct {
	Probed        bool     `json:"probed"`
	Error         string   `json:"error,omitempty"`
	WebEnrollment bool     `json:"webEnrollment"`
	URL           string   `json:"url,omitempty"`
	AuthSchemes   []string `json:"authSchemes,omitempty"`
}

// TDSInfo is the MSSQL prelogin handshake result (port 1433): the server
// version from the prelogin response token stream and whether encryption
// is required. Unauthenticated by design (TDS prelogin precedes auth).
type TDSInfo struct {
	Probed  bool   `json:"probed"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"`
	Encrypt string `json:"encrypt,omitempty"` // "required", "off", "not supported"
}

// RDPInfo is the RDP security-negotiation result (port 3389): whether the
// server demands NLA (CredSSP) — the pre-auth hardening flag — from the
// X.224 negotiation response's selected protocol.
type RDPInfo struct {
	Probed bool   `json:"probed"`
	Error  string `json:"error,omitempty"`
	NLA    *bool  `json:"nla,omitempty"` // true = CredSSP/NLA enforced
}

// TargetProfile is the assembled result of a scan run.
type TargetProfile struct {
	Target      string           `json:"target"`
	ScannedAt   time.Time        `json:"scannedAt"`
	Ports       []PortResult     `json:"ports"`
	SMB         *SMBInfo         `json:"smb,omitempty"`
	RPC         *RPCInfo         `json:"rpc,omitempty"`
	LDAP        *LDAPInfo        `json:"ldap,omitempty"`
	Kerberos    *KerberosInfo    `json:"kerberos,omitempty"`
	NullSession *NullSessionInfo `json:"nullSession,omitempty"`
	TLS         *TLSInfo         `json:"tls,omitempty"`
	ADCS        *ADCSInfo        `json:"adcs,omitempty"`
	TDS         *TDSInfo         `json:"tds,omitempty"`
	RDP         *RDPInfo         `json:"rdp,omitempty"`
	Hints       []string         `json:"hints,omitempty"`
}
