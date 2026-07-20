package smbclient

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/samr"
	"github.com/mandiant/gopacket/pkg/dcerpc/srvsvc"
	"github.com/mandiant/gopacket/pkg/dcerpc/wkssvc"
)

// Enumeration over DCE/RPC named pipes riding the existing SMB session's
// IPC$ share — no new connections, mirroring gopacket's tools/netview
// (srvsvc) and tools/samrdump (samr).

// SessionInfo is one connected SMB session (srvsvc NetrSessionEnum).
type SessionInfo struct {
	Username   string
	Source     string // client host (Cname with leading \\ stripped)
	ActiveTime uint32 // seconds
	IdleTime   uint32 // seconds
}

// EnumSessions enumerates active sessions on the server via srvsvc
// NetrSessionEnum (level 10).
func (s *Session) EnumSessions() ([]SessionInfo, error) {
	pipe, err := s.client.OpenPipe("srvsvc")
	if err != nil {
		return nil, fmt.Errorf("open srvsvc pipe: %v", err)
	}
	defer pipe.Close()

	client := dcerpc.NewClient(pipe)
	if err := client.Bind(srvsvc.UUID, srvsvc.MajorVersion, srvsvc.MinorVersion); err != nil {
		return nil, fmt.Errorf("bind srvsvc: %v", err)
	}

	infos, err := srvsvc.NetrSessionEnum(client)
	if err != nil {
		return nil, err
	}

	out := make([]SessionInfo, 0, len(infos))
	for _, si := range infos {
		out = append(out, SessionInfo{
			Username:   si.Username,
			Source:     strings.TrimPrefix(si.Cname, "\\\\"),
			ActiveTime: si.ActiveTime,
			IdleTime:   si.IdleTime,
		})
	}
	return out, nil
}

// UserInfo is one domain account (samr).
type UserInfo struct {
	Name     string
	RID      uint32
	FullName string
	Comment  string // AdminComment, else UserComment
}

// openSAMR connects to the SAMR pipe on the existing session's IPC$ and
// opens the first non-Builtin domain (mirrors tools/samrdump's flow). The
// returned cleanup closes the SAMR client and the pipe.
func (s *Session) openSAMR() (*samr.SamrClient, func(), error) {
	// SAMR needs the SMB session key (per samrdump). On the NTLM path it
	// comes from pkg/smb's initiator; on the kerberos path we stored it at
	// connect time.
	sessionKey := s.client.GetSessionKey()
	if len(sessionKey) == 0 {
		sessionKey = s.smbSessionKey
	}
	if len(sessionKey) == 0 {
		return nil, nil, fmt.Errorf("no SMB session key (required for SAMR)")
	}

	pipe, err := s.client.OpenPipe("samr")
	if err != nil {
		return nil, nil, fmt.Errorf("open samr pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		pipe.Close()
		return nil, nil, fmt.Errorf("bind samr: %v", err)
	}

	sc := samr.NewSamrClient(rpcClient, sessionKey)
	if err := sc.Connect(); err != nil {
		pipe.Close()
		return nil, nil, fmt.Errorf("samr connect: %v", err)
	}
	cleanup := func() {
		sc.Close()
		pipe.Close()
	}

	domains, err := sc.EnumerateDomains()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("enumerate domains: %v", err)
	}

	domainName := ""
	for _, d := range domains {
		if !strings.EqualFold(d, "Builtin") {
			domainName = d
			break
		}
	}
	if domainName == "" {
		cleanup()
		return nil, nil, fmt.Errorf("no non-Builtin domain found")
	}

	if err := sc.OpenDomain(domainName); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open domain: %v", err)
	}
	return sc, cleanup, nil
}

// EnumUsers enumerates domain users via SAMR, mirroring tools/samrdump:
// enumerate, then one QueryUserInfo round trip per user for
// FullName/Comment.
func (s *Session) EnumUsers() ([]UserInfo, error) {
	sc, cleanup, err := s.openSAMR()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	users, err := sc.EnumerateDomainUsers()
	if err != nil {
		return nil, err
	}

	out := make([]UserInfo, 0, len(users))
	for _, u := range users {
		ui := UserInfo{Name: u.Name, RID: u.RID}
		if h, err := sc.OpenUser(u.RID); err == nil {
			if info, err := sc.QueryUserInfo(h); err == nil {
				ui.FullName = info.FullName
				ui.Comment = info.AdminComment
				if ui.Comment == "" {
					ui.Comment = info.UserComment
				}
			}
			sc.CloseHandle(h)
		}
		out = append(out, ui)
	}
	return out, nil
}

// LoggedOnInfo is one interactively logged-on user (wkssvc
// WKSTA_USER_INFO_1).
type LoggedOnInfo struct {
	Username    string
	LogonDomain string
	OthDomains  string
	LogonServer string
}

// EnumLoggedOn enumerates interactively logged-on users via wkssvc
// NetrWkstaUserEnum (level 1) over the existing session's IPC$, mirroring
// tools/netview. Level 1 yields names/domains only — no logon time or auth
// package (higher levels are not implemented in pkg/dcerpc/wkssvc).
func (s *Session) EnumLoggedOn() ([]LoggedOnInfo, error) {
	pipe, err := s.client.OpenPipe("wkssvc")
	if err != nil {
		return nil, fmt.Errorf("open wkssvc pipe: %v", err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(wkssvc.UUID, wkssvc.MajorVersion, wkssvc.MinorVersion); err != nil {
		return nil, fmt.Errorf("bind wkssvc: %v", err)
	}

	users, err := wkssvc.NetrWkstaUserEnum(rpc)
	if err != nil {
		return nil, err
	}

	out := make([]LoggedOnInfo, 0, len(users))
	for _, u := range users {
		out = append(out, LoggedOnInfo{
			Username:    u.Username,
			LogonDomain: u.LogonDomain,
			OthDomains:  u.OthDomains,
			LogonServer: u.LogonServer,
		})
	}
	return out, nil
}

// GroupInfo is one domain group (samr).
type GroupInfo struct {
	Name string
	RID  uint32
}

// EnumGroups enumerates domain global groups via SAMR (net group /domain
// semantics). The samr package exposes no group-description query, so only
// name and RID are reported.
func (s *Session) EnumGroups() ([]GroupInfo, error) {
	sc, cleanup, err := s.openSAMR()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	groups, err := sc.EnumerateDomainGroups()
	if err != nil {
		return nil, err
	}

	out := make([]GroupInfo, 0, len(groups))
	for _, g := range groups {
		out = append(out, GroupInfo{Name: g.Name, RID: g.RID})
	}
	return out, nil
}

// MemberInfo is one member of a domain group. Name is empty when the member
// RID could not be resolved (nested group or foreign member) — show the raw
// RID in that case.
type MemberInfo struct {
	Name string
	RID  uint32
}

// EnumGroupMembers resolves a domain group by name and lists its members,
// resolving member RIDs to account names via a fresh user enumeration.
func (s *Session) EnumGroupMembers(groupName string) ([]MemberInfo, error) {
	sc, cleanup, err := s.openSAMR()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rid, err := sc.LookupName(groupName)
	if err != nil {
		return nil, fmt.Errorf("group %q not found", groupName)
	}

	gh, err := sc.OpenGroup(rid)
	if err != nil {
		return nil, fmt.Errorf("open group %q: %v", groupName, err)
	}
	defer sc.CloseHandle(gh)

	memberRids, err := sc.GetMembersInGroup(gh)
	if err != nil {
		return nil, err
	}

	names := map[uint32]string{}
	if users, err := sc.EnumerateDomainUsers(); err == nil {
		for _, u := range users {
			names[u.RID] = u.Name
		}
	}

	out := make([]MemberInfo, 0, len(memberRids))
	for _, r := range memberRids {
		out = append(out, MemberInfo{Name: names[r], RID: r})
	}
	return out, nil
}
