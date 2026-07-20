package smbclient

import (
	"fmt"
	"strings"
)

// SAMR write primitives (password reset, group membership edits) over the
// existing SMB session's SAMR pipe — the same transport as
// users/groups/members (enum.go), so no new channel is opened. These are the
// non-LDAP counterparts to changepasswd/rbcd-style edits, for targets where
// LDAP/LDAPS is blocked but SMB 445 is not.

// SetPasswordSAMR changes user's password via SAMR
// (SamrUnicodeChangePasswordUser2, MS-SAMR 3.1.5.10.3) with knowledge of the
// old password — the non-LDAP alternative to ChangePassword for when
// LDAP/LDAPS is unreachable. Any authenticated session can change any
// account's password this way as long as the old password is known (no admin
// rights needed); the encrypted blobs are keyed by the old/new NT hashes, so
// unlike the reset path no SMB session key is involved.
//
// Why change-with-old rather than an admin reset: the only reset op the
// samr package exports is SamrSetInformationUser level 18, which CORRUPTS
// the password on Server 2022 (accepted with STATUS_SUCCESS, but the stored
// NT hash decrypts to garbage — verified 2026-07: old password kept working
// for a short grace window, then neither old nor new worked). The correct
// reset payload (UserInternal4Information with the RC4 SAMPR buffer) exists
// in gopacket only as an unexported helper, so a reset is out of reach
// without reimplementing the SAMR handshake; use changepasswd (LDAP) for
// resets. Being a change, this is subject to domain password policy —
// including minimum password age (STATUS_PASSWORD_RESTRICTION).
func (s *Session) SetPasswordSAMR(user, new, old string) error {
	if old == "" {
		return fmt.Errorf("SAMR password set needs the old password (admin reset is not supported over SAMR — use changepasswd)")
	}
	if new == "" {
		return fmt.Errorf("empty password")
	}

	sc, cleanup, err := s.openSAMR()
	if err != nil {
		return err
	}
	defer cleanup()

	user = stripDomainPrefix(user)
	if err := sc.ChangeUserPassword(user, old, new); err != nil {
		return fmt.Errorf("setting password for %s: %v", user, mapSAMRError(err))
	}
	return nil
}

// AddGroupMember adds user to the named group via SAMR. group may be a
// domain group (SamrAddMemberToGroup, member by RID) or a Builtin alias such
// as "Remote Desktop Users" (SamrAddMemberToAlias, member by full SID) — see
// setGroupMembership for why both paths exist.
func (s *Session) AddGroupMember(group, user string) error {
	return s.setGroupMembership(group, user, true)
}

// RemoveGroupMember removes user from the named group via SAMR (same dual
// group/alias resolution as AddGroupMember).
func (s *Session) RemoveGroupMember(group, user string) error {
	return s.setGroupMembership(group, user, false)
}

// setGroupMembership implements AddGroupMember/RemoveGroupMember. Windows
// exposes two group families over SAMR: account-domain groups (Domain
// Admins, Domain Guests, ...) and Builtin aliases (Administrators, Remote
// Desktop Users, ...), which live in the SAM "Builtin" domain and are NOT
// resolvable in the account domain — SamrLookupNamesInDomain for
// "Remote Desktop Users" against the domain handle maps nothing (observed
// vs Server 2022). Aliases also differ operationally: SamrAddMemberToAlias
// takes the member's full SID, while SamrAddMemberToGroup takes the RID.
// So: resolve in the account domain first, fall back to the Builtin domain
// and the alias op set.
func (s *Session) setGroupMembership(group, user string, add bool) error {
	sc, cleanup, err := s.openSAMR()
	if err != nil {
		return err
	}
	defer cleanup()

	verb := "adding to"
	if !add {
		verb = "removing from"
	}

	user = stripDomainPrefix(user)
	userRID, err := sc.LookupName(user)
	if err != nil {
		return fmt.Errorf("user %q not found in the domain", user)
	}

	group = stripDomainPrefix(group)
	if groupRID, err := sc.LookupName(group); err == nil {
		gh, err := sc.OpenGroup(groupRID)
		if err != nil {
			return fmt.Errorf("open group %q: %v", group, mapSAMRError(err))
		}
		defer sc.CloseHandle(gh)

		if add {
			err = sc.AddMemberToGroup(gh, userRID)
		} else {
			err = sc.RemoveMemberFromGroup(gh, userRID)
		}
		if err != nil {
			return fmt.Errorf("%s %q: %v", verb, group, mapSAMRError(err))
		}
		return nil
	}

	// Builtin alias path. OpenBuiltinDomain looks up and opens Builtin and
	// restores the account-domain handle afterwards, so sc.RidToSid below
	// still builds the member SID from the ACCOUNT domain SID (a Builtin
	// alias holds domain SIDs, never Builtin-domain RIDs).
	bh, _, err := sc.OpenBuiltinDomain()
	if err != nil {
		return fmt.Errorf("group %q not found in the domain", group)
	}
	aliasRID, err := sc.LookupNameInDomain(bh, group)
	if err != nil {
		return fmt.Errorf("group %q not found in the domain or Builtin", group)
	}
	ah, err := sc.OpenAlias(bh, aliasRID)
	if err != nil {
		return fmt.Errorf("open group %q: %v", group, mapSAMRError(err))
	}
	defer sc.CloseHandle(ah)

	sid := sc.RidToSid(userRID)
	if add {
		err = sc.AddMemberToAlias(ah, sid)
	} else {
		err = sc.RemoveMemberFromAlias(ah, sid)
	}
	if err != nil {
		return fmt.Errorf("%s %q: %v", verb, group, mapSAMRError(err))
	}
	return nil
}

// stripDomainPrefix accepts "DOMAIN\user" or "user" and returns the bare
// sAMAccountName; SamrLookupNamesInDomain wants no domain qualifier.
func stripDomainPrefix(name string) string {
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// mapSAMRError translates the NTSTATUS codes pkg/dcerpc/samr flattens into
// its errors ("... NTSTATUS 0xc0000067") into plain-language hints,
// mirroring mapPasswordError. Codes per MS-ERREF (verified against
// pkg/third_party/smb2/internal/erref/ntstatus.go); the original text is
// preserved for context.
func mapSAMRError(err error) error {
	msg := err.Error()
	var hint string
	switch {
	case strings.Contains(msg, "0xc0000022"): // STATUS_ACCESS_DENIED
		hint = "access denied — needs Domain Admins / Account Operators"
	case strings.Contains(msg, "0xc0000064"): // STATUS_NO_SUCH_USER
		hint = "no such user"
	case strings.Contains(msg, "0xc0000066"): // STATUS_NO_SUCH_GROUP
		hint = "no such group"
	case strings.Contains(msg, "0xc0000067"): // STATUS_MEMBER_IN_GROUP
		hint = "already a member of the group"
	case strings.Contains(msg, "0xc0000068"): // STATUS_MEMBER_NOT_IN_GROUP
		hint = "not a member of the group"
	case strings.Contains(msg, "0xc000006a"): // STATUS_WRONG_PASSWORD
		hint = "the old password is incorrect"
	case strings.Contains(msg, "0xc000006c"): // STATUS_PASSWORD_RESTRICTION
		hint = "password rejected by domain policy (complexity, history, or minimum age)"
	case strings.Contains(msg, "0xc0000151"): // STATUS_NO_SUCH_ALIAS
		hint = "no such local group"
	case strings.Contains(msg, "0xc0000152"): // STATUS_MEMBER_NOT_IN_ALIAS
		hint = "not a member of the group"
	case strings.Contains(msg, "0xc0000153"): // STATUS_MEMBER_IN_ALIAS
		hint = "already a member of the group"
	default:
		return err
	}
	return fmt.Errorf("%s (%s)", msg, hint)
}
