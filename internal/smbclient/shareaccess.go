package smbclient

import (
	"strings"
)

// ShareAccess is the smbmap-style access verdict for one share.
type ShareAccess struct {
	Name  string
	Read  bool
	Write bool
	Note  string // "denied", "pipe share", leftover marker, or ""
}

// ProbeShares enumerates shares and probes access for each on the EXISTING
// session: tree connects share the connection (no new dials), and the
// caller's selected share is never touched — probes mount and umount
// directly through the exported *smb2.Session instead of UseShare.
func (s *Session) ProbeShares() ([]ShareAccess, error) {
	names, err := s.ListShares()
	if err != nil {
		return nil, err
	}

	out := make([]ShareAccess, 0, len(names))
	for _, name := range names {
		out = append(out, s.probeShare(name))
	}
	return out, nil
}

func (s *Session) probeShare(name string) ShareAccess {
	sa := ShareAccess{Name: name}

	if strings.EqualFold(name, "IPC$") {
		// Pipe share: no directory semantics, and reachable by definition
		// (the share list itself came through it).
		sa.Note = "pipe share"
		return sa
	}

	share, err := s.client.Session.Mount(name)
	if err != nil {
		sa.Note = "denied"
		return sa
	}
	defer share.Umount()

	if _, err := share.ReadDir("."); err != nil {
		sa.Note = "denied"
		return sa
	}
	sa.Read = true

	// Write test: briefly create and delete a uniquely-named tiny file at
	// the share root (smbmap does the same). On failure, best-effort delete
	// and report read-only.
	tmp := "anv-" + randHex(4) + ".tmp"
	f, err := share.Create(tmp)
	if err != nil {
		return sa
	}
	f.Close()
	if err := share.Remove(tmp); err != nil {
		// Created but not deleted: still proves write access; flag the
		// leftover rather than hiding it.
		sa.Write = true
		sa.Note = "left " + tmp
		return sa
	}
	sa.Write = true
	return sa
}
