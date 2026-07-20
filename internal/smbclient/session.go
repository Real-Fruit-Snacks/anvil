// Package smbclient wraps gopacket's pkg/smb client with the small,
// session-oriented surface anvil's interactive shell needs. One connection,
// one session: commands never reconnect.
package smbclient

import (
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
)

// Session is a persistent authenticated SMB session.
type Session struct {
	client        *smb.Client
	creds         *session.Credentials // kept for RPC interfaces needing an authenticated bind (tsch)
	conn          net.Conn             // kerberos path only (pkg/smb owns its conn on the NTLM path)
	smbSessionKey []byte               // kerberos path only (pkg/smb exposes it via GetSessionKey on NTLM)
	host          string
	port          int
	share         string // currently selected share (pkg/smb keeps it unexported)
	null          bool   // true when no credentials were supplied (null session)
}

// Connect establishes an SMB session to host:port with the given credentials.
// pkg/smb dials through gopacket's internal transport.Dialer (const 30s
// timeout, no exported knob), so a reachability pre-flight with our own
// timeout keeps --timeout meaningful for dead hosts; the real session then
// connects via pkg/smb exactly like gopacket's tools/smbclient.
func Connect(host string, port int, targetIP string, creds *session.Credentials, timeout time.Duration, nullSession bool) (*Session, error) {
	if creds.UseKerberos {
		// Kerberos path: single dial inside connectKerberos (no pre-flight —
		// one connection, one session like the NTLM path).
		target := session.Target{Host: host, Port: port, IP: targetIP}
		client, conn, key, err := connectKerberos(target, creds, timeout)
		if err != nil {
			return nil, err
		}
		return &Session{client: client, creds: creds, conn: conn, smbSessionKey: key, host: host, port: port}, nil
	}

	dialHost := host
	if targetIP != "" {
		dialHost = targetIP
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(port))

	probe, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %v", addr, err)
	}
	probe.Close()

	client := smb.NewClient(session.Target{Host: host, Port: port, IP: targetIP}, creds)
	if err := client.Connect(); err != nil {
		return nil, mapConnectError(err, nullSession, false)
	}

	// Backfill the domain from the NTLM challenge when the user didn't pass
	// -d: LDAP features (adenum, roast) need it for bind identities, and the
	// server told us at connect time anyway.
	if creds.Domain == "" {
		if tree := client.GetDNSTreeName(); tree != "" {
			creds.Domain = tree
		}
	}

	return &Session{client: client, creds: creds, host: host, port: port, null: nullSession}, nil
}

// Close tears down shares, session, and connection.
func (s *Session) Close() {
	s.client.Close()
	if s.conn != nil {
		s.conn.Close()
	}
}

// Host returns the connected host.
func (s *Session) Host() string { return s.host }

// NullSession reports whether the session was established without credentials.
func (s *Session) NullSession() bool { return s.null }

// Creds returns the credentials the session was established with (needed by
// RPC interfaces that do their own authenticated bind, e.g. tsch/drsuapi).
func (s *Session) Creds() *session.Credentials { return s.creds }

// Share returns the currently selected share, or "" if none.
func (s *Session) Share() string {
	// UseShare is the only mutator; tracked here because pkg/smb keeps the
	// current share unexported.
	return s.share
}

// Path returns the current remote directory, normalized to a backslash root.
// pkg/smb tracks the path with path.Join, which yields "." for the root.
func (s *Session) Path() string {
	p := s.client.GetCurrentPath()
	if p == "" || p == "." {
		return "\\"
	}
	return p
}

// ServerInfo returns the server's DNS hostname and DNS tree name learned
// from the NTLM challenge during Connect (empty when unavailable).
func (s *Session) ServerInfo() (dnsHostName, dnsTreeName string) {
	return s.client.GetDNSHostName(), s.client.GetDNSTreeName()
}

// ListShares enumerates shares via srvsvc over IPC$ (SMB2-level op inside
// gopacket's smb2 library — the same path tools/smbclient uses).
func (s *Session) ListShares() ([]string, error) {
	return s.client.ListShares()
}

// UseShare tree-connects to the share and resets the working directory to
// its root.
func (s *Session) UseShare(name string) error {
	if err := s.client.UseShare(name); err != nil {
		return err
	}
	s.share = name
	return nil
}

// Ls lists a remote directory relative to the current path.
func (s *Session) Ls(dir string) ([]os.FileInfo, error) {
	return s.client.Ls(smbPath(dir))
}

// Stat returns the FileInfo for a single remote path. pkg/smb exports no
// stat, so it goes through the smb2 session directly on the selected share.
func (s *Session) Stat(path string) (os.FileInfo, error) {
	if s.share == "" {
		return nil, fmt.Errorf("no share selected — use <share> first")
	}
	sh, err := s.client.Session.Mount(s.share)
	if err != nil {
		return nil, err
	}
	defer sh.Umount()
	return sh.Stat(smbPath(path))
}

// Cd changes the current remote directory.
func (s *Session) Cd(dir string) error {
	return s.client.Cd(smbPath(dir))
}

// Get downloads remote to local and reports bytes written and wall time.
func (s *Session) Get(remote, local string) (n int64, elapsed time.Duration, err error) {
	start := time.Now()
	if err := s.client.Get(smbPath(remote), local); err != nil {
		return 0, 0, err
	}
	if fi, statErr := os.Stat(local); statErr == nil {
		n = fi.Size()
	}
	return n, time.Since(start), nil
}

// Put uploads local to remote and reports bytes sent and wall time.
func (s *Session) Put(local, remote string) (n int64, elapsed time.Duration, err error) {
	fi, err := os.Stat(local)
	if err != nil {
		return 0, 0, err
	}
	if fi.IsDir() {
		return 0, 0, fmt.Errorf("%s is a directory", local)
	}
	start := time.Now()
	if err := s.client.Put(local, smbPath(remote)); err != nil {
		return 0, 0, err
	}
	return fi.Size(), time.Since(start), nil
}

// smbPath converts user-typed backslash paths to forward slashes. pkg/smb
// resolves paths with Go's path.Join, which only treats '/' as a separator;
// a literal backslash would otherwise become part of a filename.
func smbPath(p string) string { return strings.ReplaceAll(p, "\\", "/") }

// Rm deletes a remote file.
func (s *Session) Rm(file string) error {
	return s.client.Rm(smbPath(file))
}

// Mkdir creates a remote directory.
func (s *Session) Mkdir(dir string) error {
	return s.client.Mkdir(smbPath(dir))
}

// Rmdir removes a remote directory.
func (s *Session) Rmdir(dir string) error {
	return s.client.Rmdir(smbPath(dir))
}

// Rename moves/renames a remote file or directory.
func (s *Session) Rename(oldPath, newPath string) error {
	return s.client.Rename(smbPath(oldPath), smbPath(newPath))
}

// catMaxSize caps Cat reads: pkg/smb's Cat slurps the whole file into memory
// with io.ReadAll, so anything big belongs to get instead.
const catMaxSize = 8 << 20 // 8 MiB

// Cat reads a remote file as text. Best-effort size guard via the parent
// directory listing; if the listing fails we delegate anyway and let the
// server's error surface.
func (s *Session) Cat(name string) (string, error) {
	norm := smbPath(name)
	base := path.Base(norm)
	if entries, err := s.client.Ls(path.Dir(norm)); err == nil {
		for _, e := range entries {
			if strings.EqualFold(e.Name(), base) && !e.IsDir() && e.Size() > catMaxSize {
				return "", fmt.Errorf("file too large for cat (%d bytes > %d MiB) — use get instead",
					e.Size(), catMaxSize>>20)
			}
		}
	}
	return s.client.Cat(norm)
}
