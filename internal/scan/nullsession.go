package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
)

// probeNullSession attempts an anonymous (null-session) SMB logon on
// target:port and, when the session comes up, enumerates shares via srvsvc
// over IPC$ — the same ListShares call the shell's `shares` command and the
// keepalive Ping use.
//
// The flow mirrors the connect command's null-session path
// (internal/cli/connect.go + internal/smbclient/session.go): empty
// session.Credentials{} into smb.NewClient + Connect, preceded by a
// reachability pre-flight with our own timeout because pkg/smb dials
// through gopacket's internal transport.Dialer (const 30s timeout, no
// exported knob). Connect+enum run under a watchdog like probeLDAP:
// gopacket's smb2 conn has no read deadline, so a server that stalls
// session setup or the share enum would otherwise hang the scan past its
// timeout. On watchdog expiry the worker goroutine leaks until the
// underlying op returns — same tradeoff probeLDAP documents.
//
// Interop: both refusal styles are clean outcomes, not crashes. Windows
// refuses the session outright (STATUS_LOGON_FAILURE at SESSION_SETUP),
// while Samba accepts anonymous session setup and then denies the
// operations (access denied on the IPC$ tree connect or the srvsvc enum).
// One pkg/smb caveat: Connect hardwires RequireMessageSigning, and
// gopacket's smb2 aborts any session the server flags anonymous/guest
// ("...doesn't support signing"). Reaching that error means the server
// ACCEPTED the null logon — itself a finding — but gopacket cannot ride
// the unsigned session on to share enumeration.
func probeNullSession(target string, port int, timeout time.Duration) *NullSessionInfo {
	done := make(chan *NullSessionInfo, 1)
	go func() {
		done <- probeNullSessionConn(target, port, timeout)
	}()

	watchdog := 4 * timeout
	if watchdog < 10*time.Second {
		watchdog = 10 * time.Second
	}

	select {
	case info := <-done:
		return info
	case <-time.After(watchdog):
		return &NullSessionInfo{Probed: true, Error: fmt.Sprintf("timed out after %s", watchdog)}
	}
}

func probeNullSessionConn(target string, port int, timeout time.Duration) *NullSessionInfo {
	info := &NullSessionInfo{Probed: true}
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	// Reachability pre-flight with our own timeout (same pattern as
	// smbclient.Session.dial): keeps the scan timeout meaningful for dead
	// hosts instead of sitting in gopacket's 30s internal dial.
	probe, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		info.Error = fmt.Sprintf("connect: %v", err)
		return info
	}
	probe.Close()

	// Anonymous session: empty credentials take the NTLM path with an empty
	// identity, exactly like `connect` with no -u/-p.
	client := smb.NewClient(session.Target{Host: target, Port: port}, &session.Credentials{})
	if err := client.Connect(); err != nil {
		if strings.Contains(err.Error(), "doesn't support signing") {
			info.SigningBlocked = true
		}
		info.Error = describeNullSessionError(err, "null session refused")
		return info
	}
	defer client.Close()

	// srvsvc NetShareEnumAll over IPC$; pkg/smb returns the names sorted.
	// An empty list with no error is a valid result (server answered, has
	// no shares visible to anonymous).
	shares, err := client.ListShares()
	if err != nil {
		info.Error = describeNullSessionError(err, "share enumeration failed")
		return info
	}
	info.Shares = shares
	return info
}

// describeNullSessionError maps a flattened pkg/smb error to a short
// plain-language reason, falling back to the caller's context-appropriate
// default when nothing matches. pkg/smb flattens errors with %v (not %w),
// so the typed *smb2.ResponseError and its NTSTATUS are gone by the time we
// see them — gopacket's erref renders NTSTATUS values as their MS-ERREF
// description text, which is what these substrings match (same approach as
// smbclient/errors.go, verified against
// pkg/third_party/smb2/internal/erref/ntstatus.go).
func describeNullSessionError(err error, fallback string) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "doesn't support signing"):
		// smb2 aborts sessions the server flags IS_NULL/IS_GUEST when the
		// client requires signing (pkg/smb hardwires it). The null logon
		// itself succeeded; gopacket just refuses the unsigned session.
		return "null session accepted but blocked by client signing requirement"
	case strings.Contains(msg, "Access Denied"), // STATUS_ACCESS_DENIED erref text
		strings.Contains(msg, "0x00000005"): // Win32 ERROR_ACCESS_DENIED (Samba renders it bare)
		return "access denied"
	case strings.Contains(msg, "The attempted logon is invalid"): // STATUS_LOGON_FAILURE
		return "null session refused"
	}
	return fallback
}
