package smbclient

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// Error mapping. pkg/smb flattens Connect errors with %v (not %w), so the
// typed *smb2.ResponseError and its NTSTATUS code are lost by the time we
// see them. gopacket's erref renders NTSTATUS values as their MS-ERREF
// description text, which is what these substrings match (verified against
// pkg/third_party/smb2/internal/erref/ntstatus.go).

// mapConnectError translates flattened pkg/smb Connect errors into clean,
// actionable messages. kerberos reports whether the session authenticates
// via Kerberos (-k), so STATUS_LOGON_FAILURE — a bad password over NTLM —
// is described as the rejected service ticket it actually is.
func mapConnectError(err error, nullSession, kerberos bool) error {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "KRB_AP_ERR_SKEW"):
		return fmt.Errorf("kerberos clock skew too great — sync time with the DC")
	case strings.Contains(msg, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return fmt.Errorf("kerberos: user not found in the Kerberos database")
	case strings.Contains(msg, "KDC_ERR_S_PRINCIPAL_UNKNOWN"):
		return fmt.Errorf("kerberos: SPN not found — check --host is the server's real FQDN")
	case strings.Contains(msg, "KDC_ERR_PREAUTH_FAILED"):
		return fmt.Errorf("kerberos: bad password (pre-auth failed)")
	case strings.Contains(msg, "no valid kerberos credentials found"),
		strings.Contains(msg, "no TGT available and no cached service ticket"):
		return fmt.Errorf("no kerberos ticket — mint one (getTGT/kinit) and set KRB5CCNAME, or pass -p")
	case strings.Contains(msg, "domain/realm is required"):
		return fmt.Errorf("kerberos needs a realm — pass -d <domain>")
	case strings.Contains(msg, "The specified account does not exist"): // STATUS_NO_SUCH_USER
		return fmt.Errorf("no such user")
	case strings.Contains(msg, "the current password is not correct"): // STATUS_WRONG_PASSWORD
		return fmt.Errorf("bad password")
	case strings.Contains(msg, "The user account password has expired"): // STATUS_PASSWORD_EXPIRED
		return fmt.Errorf("password expired for this account")
	case strings.Contains(msg, "The attempted logon is invalid"): // STATUS_LOGON_FAILURE
		if kerberos {
			return fmt.Errorf("kerberos: service ticket rejected by the server (logon failure)")
		}
		return fmt.Errorf("logon failure (bad username or password)")
	case strings.Contains(msg, "doesn't support signing"):
		// smb2 refuses anonymous/guest sessions when the client requires
		// signing (pkg/smb always sets RequireMessageSigning).
		return fmt.Errorf("server treated the session as guest/anonymous, which the client rejects (signing required); supply valid -u/-p credentials")
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("access denied")
	}

	if nullSession {
		return fmt.Errorf("authentication failed; null sessions are likely disabled — supply -u/-p")
	}
	return fmt.Errorf("authentication failed: %s", msg)
}

// Describe renders an in-shell operation error as a short one-liner.
func Describe(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file or directory"
	case errors.Is(err, os.ErrPermission):
		return "access denied"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no share selected"):
		return "no share selected — use <share> first"
	case strings.Contains(msg, "not a directory"):
		return "not a directory"
	case strings.Contains(msg, "0x00000005"):
		// Win32 ERROR_ACCESS_DENIED (Samba renders it bare; Windows via
		// "NTSTATUS 0x00000005").
		return "access denied"
	case strings.Contains(msg, "0x1c010002"):
		// DCE/RPC nca_s_op_rng_error — the server bound the interface but
		// doesn't implement the opnum (Samba wkssvc lacks NetrWkstaUserEnum).
		return "not supported on this server (unknown RPC opnum)"
	case strings.Contains(msg, "0x000006f7"):
		// EPT_S_NOT_REGISTERED — the interface bound but the backend op
		// isn't functional (Samba winreg).
		return "not supported on this server (RPC op not registered)"
	case strings.Contains(msg, "0x00002105"):
		// ERROR_DS_DRA_ACCESS_DENIED — replication rights required.
		return "replication rights denied (needs Domain Admins / Replicating Directory Changes)"
	case strings.Contains(msg, "NTSTATUS 0x0000007c"):
		// Win32 ERROR_INVALID_LEVEL — Samba's srvsvc lacks level 10.
		return "not supported on this server (invalid level)"
	case strings.Contains(msg, "Network Name Not Found"):
		// STATUS_BAD_NETWORK_NAME — e.g. C$ missing on non-Windows targets.
		return "network name not found on the server"
	}
	return msg
}

// IsTransportError reports whether err is a fatal net-layer failure (the
// smb2 library wraps those in *smb2.TransportError). Used by the shell to
// distinguish "command failed" from "session is dead".
func IsTransportError(err error) bool {
	var te *smb2.TransportError
	return errors.As(err, &te)
}
