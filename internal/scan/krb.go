package scan

// Kerberos probe safety model: the exchange below is read-only and touches
// no account state on the KDC.
//
//   - The AS-REQ asks for a deliberately nonexistent principal,
//     "anvil-<8 random hex>". A failed lookup of a name that does not
//     exist in the KDC database is not an authentication attempt against
//     any real account, so it increments no bad-password counter and
//     presents no lockout surface — the same traffic any Kerberos client
//     generates when a user mistypes their name.
//   - No credentials, keys, or pre-authentication data are sent; the
//     request carries only the random principal name and standard client
//     options (the same shape as nmap's krb5-enum-realms or impacket's
//     unauthenticated GetNPUsers reachability check).
//   - Exactly one request is written and exactly one reply is read. The
//     KRB-ERROR the KDC returns is the fingerprint: it confirms a live
//     KDC and carries the realm in its srealm field.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/asnAppTag"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/errorcode"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// maxKDCReply caps the TCP-framed reply we will buffer. A KRB-ERROR is a
// few hundred bytes; even a PAC-laden AS-REP stays in the low kilobytes.
// The cap exists so a hostile or confused peer cannot make us allocate on
// its say-so via the length prefix.
const maxKDCReply = 1 << 20

// probeKRB confirms a KDC on target:port and lifts the Kerberos realm from
// the KRB-ERROR reply to one AS-REQ for a nonexistent principal. realmHint
// (e.g. derived from the SMB/LDAP probes) is used as the request realm;
// without one we send the deliberately invalid "ANVIL.INVALID". The request
// realm only affects *which* error comes back — a Windows KDC answers
// KDC_ERR_C_PRINCIPAL_UNKNOWN when the realm is right, and may answer
// KDC_ERR_WRONG_REALM when it is not — while the reply's Realm field is the
// KDC's own and is authoritative either way. Both outcomes confirm the
// service, so any KRB-ERROR is a success for this probe; KDCReply records
// which symbolic error arrived rather than treating others as failures.
//
// Kerberos-over-TCP framing (RFC 4120 §7.2.2): each message is prefixed
// with a 4-byte big-endian length. The probe never fails hard: dial,
// write, read, and parse problems are recorded in Error and the scan moves
// on.
func probeKRB(target string, port int, timeout time.Duration, realmHint string) *KerberosInfo {
	info := &KerberosInfo{Probed: true}

	realm := realmHint
	if realm == "" {
		realm = "ANVIL.INVALID"
	}

	req, err := buildASReq(realm)
	if err != nil {
		info.Error = fmt.Sprintf("building AS-REQ: %v", err)
		return info
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), timeout)
	if err != nil {
		info.Error = fmt.Sprintf("dial: %v", err)
		return info
	}
	defer conn.Close()
	// One deadline covering the whole write+read exchange; the KDC either
	// answers an AS-REQ immediately or not at all.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeKRBFrame(conn, req); err != nil {
		info.Error = fmt.Sprintf("write: %v", err)
		return info
	}
	body, err := readKRBFrame(conn)
	if err != nil {
		info.Error = fmt.Sprintf("read: %v", err)
		return info
	}

	r, reply, err := parseKDCReply(body)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Realm = r
	info.KDCReply = reply
	return info
}

// buildASReq marshals one AS-REQ for the nonexistent principal
// anvil-<8 lowercase hex> in the given realm, asking for krbtgt/<realm>.
// The sname uses KRB_NT_SRV_INST, the canonical krbtgt name form every real
// client sends (mirrors gopacket's messages.NewASReqForTGT). config.New()
// defaults NoAddresses=true, so the request carries no client addresses and
// construction performs no local interface enumeration.
func buildASReq(realm string) ([]byte, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"anvil-" + hex.EncodeToString(suffix[:])},
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

// parseKDCReply decodes one KDC reply with the TCP framing already stripped.
// The expected case is a KRB-ERROR (the requested principal does not exist,
// and even a bogus request realm yields an error, never a ticket). Anything
// else — a genuine AS-REP, another message type, or non-Kerberos garbage —
// is an error here, and the caller records it in KerberosInfo.Error.
func parseKDCReply(b []byte) (realm, reply string, err error) {
	var kerr messages.KRBError
	if uerr := kerr.Unmarshal(b); uerr != nil {
		// Application-tag first bytes (0x60 | tag, for tags < 31): an
		// AS-REP means the KDC issued a ticket for a principal meant not
		// to exist — worth saying plainly rather than "unmarshal error".
		if len(b) > 0 && b[0] == 0x60|byte(asnAppTag.ASREP) {
			return "", "", fmt.Errorf("unexpected AS-REP (ticket issued for nonexistent principal)")
		}
		return "", "", fmt.Errorf("not a KRB-ERROR reply: %v", uerr)
	}
	// srealm (tag 9) is the KDC's own realm. CRealm is only the echo of
	// the client realm from our request — with the ANVIL.INVALID
	// placeholder that echo is worthless, so it is strictly a fallback
	// for KDCs that leave srealm empty.
	realm = kerr.Realm
	if realm == "" {
		realm = kerr.CRealm
	}
	return realm, errorName(kerr.ErrorCode), nil
}

// errorName reduces errorcode.Lookup's rendering —
// "(6) KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database" —
// to the bare symbolic name the profile reports. Codes outside the table
// render as "Unknown ErrorCode N" already and are kept whole.
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
