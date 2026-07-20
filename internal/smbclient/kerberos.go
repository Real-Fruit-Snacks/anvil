package smbclient

import (
	"encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/gssapi"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// smb302 pins kerberos sessions to SMB 3.0.2. The smb2 library's SMB 3.1.1
// preauth-integrity hash is not updated on the kerberos immediate-success
// session-setup leg, which breaks signing-key derivation (signature
// mismatch, then ACCESS_DENIED on every signed packet). 3.0.2 derives
// signing keys from the session key alone.
const smb302 = 0x0302

// kerbInitiator mirrors pkg/smb's KerberosInitiator but generates the
// AP-REQ with a properly structured GSS channel-binding checksum
// (GenerateAPReqWithBinding: Lgth=16, replay+sequence flags) instead of
// GenerateAPReqFull's all-zero checksum, which Samba's GSS acceptor rejects
// with "Incorrect channel bindings were supplied".
type kerbInitiator struct {
	krb *kerberos.Client
	spn string
	key types.EncryptionKey
}

var oidKrb5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

func (k *kerbInitiator) OID() asn1.ObjectIdentifier { return oidKrb5 }

func (k *kerbInitiator) InitSecContext() ([]byte, error) {
	apReq, key, err := k.krb.GenerateAPReqWithBinding(k.spn, nil)
	if err != nil {
		return nil, err
	}
	k.key = key
	return apReq, nil
}

func (k *kerbInitiator) AcceptSecContext(sc []byte) ([]byte, error) { return nil, nil }

// Sum computes the SPNEGO mechListMIC with the kerberos session key
// (mirrors pkg/smb's KerberosInitiator.Sum).
func (k *kerbInitiator) Sum(b []byte) []byte {
	tok, err := gssapi.NewInitiatorMICToken(b, k.key)
	if err != nil {
		return nil
	}
	m, err := tok.Marshal()
	if err != nil {
		return nil
	}
	return m
}

// SessionKey returns the SMB session key (mirrors pkg/smb's
// KerberosInitiator.SessionKey).
func (k *kerbInitiator) SessionKey() []byte {
	if len(k.key.KeyValue) > 16 {
		return k.key.KeyValue[:16]
	}
	return k.key.KeyValue
}

// connectKerberos establishes the SMB session via Kerberos (ccache from
// KRB5CCNAME / <user>.ccache, or password-derived TGT when no ccache
// exists). It mirrors pkg/smb's Connect kerberos branch with the two fixes
// above; the returned net.Conn is the session's transport (pkg/smb keeps
// its own unexported, so the caller owns this one).
func connectKerberos(target session.Target, creds *session.Credentials, timeout time.Duration) (*smb.Client, net.Conn, []byte, error) {
	// Realm resolution (pkg/kerberos NewClientFromSession): the ccache's
	// default principal realm wins when present; creds.Domain (--domain)
	// otherwise. Realm must be DNS-form (LAB.LOCAL), not NetBIOS.
	krbClient, err := kerberos.NewClientFromSession(creds, target, creds.DCIP)
	if err != nil {
		return nil, nil, nil, mapConnectError(err, false, true)
	}
	init := &kerbInitiator{krb: krbClient, spn: "cifs/" + target.Host}

	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	addr := net.JoinHostPort(host, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot reach %s: %v", addr, err)
	}

	d := &smb2.Dialer{
		Initiator:  init,
		Negotiator: smb2.Negotiator{RequireMessageSigning: true, SpecifiedDialect: smb302},
	}
	s2, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, mapConnectError(err, false, true)
	}

	client := smb.NewClient(target, creds)
	client.Session = s2
	return client, conn, init.SessionKey(), nil
}
