package smbclient

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/credentials"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/gssapi"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/keyusage"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/patype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// smb302 pins kerberos sessions to SMB 3.0.2. The smb2 library's SMB 3.1.1
// preauth-integrity hash is not updated on the kerberos immediate-success
// session-setup leg, which breaks signing-key derivation (signature
// mismatch, then ACCESS_DENIED on every signed packet). 3.0.2 derives
// signing keys from the session key alone.
const smb302 = 0x0302

// clockOffset is the server-minus-local clock difference (--sync-clock)
// applied to every kerberos timestamp anvil stamps itself. Zero keeps the
// stock library behavior (trust the local clock).
var clockOffset time.Duration

// SetClockOffset applies d (server time minus local time, e.g. measured by
// NTPOffset) to the kerberos side of Connect. Call it before Connect; zero
// restores stock behavior.
//
// The gokrb5 fork has no Clock injection point — time.Now() is hardcoded at
// ~15 sites (authenticators, AS/TGS requests, reply verification) — so the
// offset is applied where anvil controls the wire timestamp: authenticator
// construction in kerbInitiator (the "wrap the time source" pattern), plus
// a widened Clockskew so KDC replies stamped with the KDC's own clock still
// verify locally. The password AS-exchange leg (PA-ENC-TIMESTAMP) is
// library-internal and NOT covered: clock sync therefore targets ccache
// flows (golden/silver tickets), the case skew breaks in practice. With no
// ccache present the offset path declines and the stock path runs unchanged.
func SetClockOffset(d time.Duration) { clockOffset = d }

// kerbInitiator mirrors pkg/smb's KerberosInitiator but generates the
// AP-REQ with a properly structured GSS channel-binding checksum
// (GenerateAPReqWithBinding: Lgth=16, replay+sequence flags) instead of
// GenerateAPReqFull's all-zero checksum, which Samba's GSS acceptor rejects
// with "Incorrect channel bindings were supplied". With a non-zero clock
// offset it additionally stamps authenticators with server time.
type kerbInitiator struct {
	krb    *kerberos.Client
	spn    string
	user   string // client principal name, for self-built authenticators
	key    types.EncryptionKey
	offset time.Duration
}

var oidKrb5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

func (k *kerbInitiator) OID() asn1.ObjectIdentifier { return oidKrb5 }

func (k *kerbInitiator) InitSecContext() ([]byte, error) {
	if k.offset != 0 {
		apReq, key, err := k.offsetAPReq()
		switch {
		case err == nil:
			k.key = key
			return apReq, nil
		case errors.Is(err, errNoTicketMaterial):
			// No ccache to draw ticket material from (e.g. password-based
			// -k): the offset cannot reach the library's AS leg anyway, so
			// fall through to the stock path rather than failing a logon
			// that works without sync.
		default:
			return nil, err
		}
	}
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

	if clockOffset != 0 && krbClient.KrbClient != nil {
		// The library checks KDC-stamped times (TGT endTime at Login,
		// AS/TGS reply AuthTime/StartTime) against the LOCAL clock. Widen
		// the tolerance past the measured offset so valid replies survive;
		// wire timestamps are corrected separately in kerbInitiator.
		cfg := krbClient.KrbClient.Config
		skew := clockOffset
		if skew < 0 {
			skew = -skew
		}
		if cfg.LibDefaults.Clockskew < skew+5*time.Minute {
			cfg.LibDefaults.Clockskew = skew + 5*time.Minute
		}
	}

	init := &kerbInitiator{krb: krbClient, spn: "cifs/" + target.Host, user: creds.Username, offset: clockOffset}

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

// --- clock-offset kerberos (--sync-clock) ---
//
// All timestamps below are stamped with server time (local + clockOffset)
// so a skewed client passes the KDC's and the service's ±5-minute
// authenticator checks. The code mirrors gopacket's
// kerberos.Client.GenerateAPReqWithBinding and gokrb5's unexported
// TGSReq.setPAData — both reimplemented here because the library hardcodes
// time.Now() and exports no clock hook.

// errNoTicketMaterial marks "no ccache material to build a ticket from" —
// the offset path declines and InitSecContext falls back to the stock
// library path. Exchange/parse failures are real errors and propagate.
var errNoTicketMaterial = errors.New("no kerberos ticket material in ccache")

// offsetAPReq builds the service AP-REQ for the SMB session with server-
// time authenticators. ccache-first like the library: a cached service
// ticket for the SPN wins; otherwise the ccache's TGT drives one
// offset-corrected TGS exchange against the KDC.
func (k *kerbInitiator) offsetAPReq() ([]byte, types.EncryptionKey, error) {
	cc, err := loadResolvedCCache(k.user)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	realm := strings.ToUpper(cc.DefaultPrincipal.Realm)
	cname := types.PrincipalName{NameType: 1 /* KRB_NT_PRINCIPAL */, NameString: []string{k.user}}
	sname, _ := types.ParseSPNString(k.spn)

	var tkt *messages.Ticket
	var key types.EncryptionKey
	if cred, found := cc.GetEntry(sname); found {
		tkt = new(messages.Ticket)
		if err := tkt.Unmarshal(cred.Ticket); err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("cached service ticket for %s does not parse: %v", k.spn, err)
		}
		key = cred.Key
	} else {
		tgt, tkey, err := ccacheTGT(cc)
		if err != nil {
			return nil, types.EncryptionKey{}, err
		}
		if k.krb.KrbClient == nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("no TGT available and no cached service ticket for %s", k.spn)
		}
		tkt, key, err = k.offsetTGSExchange(tgt, tkey, sname, realm, cname)
		if err != nil {
			return nil, types.EncryptionKey{}, err
		}
	}
	return k.buildAPReq(tkt, key, realm, cname)
}

// loadResolvedCCache resolves the ccache the way gopacket's
// kerberos.NewClientFromSession does — $KRB5CCNAME (FILE: prefix stripped)
// first, ./<user>.ccache otherwise — minus the interactive prompt: with an
// offset configured the file is used unconditionally. (When the user
// declines the prompt and falls back to a password, KrbClient carries
// credentials with HasPassword() true and no ccache is loaded here, so the
// two resolutions can't disagree in practice.)
func loadResolvedCCache(user string) (*credentials.CCache, error) {
	path := os.Getenv("KRB5CCNAME")
	if path != "" {
		path = strings.TrimPrefix(path, "FILE:")
	} else if local := user + ".ccache"; fileExists(local) {
		path = local
	}
	if path == "" {
		return nil, errNoTicketMaterial
	}
	cc, err := loadCCacheSafe(path)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// loadCCacheSafe mirrors gopacket kerberos.loadCCacheSafe: gokrb5's
// Unmarshal can panic on malformed ccache bytes — recover and report.
func loadCCacheSafe(path string) (cc *credentials.CCache, err error) {
	defer func() {
		if r := recover(); r != nil {
			cc = nil
			err = fmt.Errorf("invalid ccache file: %v", r)
		}
	}()
	return credentials.LoadCCache(path)
}

// ccacheTGT extracts the krbtgt TGT and its session key for the ccache's
// own realm (same lookup client.NewFromCCache performs).
func ccacheTGT(cc *credentials.CCache) (*messages.Ticket, types.EncryptionKey, error) {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", cc.DefaultPrincipal.Realm},
	}
	cred, found := cc.GetEntry(spn)
	if !found {
		return nil, types.EncryptionKey{}, fmt.Errorf("%w: no krbtgt TGT", errNoTicketMaterial)
	}
	tgt := new(messages.Ticket)
	if err := tgt.Unmarshal(cred.Ticket); err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("ccache TGT does not parse: %v", err)
	}
	return tgt, cred.Key, nil
}

// offsetTGSExchange requests a service ticket for sname with the ccache's
// TGT, stamping the TGS-REQ authenticator with server time. Cross-realm
// referrals regenerate the request inside the library (local time) — same
// limitation as the stock path, and irrelevant for same-realm SPNs.
func (k *kerbInitiator) offsetTGSExchange(tgt *messages.Ticket, tkey types.EncryptionKey, sname types.PrincipalName, realm string, cname types.PrincipalName) (*messages.Ticket, types.EncryptionKey, error) {
	cl := k.krb.KrbClient

	tgsReq, err := messages.NewTGSReq(cname, realm, cl.Config, *tgt, tkey, sname, false)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("build TGS_REQ: %v", err)
	}

	// Move the requested expiry onto server time (preserving the lifetime
	// the library picked), then rebuild the PA data: the PA-TGS-REQ
	// authenticator checksums the marshaled body, so any ReqBody edit must
	// precede the checksum, and the library's setPAData is unexported.
	tgsReq.ReqBody.Till = k.now().Add(time.Until(tgsReq.ReqBody.Till))
	if err := k.setShiftedPAData(&tgsReq, *tgt, tkey); err != nil {
		return nil, types.EncryptionKey{}, err
	}

	_, tgsRep, err := cl.TGSExchange(tgsReq, realm, *tgt, tkey, 0)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	return &tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}

// setShiftedPAData rebuilds the TGS-REQ's PA-TGS-REQ exactly like gokrb5's
// unexported setPAData — body checksum keyed with the TGT session key,
// authenticator as the AP-REQ — but with the shifted timestamp.
func (k *kerbInitiator) setShiftedPAData(req *messages.TGSReq, tgt messages.Ticket, sessionKey types.EncryptionKey) error {
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return fmt.Errorf("marshal TGS_REQ body: %v", err)
	}
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return fmt.Errorf("get etype for TGS authenticator: %v", err)
	}
	cb, err := et.GetChecksumHash(sessionKey.KeyValue, body, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return fmt.Errorf("checksum TGS_REQ body: %v", err)
	}

	auth, err := k.shiftedAuthenticator(tgt.Realm, req.ReqBody.CName)
	if err != nil {
		return err
	}
	auth.Cksum = types.Checksum{CksumType: et.GetHashID(), Checksum: cb}

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return fmt.Errorf("build TGS AP_REQ: %v", err)
	}
	b, err := apReq.Marshal()
	if err != nil {
		return fmt.Errorf("marshal TGS AP_REQ: %v", err)
	}
	req.PAData = types.PADataSequence{types.PAData{PADataType: patype.PA_TGS_REQ, PADataValue: b}}
	return nil
}

// buildAPReq mints the service AP-REQ for the SMB session setup with the
// shifted authenticator and the GSS channel-binding checksum
// GenerateAPReqWithBinding uses (Lgth=16, replay+sequence flags).
func (k *kerbInitiator) buildAPReq(tkt *messages.Ticket, key types.EncryptionKey, realm string, cname types.PrincipalName) ([]byte, types.EncryptionKey, error) {
	auth, err := k.shiftedAuthenticator(realm, cname)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	auth.Cksum = types.Checksum{
		CksumType: 0x8003,               // GSSAPI
		Checksum:  gssChecksum16(4 | 8), // GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG
	}
	apReq, err := messages.NewAPReq(*tkt, key, auth)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("build AP-REQ: %v", err)
	}
	b, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	return b, key, nil
}

// now returns the current time as the server sees it (local + offset).
func (k *kerbInitiator) now() time.Time {
	return time.Now().Add(k.offset).UTC()
}

// shiftedAuthenticator is types.NewAuthenticator with the timestamp moved
// onto server time — the field the KDC/service skew-checks on every AP-REQ.
func (k *kerbInitiator) shiftedAuthenticator(realm string, cname types.PrincipalName) (types.Authenticator, error) {
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return auth, err
	}
	t := k.now()
	auth.CTime = t
	auth.Cusec = int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6))
	return auth, nil
}

// gssChecksum16 packs the 24-byte GSS-API authenticator checksum
// (Lgth=16 + 16 zero channel-binding bytes + flags) — impacket's
// CheckSumField layout, matching gopacket kerberos.buildGSSAPIChecksum,
// which is unexported.
func gssChecksum16(flags int) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 16)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(flags))
	return buf
}
