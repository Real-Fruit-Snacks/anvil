package pkinit

// Diffie-Hellman key agreement for PKINIT (RFC 4556 §3.2.1 request side,
// §3.2.3.1 reply side).
//
// Why DH is the primary mode here: live verification against a Windows
// Server 2022 KDC answered our RSA key transport requests with
// KRB_ERR_GENERIC, and a controlled replay (certipy's request rebuilt
// without clientPublicValue) showed the KDC answering RSA-mode with
// KDC_ERR_ETYPE_NOSUPP — the RFC 4556 §3.1.2 mandatory RSA-mode reply
// encryption is 3DES-CBC, which hardened KDCs no longer use. certipy,
// minikerberos and Rubeus all default to DH for exactly this reason;
// against the same KDC, the DH flow below succeeded end to end. The RSA
// reply path in cms.go is kept as a fallback for KDCs that still speak
// it, but the request now always offers DH.
//
// Everything in this file is pinned to certipy's wire behavior
// (byte-verified against that KDC), which matches RFC 4556:
//
//   - AuthPack gains clientPublicValue [1] EXPLICIT SubjectPublicKeyInfo
//     { algorithm dhKeyAgreement, parameters DomainParameters { p, g,
//     q=0 }, subjectPublicKey BIT STRING } and clientDHNonce [3]
//     EXPLICIT OCTET STRING (RFC 4556 §3.2.1; DHNonce ::= OCTET STRING).
//   - The reply's dhInfo [0] wraps DHRepInfo { dhSignedData [0] IMPLICIT
//     OCTET STRING, serverDHNonce [1] EXPLICIT OCTET STRING }; the
//     dhSignedData is a CMS ContentInfo(SignedData) whose eContentType
//     is id-pkinit-DHKeyData (1.3.6.1.5.2.3.2) and whose eContent is the
//     DER of KDCDHKeyInfo (RFC 4556 §3.2.3.1).
//   - The reply key is octetstring2key(shared ‖ clientDHNonce ‖
//     serverDHNonce) truncated to the reply etype's key length, where
//     octetstring2key is the SHA-1 chain of RFC 4556 §3.2.3.1.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

var (
	// dhKeyAgreement is the RFC 3279 §2.3.1 OID for MODP Diffie-Hellman.
	oidDHKeyAgreement = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	// oidPKINITDHKeyData is id-pkinit-DHKeyData (RFC 4556 Appendix A) —
	// the eContentType certipy checks for in the KDC's dhSignedData.
	oidPKINITDHKeyData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
)

// dhGroup2Prime is the RFC 2412 Appendix E.2 "Well-Known Group 2"
// 1024-bit MODP prime — the group every PKINIT client sends (RFC 4556
// §3.2.1 item 8 makes it mandatory) and what certipy hardcodes. The
// leading 00 octet in the hex keeps the INTEGER positive; the value is
// the 1024-bit prime either way.
var dhGroup2Prime = mustBigIntHex("00" +
	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
	"020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14" +
	"374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406" +
	"b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff")

// dhGroup2Generator is the group generator, 2 (same RFC appendix).
var dhGroup2Generator = big.NewInt(2)

// mustBigIntHex parses a compile-time-constant hex string into a big.Int.
func mustBigIntHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("pkinit: bad DH prime hex constant")
	}
	return v
}

// dhClient is the client side of one DH exchange: our ephemeral private
// value, the public value we advertise in clientPublicValue, and the
// clientDHNonce that salts the reply key derivation.
type dhClient struct {
	priv  *big.Int
	pub   *big.Int
	nonce []byte // clientDHNonce: 32 random bytes (certipy os.urandom(32))
}

// newDHClient generates the ephemeral DH state. The private value is 32
// random bytes as an unsigned integer — certipy's DirtyDH choice; the
// public value is g^x mod p.
func newDHClient() (*dhClient, error) {
	privBytes := make([]byte, 32)
	if _, err := rand.Read(privBytes); err != nil {
		return nil, fmt.Errorf("generating the DH private value: %v", err)
	}
	priv := new(big.Int).SetBytes(privBytes)
	pub := new(big.Int).Exp(dhGroup2Generator, priv, dhGroup2Prime)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating the client DH nonce: %v", err)
	}
	return &dhClient{priv: priv, pub: pub, nonce: nonce}, nil
}

// dhDomainParameters is RFC 3279 §2.3.2 DomainParameters. q is OPTIONAL
// in the RFC, but Windows wants it present — minikerberos' comment says
// it plainly: "q = 0 # mandatory parameter, but it is not needed".
type dhDomainParameters struct {
	P *big.Int
	G *big.Int
	Q *big.Int
}

// buildClientPublicValue marshals the SubjectPublicKeyInfo for
// AuthPack.clientPublicValue: algorithm dhKeyAgreement with
// DomainParameters { p, g, q=0 }, and the public value as a BIT STRING
// whose content is the raw unsigned big-endian bytes. RFC 3279 wraps the
// public value as a DER INTEGER inside the BIT STRING — X.509's
// SubjectPublicKeyInfo convention for DH, and the ONLY form the Windows
// KDC accepts: verified against certipy's working wire bytes (its BIT
// STRING holds `02 81 81 00 <y>`), and against the KDC's answer to the
// raw-bytes form (KRB_ERR_GENERIC with empty e-text).
func buildClientPublicValue(pub *big.Int) []byte {
	algID := tlv(tagSequence, bytes.Join([][]byte{
		oidTLV(oidDHKeyAgreement),
		must(asn1.Marshal(dhDomainParameters{P: dhGroup2Prime, G: dhGroup2Generator, Q: big.NewInt(0)})),
	}, nil))
	// BIT STRING: tag 0x03, unused-bits count 0, then DER(INTEGER y).
	bitString := tlv(0x03, append([]byte{0x00}, intTLV(pub)...))
	return tlv(tagSequence, bytes.Join([][]byte{algID, bitString}, nil))
}

// dhRepInfo is RFC 4556 §3.2.3 DHRepInfo: dhSignedData [0] IMPLICIT
// OCTET STRING (the DER of the CMS ContentInfo holding the KDC's
// SignedData) and serverDHNonce [1] EXPLICIT DHNonce, present when the
// KDC reuses its DH keys — Windows always sends it.
type dhRepInfo struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"`
}

// kdcDHKeyInfo is RFC 4556 §3.2.3.1 KDCDHKeyInfo. The nonce field echoes
// the client's pkAuthenticator nonce when the KDC does NOT reuse DH keys
// and is 0 when it does (Windows reuses, so 0); like certipy we parse
// but never enforce it. dhKeyExpiration is present iff the keys are
// reused.
type kdcDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int            `asn1:"explicit,tag:1"`
	DHKeyExpiration  asn1.RawValue  `asn1:"explicit,optional,tag:2"`
}

// unwrapDHInfo extracts the AS reply key from a dhInfo PA-PK-AS-REP
// (RFC 4556 §3.2.3.1), following certipy's verified flow: parse the
// KDC's SignedData, pull its DH public value out of KDCDHKeyInfo, and
// derive the reply key from the shared secret and both nonces.
func unwrapDHInfo(dhInfoDER []byte, dh *dhClient, etype int32) (types.EncryptionKey, error) {
	var di dhRepInfo
	if _, err := asn1.Unmarshal(dhInfoDER, &di); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the DHRepInfo: %v", err)
	}
	if len(di.DHSignedData) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("the DHRepInfo carries no dhSignedData")
	}

	// dhSignedData is the DER of a ContentInfo holding the KDC's
	// SignedData — the mirror image of our signedAuthPack.
	var ci contentInfo
	if _, err := asn1.Unmarshal(di.DHSignedData, &ci); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the KDC's dhSignedData ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return types.EncryptionKey{}, fmt.Errorf("dhSignedData holds %s, not id-signedData (1.2.840.113549.1.7.2)", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the KDC's dhSignedData: %v", err)
	}
	// certipy enforces this OID check; RFC 4556 §3.2.3.1 item 2 requires
	// the content-type signed attribute to carry the same value.
	if !sd.EncapContentInfo.EContentType.Equal(oidPKINITDHKeyData) {
		return types.EncryptionKey{}, fmt.Errorf("unexpected key info content type %s, want id-pkinit-DHKeyData (1.3.6.1.5.2.3.2)", sd.EncapContentInfo.EContentType)
	}

	var kdh kdcDHKeyInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &kdh); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the KDCDHKeyInfo: %v", err)
	}
	// The KDC's DH public value is a DER INTEGER inside the BIT STRING
	// (X.509's SubjectPublicKeyInfo convention for DH — the same form the
	// client side must use, byte-verified against certipy: its slice of
	// the KDC BIT STRING skips exactly the 7 header bytes of `03 81 84 00
	// 02 81 81 00`). Reading the whole content as the integer (header
	// included) yields a 133-byte "public value" and an integrity failure
	// at the enc-part.
	var kdcPub *big.Int
	if _, err := asn1.Unmarshal(kdh.SubjectPublicKey.Bytes, &kdcPub); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the KDC's DH public value: %v", err)
	}
	if kdcPub.Sign() <= 0 {
		return types.EncryptionKey{}, fmt.Errorf("the KDC sent an empty DH public value")
	}

	// The KDC's signature over the dhSignedData is not chain-verified:
	// we hold no root CAs, same stance as the Python tooling. The reply
	// key still only works if the KDC knew our AuthPack signature was
	// valid, which binds the exchange to our certificate.
	return deriveDHReplyKey(dh.priv, kdcPub, dh.nonce, di.ServerDHNonce, etype)
}

// deriveDHReplyKey computes the AS reply key per RFC 4556 §3.2.3.1 step
// 5: k = octetstring2key(DHSharedSecret ‖ n_c ‖ n_k), where n_c is the
// clientDHNonce and n_k the serverDHNonce. Windows reuses its DH keys,
// so both nonces are always in play against AD — the RFC's conditional
// (nonces empty unless dhKeyExpiration is present) is exactly the case
// Windows is in, and certipy's unconditional concatenation is what was
// verified live. The shared secret is the minimal unsigned big-endian
// encoding (big.Int.Bytes), matching certipy's hex round-trip.
func deriveDHReplyKey(priv, kdcPub *big.Int, clientNonce, serverNonce []byte, etype int32) (types.EncryptionKey, error) {
	shared := new(big.Int).Exp(kdcPub, priv, dhGroup2Prime)

	full := make([]byte, 0, len(shared.Bytes())+len(clientNonce)+len(serverNonce))
	full = append(full, shared.Bytes()...)
	full = append(full, clientNonce...)
	full = append(full, serverNonce...)

	// The truncation length comes from the AS-REP enc-part etype.
	// RFC 4556 §3.1.1 makes AES128/AES256 the mandatory reply enctypes;
	// RC4 would need a different KDF input length dance that
	// minikerberos documents as unimplemented — and we never offer RC4.
	var keyLen int
	switch etype {
	case 18:
		keyLen = 32
	case 17:
		keyLen = 16
	default:
		return types.EncryptionKey{}, fmt.Errorf("unexpected etype %d in the AS-REP — PKINIT DH mode supports AES256/AES128 reply keys", etype)
	}
	return types.EncryptionKey{KeyType: etype, KeyValue: truncateKey(full, keyLen)}, nil
}

// truncateKey is the K-truncate of RFC 4556 §3.2.3.1's octetstring2key:
//
//	K-truncate(SHA1(0x00 ‖ x) ‖ SHA1(0x01 ‖ x) ‖ SHA1(0x02 ‖ x) ‖ …)
//
// byte-compatible with certipy's truncate_key (verified against the
// Windows KDC).
func truncateKey(value []byte, keySize int) []byte {
	out := make([]byte, 0, keySize+sha1.Size)
	buf := make([]byte, 1+len(value))
	copy(buf[1:], value)
	for i := 0; len(out) < keySize; i++ {
		buf[0] = byte(i)
		h := sha1.Sum(buf)
		out = append(out, h[:]...)
	}
	return out[:keySize]
}
