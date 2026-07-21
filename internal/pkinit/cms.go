package pkinit

// Minimal CMS (RFC 3852) machinery for PKINIT RSA key transport.
//
// This is deliberately the smallest CMS surface the protocol needs — no
// Diffie-Hellman, no CRLs, no counter-signatures, exactly one signer:
//
//   - buildSignedData emits a ContentInfo wrapping a SignedData
//     (RFC 3852 §5.1) with one SignerInfo, version 1 throughout (X.509
//     certificates plus an issuerAndSerialNumber sid), the client
//     certificate as the only entry in certificates (RFC 4556 §3.2.1
//     item 7 wants the chain hinted but forbids roots — we send just
//     the leaf), and an RSASSA-PKCS1v15-SHA-256 signature.
//   - unwrapReplyKeyPack reverses the KDC's reply: ContentInfo
//     (id-envelopedData) → EnvelopedData → one KeyTransRecipientInfo
//     (RSAES-PKCS1-v1_5, the key transport RFC 4556 §3.1.2 makes
//     mandatory and the only one Windows emits) → a temporary content
//     key → 3DES-CBC/AES-CBC → the inner ContentInfo (SignedData)
//     whose eContent is the ReplyKeyPack holding the AS reply key.
//
// Everything here is DER. encoding/asn1 marshals the primitive types
// (OID, INTEGER, OCTET STRING, times, NULL); the context-specific
// wrappers are hand-rolled TLVs because Go's encoder cannot express
// "[0] IMPLICIT OCTET STRING carrying a foreign DER blob" without
// them.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// Object identifiers, with the document that pins each one.
var (
	oidSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}     // id-signedData (RFC 3852 §3)
	oidEnvelopedData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}     // id-envelopedData (RFC 3852 §6)
	oidPKINITAuthData        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}         // id-pkinit-authData (RFC 4556 §3.2.1)
	oidPKINITRKeyData        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 3}         // id-pkinit-rkeyData (RFC 4556 §3.2.3.2)
	oidSHA1                  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}             // id-sha1 (RFC 3370 §2.3)
	oidSHA256                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} // id-sha256 (RFC 5754 §2.1)
	oidRSAEncryption         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}     // rsaEncryption = RSAES-PKCS1-v1_5 (RFC 3370 §2.2)
	oidSHA1WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}     // sha1WithRSAEncryption (RFC 3370 §2.2)
	oidRSAESOAEP             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}     // id-RSAES-OAEP (RFC 3560 §3)
	oidAttrContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}     // contentType attribute (RFC 3852 §11.1)
	oidAttrSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}     // signingTime attribute (RFC 3852 §11.3)
	oidAttrMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}     // messageDigest attribute (RFC 3852 §11.2)
	oidDESEDECBC             = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}        // des-ede3-cbc (RFC 3370 §3.1)
	oidAES128CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// ASN.1 tags used by the hand-rolled TLVs. All tags here are below 31,
// so a single tag octet always suffices.
const (
	tagSequence    = 0x30
	tagSet         = 0x31
	tagOctetString = 0x04
)

// derLen encodes a DER length: short form below 128, long form above.
func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// tlv wraps content in a TLV with a single-octet tag.
func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+4)
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// explicit wraps inner in "[n] EXPLICIT" — a context-specific constructed
// tag holding one complete inner TLV. This is the module-default tagging
// of RFC 4556 Appendix A (DEFINITIONS EXPLICIT TAGS ::=).
func explicit(n int, inner []byte) []byte {
	return tlv(byte(0xA0+n), inner)
}

// implicitOctetString wraps content in "[n] IMPLICIT OCTET STRING" — a
// context-specific primitive tag whose content octets are the embedded
// DER blob verbatim. RFC 4556 uses this for signedAuthPack and
// encKeyPack; the minikerberos client builds the identical 0x80 wrapper
// by hand, which is how we know Windows decodes it.
func implicitOctetString(n int, content []byte) []byte {
	return tlv(byte(0x80+n), content)
}

// must marshals a value whose encoding cannot fail (static OIDs, small
// integers, byte strings); an error here would be a programming bug, not
// runtime input.
func must(b []byte, err error) []byte {
	if err != nil {
		panic(fmt.Sprintf("pkinit: asn1 marshal of static value failed: %v", err))
	}
	return b
}

// oidTLV marshals an OBJECT IDENTIFIER.
func oidTLV(oid asn1.ObjectIdentifier) []byte { return must(asn1.Marshal(oid)) }

// intTLV marshals an INTEGER.
func intTLV(v interface{}) []byte { return must(asn1.Marshal(v)) }

// octetTLV marshals an OCTET STRING.
func octetTLV(b []byte) []byte { return tlv(tagOctetString, b) }

// generalizedTimeTLV marshals a KerberosTime — GeneralizedTime, second
// granularity, UTC ("Z"). RFC 4556 imports KerberosTime from RFC 4120.
func generalizedTimeTLV(t time.Time) []byte {
	return must(asn1.MarshalWithParams(t.UTC().Truncate(time.Second), "generalized"))
}

// utcTimeTLV marshals a CMS signingTime. RFC 3852 §11.3 requires UTCTime
// for years 1950–2049 (asn1.MarshalWithParams "utc" enforces it).
func utcTimeTLV(t time.Time) []byte {
	return must(asn1.MarshalWithParams(t.UTC(), "utc"))
}

// algorithmIdentifier is the RFC 3280 AlgorithmIdentifier. The NULL
// parameters on the algorithms we emit (sha-256, rsaEncryption) match
// OpenSSL/Windows output; on decode the Parameters RawValue simply
// captures whatever arrived.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// algIdentifierDER marshals an AlgorithmIdentifier with explicit NULL
// parameters — the form certipy and Windows emit for DIGEST algorithms.
func algIdentifierDER(oid asn1.ObjectIdentifier) []byte {
	return must(asn1.Marshal(algorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}))
}

// sigAlgIdentifierDER marshals an AlgorithmIdentifier with the parameters
// field ABSENT — the form certipy's SignedDigestAlgorithm emits for
// sha1WithRSAEncryption and the only form a Windows KDC accepts in the
// PKINIT SignerInfo (verified live: an explicit NULL there gets the whole
// request rejected with KRB_ERR_GENERIC, two bytes' difference).
func sigAlgIdentifierDER(oid asn1.ObjectIdentifier) []byte {
	return must(asn1.Marshal(algorithmIdentifier{Algorithm: oid}))
}

// issuerAndSerialNumber is the CMS SignerIdentifier form both sides of
// PKINIT use (RFC 3852 §5.1): the certificate's issuer Name verbatim
// plus its serial number.
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// issuerAndSerialDER marshals IssuerAndSerialNumber for cert.
func issuerAndSerialDER(cert *x509.Certificate) []byte {
	return must(asn1.Marshal(issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}))
}

// cmsAttribute marshals Attribute ::= SEQUENCE { attrType OID, attrValues
// SET OF AttributeValue } (RFC 3852 §10.1.1) with a single value.
func cmsAttribute(attrOID asn1.ObjectIdentifier, valueDER []byte) []byte {
	return tlv(tagSequence, bytes.Join([][]byte{
		oidTLV(attrOID),
		tlv(tagSet, valueDER),
	}, nil))
}

// buildSignedData produces the DER of a CMS ContentInfo { id-signedData,
// SignedData } over contentDER, signed with key and carrying cert. The
// shape is exactly what RFC 4556 §3.2.1 enumerates for the
// signedAuthPack: eContentType is the caller-supplied content OID
// (id-pkinit-authData for the AS-REQ), eContent holds contentDER, one
// signerInfo signs the content.
//
// The signedAttrs carry contentType and messageDigest (both mandatory
// per RFC 3852 §5.3; RFC 4556 §3.2.1 item 2 repeats the contentType
// requirement) plus signingTime (a SHOULD). The digest is SHA-1: that is
// the RFC 4556 §3.1.1 mandatory baseline and what certipy/minikerberos/
// Rubeus emit — and what a Windows KDC actually verifies. We shipped
// SHA-256 first (Windows has accepted it elsewhere since Vista/2008) and
// a Server 2022 KDC answered KRB_ERR_GENERIC; SHA-1 issues the TGT.
//
// The signature input is the DER of the signedAttrs with the field's
// [0] IMPLICIT tag replaced by the universal SET OF tag (RFC 3852 §5.4).
func buildSignedData(contentOID asn1.ObjectIdentifier, contentDER []byte, cert *x509.Certificate, key *rsa.PrivateKey, signingTime time.Time) ([]byte, error) {
	contentDigest := sha1.Sum(contentDER)

	// DER requires SET OF members in ascending encoded order; with
	// length octets second, that order is contentType, signingTime,
	// messageDigest — but sorting the encodings keeps that true for
	// any attribute set rather than relying on the observation.
	attrs := [][]byte{
		cmsAttribute(oidAttrContentType, oidTLV(contentOID)),
		cmsAttribute(oidAttrMessageDigest, octetTLV(contentDigest[:])),
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	attrSet := bytes.Join(attrs, nil)

	sigInput := tlv(tagSet, attrSet) // SET OF Attribute, per RFC 3852 §5.4
	sigHash := sha1.Sum(sigInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sigHash[:])
	if err != nil {
		return nil, fmt.Errorf("signing the CMS signedAttrs: %v", err)
	}

	// SignerInfo ::= SEQUENCE { version 1, sid issuerAndSerialNumber,
	// digestAlgorithm sha-1, signedAttrs [0] IMPLICIT,
	// signatureAlgorithm sha1WithRSAEncryption, signature OCTET STRING }.
	// sha1WithRSAEncryption (1.2.840.113549.1.1.5) is the signatureAlgorithm
	// certipy/minikerberos emit and Windows verifies.
	signerInfo := tlv(tagSequence, bytes.Join([][]byte{
		intTLV(1),
		issuerAndSerialDER(cert),
		algIdentifierDER(oidSHA1),
		tlv(0xA0, attrSet), // signedAttrs [0] IMPLICIT SignedAttributes
		sigAlgIdentifierDER(oidSHA1WithRSAEncryption),
		octetTLV(sig),
	}, nil))

	// SignedData ::= SEQUENCE { version 3, digestAlgorithms {sha-1},
	// encapContentInfo, certificates [0] IMPLICIT, signerInfos }. Version 3
	// is what certipy emits and the Windows KDC accepts (v1 is the CMS-
	// correct value for this shape, but we match the wire that works).
	signedData := tlv(tagSequence, bytes.Join([][]byte{
		intTLV(3),
		tlv(tagSet, algIdentifierDER(oidSHA1)),
		tlv(tagSequence, bytes.Join([][]byte{ // encapContentInfo
			oidTLV(contentOID),
			explicit(0, octetTLV(contentDER)), // eContent [0] EXPLICIT OCTET STRING
		}, nil)),
		tlv(0xA0, cert.Raw), // certificates [0] IMPLICIT CertificateSet — the leaf only
		tlv(tagSet, signerInfo),
	}, nil))

	// ContentInfo ::= SEQUENCE { contentType id-signedData, content [0]
	// EXPLICIT SignedData }.
	return tlv(tagSequence, bytes.Join([][]byte{
		oidTLV(oidSignedData),
		explicit(0, signedData),
	}, nil)), nil
}

// Decode-side structures for the KDC's reply. RawValue fields skip what
// we do not consume (digestAlgorithms, the KDC's certificates, its
// signerInfos) without pinning their shapes.

// contentInfo is the outer CMS wrapper (RFC 3852 §3): the content is
// [0] EXPLICIT anything. Go's RawValue captures the context [0] element
// whole, so the inner TLV rides in .Bytes.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

// envelopedData is the RFC 3852 §6.1 structure Windows wraps the reply
// key in.
type envelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue // SET OF RecipientInfo
	EncryptedContentInfo encryptedContentInfo
}

// encryptedContentInfo names the inner content (id-signedData) and holds
// the ciphertext as [0] IMPLICIT OCTET STRING.
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"`
}

// keyTransRecipientInfo is the only RecipientInfo choice RFC 4556 §3.2.3.2
// item 7 allows: the temporary key RSA-encrypted to the client cert.
type keyTransRecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  asn1.RawValue // rid; contents unused — the key tries regardless
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

// signedData mirrors the encode side for the KDC's inner SignedData; we
// consume only encapContentInfo.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// encapsulatedContentInfo carries the ReplyKeyPack as eContent [0]
// EXPLICIT OCTET STRING.
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// replyKeyPack is RFC 4556 §3.2.3.2: replyKey [0] EXPLICIT EncryptionKey
// (the AS reply key), asChecksum [1] EXPLICIT Checksum. The EXPLICIT
// tags follow the RFC 4556 Appendix A module default.
type replyKeyPack struct {
	ReplyKey   encryptionKey `asn1:"explicit,tag:0"`
	AsChecksum asn1.RawValue `asn1:"explicit,optional,tag:1"`
}

// encryptionKey is the RFC 4120 EncryptionKey: keytype [0] Int32,
// keyvalue [1] OCTET STRING.
type encryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// unwrapReplyKeyPack decrypts the AS reply key out of the encKeyPack
// content octets (the DER of a ContentInfo holding an EnvelopedData) per
// RFC 4556 §3.2.4. The returned key's KeyType comes from the
// ReplyKeyPack; callers decrypt the AS-REP enc-part with it.
func unwrapReplyKeyPack(encKeyPack []byte, key *rsa.PrivateKey) (types.EncryptionKey, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(encKeyPack, &ci); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the reply ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return types.EncryptionKey{}, fmt.Errorf("reply ContentInfo holds %s, not id-envelopedData (1.2.840.113549.1.7.3)", ci.ContentType)
	}

	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the reply EnvelopedData: %v", err)
	}
	if len(ed.RecipientInfos.Bytes) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("the reply EnvelopedData carries no recipient info")
	}

	// RFC 4556 §3.2.3.2 item 7: exactly one KeyTransRecipientInfo; its
	// encryptedKey is the temporary key RSA-encrypted to our client cert.
	var ktri keyTransRecipientInfo
	if _, err := asn1.Unmarshal(ed.RecipientInfos.Bytes, &ktri); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the reply KeyTransRecipientInfo: %v", err)
	}
	switch {
	case ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption):
		// RSAES-PKCS1-v1_5 — what Windows KDCs emit (RFC 4556 §3.1.2).
	case ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP):
		// Documented but not implemented: no Windows KDC uses OAEP
		// here, and stdlib OAEP decryption needs the KDC's parameters.
		return types.EncryptionKey{}, fmt.Errorf("the KDC used RSA-OAEP key transport; anvil implements RSA PKCS#1 v1.5 (what Windows emits)")
	default:
		return types.EncryptionKey{}, fmt.Errorf("unsupported reply key transport algorithm %s", ktri.KeyEncryptionAlgorithm.Algorithm)
	}
	tempKey, err := rsa.DecryptPKCS1v15(rand.Reader, key, ktri.EncryptedKey)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("RSA-decrypting the reply key transport blob (private key does not match the certificate the KDC used?): %v", err)
	}

	plain, err := decryptEnvelopedContent(tempKey, ed.EncryptedContentInfo)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	// RFC 4556 §3.2.3.2 wraps the inner SignedData in a ContentInfo of
	// its own before encrypting (this is what Windows sends, and what
	// Heimdal's PKINIT_27 path decodes). A bare SignedData is tolerated
	// — some KDC builds skip the second wrapper.
	sdDER := plain
	var inner contentInfo
	if _, err := asn1.Unmarshal(plain, &inner); err == nil && inner.ContentType.Equal(oidSignedData) {
		sdDER = inner.Content.Bytes
	}

	var sd signedData
	if _, err := asn1.Unmarshal(sdDER, &sd); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the KDC's inner SignedData: %v", err)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("the KDC's inner SignedData carries no eContent")
	}

	// eContentType should be id-pkinit-rkeyData; the check is
	// deliberately not enforced. Heimdal #if0's the same OID check
	// after meeting "windows LH with interesting CMS packets" — the
	// ReplyKeyPack parse below is the real gate.
	var rkp replyKeyPack
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &rkp); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parsing the ReplyKeyPack: %v", err)
	}
	if len(rkp.ReplyKey.KeyValue) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("the ReplyKeyPack carries an empty reply key")
	}

	// asChecksum is parsed but not verified. The RFC makes it a MUST
	// (key usage 6 over the AS-REQ with the reply key), and Heimdal
	// enforces it — but we already authenticate the KDC by being able
	// to unwrap a key it encrypted to our certificate, and impacket/
	// certipy take the same pragmatic stance. The KDC signature over
	// the inner SignedData is likewise not chain-verified: we hold no
	// root CAs, exactly like the Python tooling.
	return types.EncryptionKey{KeyType: rkp.ReplyKey.KeyType, KeyValue: rkp.ReplyKey.KeyValue}, nil
}

// decryptEnvelopedContent reverses the EnvelopedData content encryption.
// 3DES-CBC is the algorithm RFC 4556 §3.1.2 makes mandatory and what a
// Windows KDC picks when the client advertises no supportedCMSTypes;
// AES-CBC is accepted defensively. The IV travels in the algorithm
// parameters as an OCTET STRING; padding is PKCS#7 (RFC 3852 §6.3).
func decryptEnvelopedContent(tempKey []byte, eci encryptedContentInfo) ([]byte, error) {
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("parsing the content-encryption IV: %v", err)
	}

	alg := eci.ContentEncryptionAlgorithm.Algorithm
	var block cipher.Block
	var err error
	switch {
	case alg.Equal(oidDESEDECBC):
		block, err = des.NewTripleDESCipher(tempKey)
	case alg.Equal(oidAES128CBC), alg.Equal(oidAES192CBC), alg.Equal(oidAES256CBC):
		block, err = aes.NewCipher(tempKey)
	default:
		return nil, fmt.Errorf("unsupported reply content-encryption algorithm %s (anvil implements 3DES-CBC and AES-CBC)", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("the transported content key is wrong for %s: %v", alg, err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("content-encryption IV is %d bytes, want %d", len(iv), block.BlockSize())
	}

	ct := eci.EncryptedContent
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("enveloped content length %d is not a multiple of the cipher block size", len(ct))
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pkcs7Unpad(pt, block.BlockSize())
}

// pkcs7Unpad strips and validates PKCS#7 padding.
func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty enveloped content")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, fmt.Errorf("bad PKCS#7 padding on the enveloped content")
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil, fmt.Errorf("bad PKCS#7 padding on the enveloped content")
		}
	}
	return b[:len(b)-n], nil
}
