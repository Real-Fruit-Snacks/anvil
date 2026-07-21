package pkinit

// Hermetic tests: every structure is built and re-parsed in-process, and
// the CMS SignedData is additionally verified cryptographically (and by
// openssl when one is on PATH). No network, no KDC.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// makeTestCertKey generates a self-signed client-auth certificate and
// its RSA key — the in-test stand-in for CA-issued certreq loot.
func makeTestCertKey(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x5eed),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert, key
}

// pemPair renders the certreq loot layout: CERTIFICATE block, then the
// key block.
func pemPair(cert *x509.Certificate, keyType string, keyDER []byte) []byte {
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER})...)
}

func TestParsePEMCertKey(t *testing.T) {
	cert, key := makeTestCertKey(t, "testuser")
	otherCert, otherKey := makeTestCertKey(t, "otheruser")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8: %v", err)
	}
	ecPKCS8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshaling EC PKCS#8: %v", err)
	}
	otherPKCS8DER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatalf("marshaling other PKCS#8: %v", err)
	}

	tests := []struct {
		name    string
		pem     []byte
		wantErr string
	}{
		{"pkcs8 pair (certreq loot format)", pemPair(cert, "PRIVATE KEY", pkcs8DER), ""},
		{"pkcs1 pair (openssl-converted key)", pemPair(cert, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)), ""},
		{"certificate only", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), "no PRIVATE KEY"},
		{"key only", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}), "no CERTIFICATE"},
		{"ec key in pkcs8", pemPair(cert, "PRIVATE KEY", ecPKCS8DER), "not RSA"},
		{"consistent second pair parses fine", pemPair(otherCert, "PRIVATE KEY", otherPKCS8DER), ""},
		{"cert with someone else's key", append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherPKCS8DER})...), "does not match"},
		{"not pem at all", []byte("this is not a pem file"), "no CERTIFICATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCert, gotKey, err := ParsePEMCertKey(tt.pem)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotCert == nil || gotKey == nil {
				t.Fatal("expected cert and key, got nil")
			}
		})
	}

	// Round-trip fidelity on the primary format: the parsed cert is the
	// same cert, the parsed key is the same key.
	gotCert, gotKey, err := ParsePEMCertKey(pemPair(cert, "PRIVATE KEY", pkcs8DER))
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if !bytes.Equal(gotCert.Raw, cert.Raw) {
		t.Error("round-trip: certificate bytes differ")
	}
	if gotKey.N.Cmp(key.N) != 0 || gotKey.D.Cmp(key.D) != 0 {
		t.Error("round-trip: key material differs")
	}
}

// testSignerInfo decodes one SignerInfo out of a SignedData's signerInfos
// SET for the structure walk.
type testSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

// testAttr decodes one signedAttr.
type testAttr struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// buildTestSignedData is the shared fixture: a SignedData over a real
// (DH-mode) AuthPack, signed by a generated cert, with a fixed
// signingTime so the structure walk is deterministic.
func buildTestSignedData(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) (ciDER, authPackDER []byte, signingTime time.Time) {
	t.Helper()
	signingTime = time.Date(2026, 7, 21, 14, 30, 5, 0, time.UTC)
	dh, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}
	authPackDER = buildAuthPack(signingTime, 123456789, sha1.New().Sum(nil), dh)
	ciDER, err = buildSignedData(oidPKINITAuthData, authPackDER, cert, key, signingTime)
	if err != nil {
		t.Fatalf("buildSignedData: %v", err)
	}
	return ciDER, authPackDER, signingTime
}

// walkSignedData re-parses a built ContentInfo down to the SignerInfo,
// asserting every structural invariant on the way.
func walkSignedData(t *testing.T, ciDER []byte) (sd signedData, si testSignerInfo) {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(ciDER, &ci); err != nil {
		t.Fatalf("decoding ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("ContentInfo contentType = %s, want id-signedData", ci.ContentType)
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decoding SignedData: %v", err)
	}
	if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err != nil {
		t.Fatalf("decoding SignerInfo: %v", err)
	}
	return sd, si
}

func TestBuildSignedDataStructure(t *testing.T) {
	cert, key := makeTestCertKey(t, "testuser")
	ciDER, authPackDER, signingTime := buildTestSignedData(t, cert, key)
	sd, si := walkSignedData(t, ciDER)

	// SignedData: version 1 (X.509 certs + issuerAndSerialNumber sid,
	// RFC 3852 §5.1), one digest algorithm, our eContent.
	if sd.Version != 3 {
		t.Errorf("SignedData version = %d, want 3", sd.Version)
	}
	var da algorithmIdentifier
	if _, err := asn1.Unmarshal(sd.DigestAlgorithms.Bytes, &da); err != nil {
		t.Fatalf("decoding digestAlgorithms: %v", err)
	}
	if !da.Algorithm.Equal(oidSHA1) {
		t.Errorf("digestAlgorithms[0] = %s, want id-sha1", da.Algorithm)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidPKINITAuthData) {
		t.Errorf("eContentType = %s, want id-pkinit-authData", sd.EncapContentInfo.EContentType)
	}
	if !bytes.Equal(sd.EncapContentInfo.EContent, authPackDER) {
		t.Error("eContent does not carry the AuthPack DER verbatim")
	}
	// certificates [0] IMPLICIT: the client cert is the only member, and
	// a Certificate CHOICE is the cert's own DER.
	if sd.Certificates.Class != asn1.ClassContextSpecific || sd.Certificates.Tag != 0 {
		t.Errorf("certificates tag = class %d tag %d, want context [0]", sd.Certificates.Class, sd.Certificates.Tag)
	}
	if !bytes.Equal(sd.Certificates.Bytes, cert.Raw) {
		t.Error("certificates does not carry the client certificate verbatim")
	}

	// SignerInfo: version 1, sid = issuer+serial of the cert, sha-256
	// digest, rsaEncryption signature algorithm.
	if si.Version != 1 {
		t.Errorf("SignerInfo version = %d, want 1", si.Version)
	}
	var sid issuerAndSerialNumber
	if _, err := asn1.Unmarshal(si.SID.FullBytes, &sid); err != nil {
		t.Fatalf("decoding sid: %v", err)
	}
	if !bytes.Equal(sid.Issuer.FullBytes, cert.RawIssuer) {
		t.Error("sid issuer does not match the certificate issuer")
	}
	if sid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("sid serial number does not match the certificate serial")
	}
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA1) {
		t.Errorf("SignerInfo digestAlgorithm = %s, want id-sha1", si.DigestAlgorithm.Algorithm)
	}
	if !si.SignatureAlgorithm.Algorithm.Equal(oidSHA1WithRSAEncryption) {
		t.Errorf("SignerInfo signatureAlgorithm = %s, want sha1WithRSAEncryption", si.SignatureAlgorithm.Algorithm)
	}
	if si.SignedAttrs.Class != asn1.ClassContextSpecific || si.SignedAttrs.Tag != 0 {
		t.Fatalf("signedAttrs tag = class %d tag %d, want context [0]", si.SignedAttrs.Class, si.SignedAttrs.Tag)
	}

	// signedAttrs: exactly contentType, signingTime, messageDigest, in
	// ascending DER order (SET OF canonical order), with the expected
	// values.
	contentDigest := sha1.Sum(authPackDER)
	seen := map[string]bool{}
	rest := si.SignedAttrs.Bytes
	var prev []byte
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			t.Fatalf("walking signedAttrs: %v", err)
		}
		if prev != nil && bytes.Compare(prev, rv.FullBytes) >= 0 {
			t.Error("signedAttrs are not in DER SET OF ascending order")
		}
		prev = rv.FullBytes

		var attr testAttr
		if _, err := asn1.Unmarshal(rv.FullBytes, &attr); err != nil {
			t.Fatalf("decoding signedAttr: %v", err)
		}
		switch {
		case attr.Type.Equal(oidAttrContentType):
			seen["contentType"] = true
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &oid); err != nil {
				t.Fatalf("decoding contentType value: %v", err)
			}
			if !oid.Equal(oidPKINITAuthData) {
				t.Errorf("contentType attribute = %s, want id-pkinit-authData", oid)
			}
		case attr.Type.Equal(oidAttrSigningTime):
			seen["signingTime"] = true
			var st time.Time
			if _, err := asn1.UnmarshalWithParams(attr.Values.Bytes, &st, "utc"); err != nil {
				t.Fatalf("decoding signingTime value: %v", err)
			}
			if !st.Equal(signingTime) {
				t.Errorf("signingTime attribute = %v, want %v", st, signingTime)
			}
		case attr.Type.Equal(oidAttrMessageDigest):
			seen["messageDigest"] = true
			var md []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &md); err != nil {
				t.Fatalf("decoding messageDigest value: %v", err)
			}
			if !bytes.Equal(md, contentDigest[:]) {
				t.Error("messageDigest attribute is not SHA-1(eContent)")
			}
		default:
			t.Errorf("unexpected signedAttr %s", attr.Type)
		}
	}
	for _, want := range []string{"contentType", "messageDigest"} {
		if !seen[want] {
			t.Errorf("missing signedAttr %s", want)
		}
	}

	// The signature verifies cryptographically against the cert's public
	// key: RSASSA-PKCS1v15-SHA-1 over the signedAttrs with the [0]
	// IMPLICIT tag swapped for SET OF (RFC 3852 §5.4).
	sigInput := tlv(tagSet, si.SignedAttrs.Bytes)
	sigHash := sha1.Sum(sigInput)
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("test certificate does not have an RSA public key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sigHash[:], si.Signature); err != nil {
		t.Errorf("signature does not verify with the certificate's public key: %v", err)
	}
}

// TestBuildSignedDataOpenSSL cross-checks the SignedData with the system
// openssl when one is available: an independent CMS implementation must
// verify our signature. Skipped when openssl is not on PATH.
func TestBuildSignedDataOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH")
	}
	cert, key := makeTestCertKey(t, "testuser")
	ciDER, authPackDER, _ := buildTestSignedData(t, cert, key)

	path := filepath.Join(t.TempDir(), "signeddata.der")
	if err := os.WriteFile(path, ciDER, 0600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	// -noverify: the fixture is self-signed; we are checking the CMS
	// signature, not a chain. -binary: without it openssl applies S/MIME
	// CRLF canonicalization to the extracted content (observed on Git
	// Bash openssl: a 0x0A inside the AuthPack came back as 0x0D 0x0A).
	// The verified eContent goes to a file for an exact byte comparison.
	contentPath := filepath.Join(t.TempDir(), "content.der")
	out, err := exec.Command(openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", path, "-noverify", "-out", contentPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify rejected our SignedData: %v\n%s", err, out)
	}
	content, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatalf("reading openssl-verified content: %v", err)
	}
	if !bytes.Equal(content, authPackDER) {
		t.Error("openssl-verified content is not byte-identical to the AuthPack DER we signed")
	}
}

// TestBuildPAPKASReq walks the full PA-PK-AS-REQ: the padata-value wraps
// the CMS ContentInfo in "[0] IMPLICIT OCTET STRING", and the AuthPack
// inside carries the PKAuthenticator fields — paChecksum matching the
// SHA-1 of a real gokrb5 KDC-REQ-BODY, built the way TGTWithCert builds
// it.
func TestBuildPAPKASReq(t *testing.T) {
	cert, key := makeTestCertKey(t, "testuser")

	// A real request body via gokrb5, mirroring TGTWithCert's
	// construction (no network: NewASReq is pure encoding).
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17}
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/LAB.LOCAL")
	asReq, err := messages.NewASReq("LAB.LOCAL", cfg, cName, sName)
	if err != nil {
		t.Fatalf("NewASReq: %v", err)
	}
	bodyDER, err := asReq.ReqBody.Marshal()
	if err != nil {
		t.Fatalf("marshaling req-body: %v", err)
	}
	paChecksum := sha1.Sum(bodyDER)

	now := time.Date(2026, 7, 21, 14, 30, 5, 123456000, time.UTC)
	dh, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}
	paValue, err := buildPAPKASReq(now, asReq.ReqBody.Nonce, paChecksum[:], cert, key, dh)
	if err != nil {
		t.Fatalf("buildPAPKASReq: %v", err)
	}

	// Outer SEQUENCE { [0] IMPLICIT OCTET STRING } — a single primitive
	// context [0] field holding the ContentInfo DER.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(paValue, &outer)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decoding PA-PK-AS-REQ: %v (rest %d)", err, len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != 16 || !outer.IsCompound {
		t.Fatalf("PA-PK-AS-REQ outer = class %d tag %d, want SEQUENCE", outer.Class, outer.Tag)
	}
	var field asn1.RawValue
	rest, err = asn1.Unmarshal(outer.Bytes, &field)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decoding signedAuthPack field: %v (rest %d)", err, len(rest))
	}
	if field.Class != asn1.ClassContextSpecific || field.Tag != 0 || field.IsCompound {
		t.Errorf("signedAuthPack = class %d tag %d compound %v, want primitive context [0] (IMPLICIT OCTET STRING)", field.Class, field.Tag, field.IsCompound)
	}

	// field.Bytes is the ContentInfo DER; walk it to the eContent, then
	// decode the AuthPack.
	var sd signedData
	var ci contentInfo
	if _, err := asn1.Unmarshal(field.Bytes, &ci); err != nil {
		t.Fatalf("decoding ContentInfo: %v", err)
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decoding SignedData: %v", err)
	}

	var ap asn1.RawValue
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &ap); err != nil {
		t.Fatalf("decoding AuthPack: %v", err)
	}
	if ap.Class != asn1.ClassUniversal || ap.Tag != 16 {
		t.Fatalf("AuthPack = class %d tag %d, want SEQUENCE", ap.Class, ap.Tag)
	}

	// AuthPack children in order: pkAuthenticator [0] EXPLICIT,
	// clientPublicValue [1] EXPLICIT, clientDHNonce [3] EXPLICIT.
	var pkField, cpvField, nonceField asn1.RawValue
	rest, err = asn1.Unmarshal(ap.Bytes, &pkField)
	if err != nil {
		t.Fatalf("decoding pkAuthenticator field: %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &cpvField)
	if err != nil {
		t.Fatalf("decoding clientPublicValue field: %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &nonceField)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decoding clientDHNonce field: %v (rest %d)", err, len(rest))
	}
	if pkField.Class != asn1.ClassContextSpecific || pkField.Tag != 0 || !pkField.IsCompound {
		t.Errorf("pkAuthenticator = class %d tag %d compound %v, want [0] EXPLICIT (constructed)", pkField.Class, pkField.Tag, pkField.IsCompound)
	}
	if cpvField.Class != asn1.ClassContextSpecific || cpvField.Tag != 1 || !cpvField.IsCompound {
		t.Errorf("clientPublicValue = class %d tag %d compound %v, want [1] EXPLICIT (constructed)", cpvField.Class, cpvField.Tag, cpvField.IsCompound)
	}
	if nonceField.Class != asn1.ClassContextSpecific || nonceField.Tag != 3 || !nonceField.IsCompound {
		t.Errorf("clientDHNonce = class %d tag %d compound %v, want [3] EXPLICIT (constructed)", nonceField.Class, nonceField.Tag, nonceField.IsCompound)
	}

	// clientPublicValue carries our DH public value; clientDHNonce must
	// come back byte-identical.
	walkClientPublicValue(t, cpvField.Bytes, dh.pub)
	var gotNonce []byte
	if _, err := asn1.Unmarshal(nonceField.Bytes, &gotNonce); err != nil {
		t.Fatalf("decoding clientDHNonce value: %v", err)
	}
	if !bytes.Equal(gotNonce, dh.nonce) {
		t.Error("clientDHNonce does not round-trip")
	}

	var pk struct {
		CUSec      int       `asn1:"explicit,tag:0"`
		CTime      time.Time `asn1:"generalized,explicit,tag:1"`
		Nonce      int       `asn1:"explicit,tag:2"`
		PAChecksum []byte    `asn1:"explicit,optional,tag:3"`
	}
	if _, err := asn1.Unmarshal(pkField.Bytes, &pk); err != nil {
		t.Fatalf("decoding PKAuthenticator: %v", err)
	}
	if pk.CUSec != 123456 {
		t.Errorf("cusec = %d, want 123456 (microseconds of %v)", pk.CUSec, now)
	}
	wantCTime := time.Date(2026, 7, 21, 14, 30, 5, 0, time.UTC)
	if !pk.CTime.Equal(wantCTime) {
		t.Errorf("ctime = %v, want %v", pk.CTime, wantCTime)
	}
	if pk.Nonce != asReq.ReqBody.Nonce {
		t.Errorf("nonce = %d, want the req-body nonce %d", pk.Nonce, asReq.ReqBody.Nonce)
	}
	if !bytes.Equal(pk.PAChecksum, paChecksum[:]) {
		t.Error("paChecksum is not the SHA-1 of the KDC-REQ-BODY DER")
	}
}

// buildTestKDCReply assembles the KDC side of the exchange around a
// reply key: ReplyKeyPack → inner SignedData (KDC-signed) →
// EnvelopedData (3DES/AES to a temp key, temp key RSA-encrypted to the
// client cert) → PA-PK-AS-REP encKeyPack [1].
func buildTestKDCReply(t *testing.T, contentAlg asn1.ObjectIdentifier, clientCert *x509.Certificate, clientPub *rsa.PublicKey, kdcCert *x509.Certificate, kdcKey *rsa.PrivateKey, replyKeyValue []byte) []byte {
	t.Helper()

	// ReplyKeyPack ::= SEQUENCE { replyKey [0] EXPLICIT EncryptionKey,
	// asChecksum [1] EXPLICIT Checksum }. The checksum content is shape
	// only — production deliberately does not verify it.
	rkp := tlv(tagSequence, bytes.Join([][]byte{
		explicit(0, tlv(tagSequence, bytes.Join([][]byte{
			explicit(0, intTLV(int32(18))),
			explicit(1, octetTLV(replyKeyValue)),
		}, nil))),
		explicit(1, tlv(tagSequence, bytes.Join([][]byte{
			explicit(0, intTLV(int32(16))),
			explicit(1, octetTLV(make([]byte, 24))),
		}, nil))),
	}, nil))

	innerCI, err := buildSignedData(oidPKINITRKeyData, rkp, kdcCert, kdcKey, time.Now())
	if err != nil {
		t.Fatalf("building inner SignedData: %v", err)
	}

	var tempKey, iv []byte
	var block cipher.Block
	switch {
	case contentAlg.Equal(oidDESEDECBC):
		tempKey, iv = randBytes(t, 24), randBytes(t, 8)
		block, err = des.NewTripleDESCipher(tempKey)
	case contentAlg.Equal(oidAES128CBC):
		tempKey, iv = randBytes(t, 16), randBytes(t, 16)
		block, err = aes.NewCipher(tempKey)
	case contentAlg.Equal(oidAES256CBC):
		tempKey, iv = randBytes(t, 32), randBytes(t, 16)
		block, err = aes.NewCipher(tempKey)
	default:
		t.Fatalf("test does not know %s", contentAlg)
	}
	if err != nil {
		t.Fatalf("building content cipher: %v", err)
	}

	pt := pkcs7Pad(innerCI, block.BlockSize())
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pt)

	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, clientPub, tempKey)
	if err != nil {
		t.Fatalf("RSA-encrypting the temp key: %v", err)
	}

	ktri := tlv(tagSequence, bytes.Join([][]byte{
		intTLV(0),
		issuerAndSerialDER(clientCert),
		algIdentifierDER(oidRSAEncryption),
		octetTLV(encKey),
	}, nil))
	ed := tlv(tagSequence, bytes.Join([][]byte{
		intTLV(0),
		tlv(tagSet, ktri),
		tlv(tagSequence, bytes.Join([][]byte{ // encryptedContentInfo
			oidTLV(oidSignedData),
			tlv(tagSequence, bytes.Join([][]byte{oidTLV(contentAlg), octetTLV(iv)}, nil)),
			implicitOctetString(0, ct),
		}, nil)),
	}, nil))
	ci := tlv(tagSequence, bytes.Join([][]byte{oidTLV(oidEnvelopedData), explicit(0, ed)}, nil))
	return implicitOctetString(1, ci) // PA-PK-AS-REP CHOICE: encKeyPack [1]
}

func TestUnwrapPAPKASREP(t *testing.T) {
	clientCert, clientKey := makeTestCertKey(t, "testuser")
	kdcCert, kdcKey := makeTestCertKey(t, "krbtgt")
	replyKeyValue := randBytes(t, 32) // aes256 reply key

	t.Run("RSA v1.5 unwrap round-trip", func(t *testing.T) {
		tests := []struct {
			name string
			alg  asn1.ObjectIdentifier
		}{
			{"3DES-CBC (RFC 4556 mandatory, Windows default)", oidDESEDECBC},
			{"AES-128-CBC", oidAES128CBC},
			{"AES-256-CBC", oidAES256CBC},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				paValue := buildTestKDCReply(t, tt.alg, clientCert, &clientKey.PublicKey, kdcCert, kdcKey, replyKeyValue)
				got, err := unwrapPAPKASREP(paValue, clientKey, nil, 18)
				if err != nil {
					t.Fatalf("unwrapPAPKASREP: %v", err)
				}
				if got.KeyType != 18 {
					t.Errorf("reply key type = %d, want 18 (aes256)", got.KeyType)
				}
				if !bytes.Equal(got.KeyValue, replyKeyValue) {
					t.Error("reply key bytes do not round-trip")
				}
			})
		}
	})

	t.Run("OAEP key transport gets a themed refusal", func(t *testing.T) {
		paValue := buildTestKDCReply(t, oidDESEDECBC, clientCert, &clientKey.PublicKey, kdcCert, kdcKey, replyKeyValue)
		// Rewrite the ktri algorithm OID to id-RSAES-OAEP: the fixture is
		// deterministic apart from the RSA ciphertext, so patch the DER
		// by rebuilding with the OID swapped — simplest is to corrupt via
		// bytes.Replace on the rsaEncryption OID TLV.
		oaepValue := bytes.Replace(paValue, oidTLV(oidRSAEncryption), oidTLV(oidRSAESOAEP), 1)
		if bytes.Equal(oaepValue, paValue) {
			t.Fatal("fixture does not contain the rsaEncryption OID to swap")
		}
		_, err := unwrapPAPKASREP(oaepValue, clientKey, nil, 18)
		if err == nil || !strings.Contains(err.Error(), "OAEP") {
			t.Fatalf("expected OAEP refusal, got %v", err)
		}
	})

	t.Run("DH reply without a DH offer gets a themed refusal", func(t *testing.T) {
		paValue := implicitOctetString(0, tlv(tagSequence, nil)) // dhInfo [0]
		_, err := unwrapPAPKASREP(paValue, clientKey, nil, 18)
		if err == nil || !strings.Contains(err.Error(), "Diffie-Hellman") {
			t.Fatalf("expected DH refusal, got %v", err)
		}
	})

	t.Run("wrong private key cannot unwrap", func(t *testing.T) {
		_, wrongKey := makeTestCertKey(t, "wronguser")
		paValue := buildTestKDCReply(t, oidDESEDECBC, clientCert, &clientKey.PublicKey, kdcCert, kdcKey, replyKeyValue)
		_, err := unwrapPAPKASREP(paValue, wrongKey, nil, 18)
		if err == nil || !strings.Contains(err.Error(), "RSA-decrypting") {
			t.Fatalf("expected RSA unwrap failure, got %v", err)
		}
	})
}

func TestPKINITError(t *testing.T) {
	tests := []struct {
		code     int32
		contains []string
	}{
		{6, []string{"KDC_ERR_C_PRINCIPAL_UNKNOWN", "user not found"}},
		{16, []string{"KDC_ERR_PADATA_TYPE_NOSUPP", "does not support"}},
		{25, []string{"KDC_ERR_PREAUTH_REQUIRED", "additional pre-authentication"}},
		{37, []string{"KRB_AP_ERR_SKEW", "clock skew"}},
		{60, []string{"KRB_ERR_GENERIC", "rejected PKINIT"}},
		{62, []string{"KDC_ERR_CLIENT_NOT_TRUSTED", "does not trust the client certificate"}},
		{64, []string{"KDC_ERR_INVALID_SIG", "signature"}},
		{65, []string{"KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED", "Diffie-Hellman"}},
		{66, []string{"KDC_ERR_CERTIFICATE_MISMATCH", "does not match"}},
		{70, []string{"KDC_ERR_CANT_VERIFY_CERTIFICATE", "could not verify the certificate chain"}},
		{71, []string{"KDC_ERR_INVALID_CERTIFICATE", "failed validation"}},
		{72, []string{"KDC_ERR_REVOKED_CERTIFICATE", "revoked"}},
		{73, []string{"KDC_ERR_REVOCATION_STATUS_UNKNOWN", "revocation status"}},
		{74, []string{"KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", "revocation source"}},
		{75, []string{"KDC_ERR_CLIENT_NAME_MISMATCH", "not bound to the requested user"}},
		{76, []string{"KDC_ERR_KDC_NAME_MISMATCH", "does not match the realm"}},
		{77, []string{"KDC_ERR_INCONSISTENT_KEY_PURPOSE", "client-auth EKU"}},
		{78, []string{"KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED", "digest the KDC does not accept"}},
		{79, []string{"KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED", "PA checksum"}},
		{80, []string{"KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED", "digest algorithm"}},
		{81, []string{"KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED", "RSA key transport"}},
		{999, []string{"KDC error", "999"}},
	}
	for _, tt := range tests {
		t.Run(errorcodeNameForTest(tt.code), func(t *testing.T) {
			err := pkinitError(messages.KRBError{ErrorCode: tt.code, EText: "extra detail"})
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, sub := range tt.contains {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing %q", err.Error(), sub)
				}
			}
			// The KDC's e-text always rides along — Windows packs the
			// real cause there.
			if !strings.Contains(err.Error(), "extra detail") {
				t.Errorf("error %q missing the KDC e-text", err.Error())
			}
		})
	}
}

// errorcodeNameForTest gives each table entry a readable subtest name.
func errorcodeNameForTest(code int32) string {
	if info, ok := pkinitErrorInfos[code]; ok {
		return info.name
	}
	return "unknown"
}

// pkcs7Pad appends PKCS#7 padding, the inverse of cms.go's pkcs7Unpad.
func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

// randBytes returns n random bytes.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// =========================================================================
// Diffie-Hellman mode (RFC 4556 §3.2.3.1)
// =========================================================================

// mustHex decodes a hardcoded test vector.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test vector: %v", err)
	}
	return b
}

// TestDHKeygenRoundTrip proves the Diffie-Hellman primitives: two
// independent keypairs derive the same shared secret in both directions
// (plain math/big modexp over the RFC 2412 group).
func TestDHKeygenRoundTrip(t *testing.T) {
	a, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}
	b, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}

	ab := new(big.Int).Exp(b.pub, a.priv, dhGroup2Prime)
	ba := new(big.Int).Exp(a.pub, b.priv, dhGroup2Prime)
	if ab.Cmp(ba) != 0 {
		t.Error("DH shared secrets disagree between directions")
	}
	if a.pub.Sign() <= 0 || a.pub.Cmp(dhGroup2Prime) >= 0 {
		t.Error("public value outside the group")
	}
	if len(a.nonce) != 32 || len(b.nonce) != 32 {
		t.Error("clientDHNonce must be 32 bytes (certipy os.urandom(32))")
	}
	if bytes.Equal(a.nonce, b.nonce) {
		t.Error("clientDHNonce is not random")
	}
}

// walkClientPublicValue re-parses a built SubjectPublicKeyInfo and
// asserts the DH algorithm, the DomainParameters { p, g, q=0 }, and that
// the BIT STRING carries the public value as a DER INTEGER (the X.509
// SubjectPublicKeyInfo convention for DH — the only form the Windows KDC
// accepts, verified against certipy's wire).
func walkClientPublicValue(t *testing.T, spkiDER []byte, wantPub *big.Int) {
	t.Helper()
	var spki asn1.RawValue
	rest, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decoding SubjectPublicKeyInfo: %v (rest %d)", err, len(rest))
	}
	if spki.Class != asn1.ClassUniversal || spki.Tag != 16 {
		t.Fatalf("SubjectPublicKeyInfo = class %d tag %d, want SEQUENCE", spki.Class, spki.Tag)
	}

	var algField, bitField asn1.RawValue
	rest, err = asn1.Unmarshal(spki.Bytes, &algField)
	if err != nil {
		t.Fatalf("decoding algorithm field: %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &bitField)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decoding publicKey field: %v (rest %d)", err, len(rest))
	}

	var oid asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(algField.Bytes, &oid)
	if err != nil {
		t.Fatalf("decoding algorithm OID: %v", err)
	}
	if !oid.Equal(oidDHKeyAgreement) {
		t.Errorf("algorithm = %s, want dhKeyAgreement (1.2.840.10046.2.1)", oid)
	}
	var params struct {
		P *big.Int
		G *big.Int
		Q *big.Int
	}
	if _, err := asn1.Unmarshal(rest, &params); err != nil {
		t.Fatalf("decoding DomainParameters: %v", err)
	}
	if params.P.Cmp(dhGroup2Prime) != 0 {
		t.Error("DomainParameters p is not the RFC 2412 group 2 prime")
	}
	if params.G.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("DomainParameters g = %v, want 2", params.G)
	}
	if params.Q == nil || params.Q.Sign() != 0 {
		t.Error("DomainParameters q must be present and 0 (Windows wants it)")
	}

	var bs asn1.BitString
	if _, err := asn1.Unmarshal(bitField.FullBytes, &bs); err != nil {
		t.Fatalf("decoding publicKey BIT STRING: %v", err)
	}
	// The BIT STRING content is DER(INTEGER y): asn1.Unmarshal of it must
	// yield wantPub exactly (Go's asn1 handles the sign byte).
	var y *big.Int
	if _, err := asn1.Unmarshal(bs.Bytes, &y); err != nil {
		t.Fatalf("publicKey BIT STRING content is not a DER INTEGER: %v", err)
	}
	if y.Cmp(wantPub) != 0 {
		t.Errorf("publicKey INTEGER = %x…, want %x…", y.Bytes()[:4], wantPub.Bytes()[:4])
	}
}

// TestBuildClientPublicValue checks the clientPublicValue DER shape end
// to end against a generated DH keypair.
func TestBuildClientPublicValue(t *testing.T) {
	dh, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}
	walkClientPublicValue(t, buildClientPublicValue(dh.pub), dh.pub)
}

// TestTruncateKey pins the RFC 4556 §3.2.3.1 octetstring2key truncation
// against vectors computed independently with certipy's truncate_key
// (Python hashlib) — the byte-exact KDF the Windows KDC uses.
func TestTruncateKey(t *testing.T) {
	tests := []struct {
		name   string
		input  string // hex
		size   int
		expect string // hex
	}{
		{
			"48-byte input, AES-256 length",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			32,
			"29e612fb53470812d07e25c36ba4be6b2a4c6e0bd0dde829c09155a42ac72fc4",
		},
		{
			"48-byte input, AES-128 length",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			16,
			"29e612fb53470812d07e25c36ba4be6b",
		},
		{
			"64-byte input (multi-round), AES-256 length",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			32,
			"322bd22cf094ad8240eb9ffdae847d2635ba6bcafc2b366bf31c5bc190f32a46",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateKey(mustHex(t, tt.input), tt.size)
			if !bytes.Equal(got, mustHex(t, tt.expect)) {
				t.Errorf("truncateKey = %x, want %s", got, tt.expect)
			}
		})
	}
}

// TestDeriveDHReplyKey pins the full derivation — modexp shared secret,
// nonce concatenation, truncation — against a vector computed
// independently in Python (pow() + certipy's truncate_key).
func TestDeriveDHReplyKey(t *testing.T) {
	clientPriv := new(big.Int).SetBytes(mustHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
	kdcPub := new(big.Int).SetBytes(mustHex(t,
		"0cfaaafb160cda22c4b61bc983d934b3953eaf41645c7936908b573e512116d5ad177dbb3e5bdd566fa953af8fecd9edca184a033f917e7517bff399a6a8aa"+
			"01240321ff82be7d764f9f7cbb4151aec400f2925aa1cbccc3e6108751f2a9e31a5c1c0a7d6396cd79f178ae67608c5318b180106c6f7d4c5cf0c2ab54a3286d2b"))
	clientNonce := bytes.Repeat([]byte{0xaa}, 32)
	serverNonce := bytes.Repeat([]byte{0xbb}, 32)

	tests := []struct {
		name   string
		etype  int32
		expect string
	}{
		{"AES-256 reply", 18, "ab0b23ab21c67bdd72886434b37dbc3f937b64b6a6eab9930fb984223fff8f87"},
		{"AES-128 reply", 17, "ab0b23ab21c67bdd72886434b37dbc3f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deriveDHReplyKey(clientPriv, kdcPub, clientNonce, serverNonce, tt.etype)
			if err != nil {
				t.Fatalf("deriveDHReplyKey: %v", err)
			}
			if got.KeyType != tt.etype {
				t.Errorf("key type = %d, want %d", got.KeyType, tt.etype)
			}
			if !bytes.Equal(got.KeyValue, mustHex(t, tt.expect)) {
				t.Errorf("reply key = %x, want %s", got.KeyValue, tt.expect)
			}
		})
	}

	t.Run("unsupported etype gets a themed refusal", func(t *testing.T) {
		_, err := deriveDHReplyKey(clientPriv, kdcPub, clientNonce, serverNonce, 23)
		if err == nil || !strings.Contains(err.Error(), "etype 23") {
			t.Fatalf("expected etype refusal, got %v", err)
		}
	})
}

// buildTestDHReply assembles the KDC side of a DH reply around the KDC's
// ephemeral DH keypair: KDCDHKeyInfo → KDC-signed SignedData → DHRepInfo
// → PA-PK-AS-REP dhInfo [0] EXPLICIT. The nonce field is 0 and
// dhKeyExpiration is present, the shape Windows sends when reusing its
// DH keys.
func buildTestDHReply(t *testing.T, contentOID asn1.ObjectIdentifier, kdcPriv *big.Int, kdcCert *x509.Certificate, kdcKey *rsa.PrivateKey, serverNonce []byte) []byte {
	t.Helper()
	kdcPub := new(big.Int).Exp(dhGroup2Generator, kdcPriv, dhGroup2Prime)

	// KDCDHKeyInfo ::= SEQUENCE { subjectPublicKey [0] EXPLICIT BIT
	// STRING, nonce [1] EXPLICIT INTEGER, dhKeyExpiration [2] EXPLICIT
	// KerberosTime OPTIONAL } — the BIT STRING carries the public value
	// as a DER INTEGER, exactly like the KDC (and our buildClientPublicValue).
	kdh := tlv(tagSequence, bytes.Join([][]byte{
		explicit(0, tlv(0x03, append([]byte{0x00}, intTLV(kdcPub)...))),
		explicit(1, intTLV(0)),
		explicit(2, generalizedTimeTLV(time.Now().Add(24*time.Hour))),
	}, nil))

	ci, err := buildSignedData(contentOID, kdh, kdcCert, kdcKey, time.Now())
	if err != nil {
		t.Fatalf("building KDC dhSignedData: %v", err)
	}
	dhRep := tlv(tagSequence, bytes.Join([][]byte{
		implicitOctetString(0, ci),
		explicit(1, octetTLV(serverNonce)),
	}, nil))
	return explicit(0, dhRep) // PA-PK-AS-REP CHOICE: dhInfo [0] EXPLICIT
}

// TestUnwrapDHInfo drives the full DH reply parse: a synthetic KDC
// dhInfo is unwrapped and the derived key compared against an
// independent in-test derivation over the same DH values.
func TestUnwrapDHInfo(t *testing.T) {
	clientDH, err := newDHClient()
	if err != nil {
		t.Fatalf("newDHClient: %v", err)
	}
	kdcPriv := new(big.Int).SetBytes(randBytes(t, 32))
	kdcCert, kdcKey := makeTestCertKey(t, "krbtgt")
	clientCert, clientKey := makeTestCertKey(t, "testuser")
	_ = clientCert
	serverNonce := randBytes(t, 32)

	t.Run("dhInfo unwrap round-trip", func(t *testing.T) {
		paValue := buildTestDHReply(t, oidPKINITDHKeyData, kdcPriv, kdcCert, kdcKey, serverNonce)
		got, err := unwrapPAPKASREP(paValue, clientKey, clientDH, 18)
		if err != nil {
			t.Fatalf("unwrapPAPKASREP: %v", err)
		}

		// Independent derivation over the same DH values (the truncateKey
		// KDF itself is pinned against Python-computed vectors in
		// TestDeriveDHReplyKey).
		kdcPub := new(big.Int).Exp(dhGroup2Generator, kdcPriv, dhGroup2Prime)
		shared := new(big.Int).Exp(kdcPub, clientDH.priv, dhGroup2Prime)
		full := append(append(append([]byte{}, shared.Bytes()...), clientDH.nonce...), serverNonce...)
		want := truncateKey(full, 32)

		if got.KeyType != 18 {
			t.Errorf("reply key type = %d, want 18 (aes256)", got.KeyType)
		}
		if !bytes.Equal(got.KeyValue, want) {
			t.Error("derived reply key does not match the independent derivation")
		}
	})

	t.Run("wrong key info content type gets a themed refusal", func(t *testing.T) {
		paValue := buildTestDHReply(t, oidPKINITAuthData, kdcPriv, kdcCert, kdcKey, serverNonce)
		_, err := unwrapPAPKASREP(paValue, clientKey, clientDH, 18)
		if err == nil || !strings.Contains(err.Error(), "unexpected key info content type") {
			t.Fatalf("expected content-type refusal, got %v", err)
		}
	})

	t.Run("empty dhSignedData gets a themed refusal", func(t *testing.T) {
		dhRep := tlv(tagSequence, bytes.Join([][]byte{
			implicitOctetString(0, nil),
			explicit(1, octetTLV(serverNonce)),
		}, nil))
		_, err := unwrapPAPKASREP(explicit(0, dhRep), clientKey, clientDH, 18)
		if err == nil || !strings.Contains(err.Error(), "no dhSignedData") {
			t.Fatalf("expected empty-dhSignedData refusal, got %v", err)
		}
	})
}
