package smbclient

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/icpr"
)

// CertResult is one issued certificate: the CA that issued it, the template
// it was requested against, the issued subject as the CA rendered it, and
// the PEM pair the operator takes away (issued cert only — no chain — plus
// the locally generated PKCS#8 key). PKCS#12 is deliberately not produced:
// Go has no stdlib encoder and the repo allows no new dependencies; the
// README documents the one-line openssl conversion.
type CertResult struct {
	CAName   string // "host\\CA-Name" used
	Template string
	Subject  string // issued cert's subject, rendered
	CertPEM  []byte
	KeyPEM   []byte
}

// Microsoft-private OIDs on the enrollment path.
var (
	// oidExtensionSubjectAltName is the standard X.509 SAN (2.5.29.17).
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// oidEnrollCertTypeExtension is szOID_ENROLL_CERTTYPE_EXTENSION
	// (1.3.6.1.4.1.311.20.2) — the CSR extension that names the certificate
	// template. The value is a DER-encoded UTF8String of the template name,
	// exactly the MS-WCCE 2.2.2.7.6 documented form
	// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3aec3e50-511a-42f9-a5d5-240af503e470).
	// Verified live against a Server 2022 CA: the raw-UTF16LE form some
	// client-code readings suggest gets the request rejected at disposition
	// 1 (CR_DISP_INCOMPLETE); the DER UTF8String issues.
	oidEnrollCertTypeExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}

	// oidNTPrincipalName is szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3),
	// the OtherName type-id a CA maps to the UPN SAN — per MS-WCCE
	// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f)
	// and certipy's lib/certificate.py (OID_PRINCIPAL_NAME). Do not confuse
	// with the sibling arc .2.1 (Certificate Request Agent EKU — see
	// internal/adenum/adcs.go) or .2.2 (Smart Card Logon EKU); neither
	// carries a UPN.
	oidNTPrincipalName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// enrollmentServicesBase is the Configuration-NC container holding one
// pKIEnrollmentService object per enterprise CA.
const enrollmentServicesBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"

// FindCA locates the domain's enterprise CA: over one transient LDAP channel
// it reads the pKIEnrollmentService objects under the Configuration NC's
// Public Key Services container and returns the first one's dNSHostName and
// cn (the CA's machine and CA name — the pair ICPR wants as "host\CA-Name").
// A domain with no AD CS has no such objects; that is its own themed error,
// not an empty result.
func (s *Session) FindCA() (caHost, caName string, err error) {
	if s.null || s.creds == nil || s.creds.Username == "" {
		return "", "", fmt.Errorf("certreq needs an authenticated session — this connection is a null session")
	}

	cl, cleanup, err := s.openLDAP()
	if err != nil {
		return "", "", err
	}
	defer cleanup()

	baseDN, err := cl.GetDefaultNamingContext()
	if err != nil {
		return "", "", fmt.Errorf("naming context: %v", err)
	}

	res, err := cl.Search(enrollmentServicesBase+baseDN,
		"(objectClass=pKIEnrollmentService)", []string{"dNSHostName", "cn"})
	if err != nil {
		return "", "", fmt.Errorf("search enrollment services: %v", err)
	}
	if len(res.Entries) == 0 {
		return "", "", fmt.Errorf("no enrollment services found")
	}
	entry := res.Entries[0] // first CA wins — multi-CA selection is the operator's job
	return entry.GetAttributeValue("dNSHostName"), entry.GetAttributeValue("cn"), nil
}

// CertRequest enrolls for a certificate against caHost\caName using template,
// riding the existing SMB session: the MS-ICPR interface (ICertPassage) lives
// on \pipe\cert, which only exists on hosts running AD CS — a pipe-open
// failure therefore means "no enrollment here", themed accordingly. Key and
// CSR are built locally (RSA-2048, PKCS#10): cn is the subject CN (empty →
// the session user), and a non-empty san goes into the CSR as a UPN
// subjectAltName — the ENROLLEE_SUPPLIES_SUBJECT (ESC1) primitive. The
// template is named twice per MS-WCCE/client practice: the CSR's
// szOID_ENROLL_CERTTYPE_EXTENSION and the ICPR attributes string.
func (s *Session) CertRequest(caHost, caName, template, cn, san string) (*CertResult, error) {
	if s.null || s.creds == nil || s.creds.Username == "" {
		return nil, fmt.Errorf("certreq needs an authenticated session — this connection is a null session")
	}
	if cn == "" {
		cn = s.creds.Username
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %v", err)
	}

	csrDER, err := buildCSR(key, template, cn, san)
	if err != nil {
		return nil, err
	}

	pipe, err := s.client.OpenPipe("cert")
	if err != nil {
		return nil, fmt.Errorf("no certificate enrollment on this server (no cert pipe)")
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	// The CA refuses an unauthenticated bind: CertServerRequest must run on
	// an NTLM-authenticated RPC bind at packet privacy (verified against a
	// Server 2022 CA — an unauthenticated bind faults with the misleading
	// EPT_S_NOT_REGISTERED / RPC_S_BINDING_HAS_NO_AUTH, and
	// IF_ENFORCEENCRYPTICERTREQUEST is on by default).
	if err := rpc.BindAuth(icpr.UUID, icpr.MajorVersion, icpr.MinorVersion, s.creds); err != nil {
		return nil, fmt.Errorf("bind ICPR: %v", err)
	}

	// The authority string is the CA's COMMON NAME only ("HACKERBLUEPRINT-CA"
	// — the pKIEnrollmentService cn), never host\name: certsrv answers the
	// host\name form with E_INVALIDARG (verified live).
	certDER, _, err := certServerRequest(rpc, caName, csrDER, certRequestAttributes(template))
	if err != nil {
		return nil, mapCertError(err)
	}

	// The CA's disposition said ISSUED; if the blob still doesn't parse, the
	// session caught something other than AD CS — surface it, don't save it.
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("CA returned an unparseable certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %v", err)
	}

	return &CertResult{
		CAName:   caHost + `\` + caName,
		Template: template,
		Subject:  cert.Subject.String(),
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// certRequestAttributes builds the MS-ICPR pctbAttribs string list. Only the
// template is named here: the SAN travels inside the CSR as an extension
// (certipy's CSR path — the "SAN:upn=..." attribute form is the separate
// EDITF_ATTRIBUTESUBJECTALTNAME2 scenario, not ENROLLEE_SUPPLIES_SUBJECT).
// certServerRequest performs MS-ICPR CertServerRequest (opnum 0) with the
// wire layout the Windows stub actually accepts, byte-for-byte verified
// against impacket: parameters in declaration order with each pointer's
// data deferred IMMEDIATELY after its referent — dwFlags, ref+pwszAuthority
// string, pdwRequestId inline, pctbAttribs cb+ref+array, pctbRequest
// cb+ref+array. gopacket's icpr.CertServerRequest marshals all inline
// fields first and faults with EPT_S_NOT_REGISTERED against a Server 2022
// CA; impacket's layout is what cexp/certipy produce on the wire, so that
// is what we emit. The attribute string is UTF-16LE, NUL-terminated, cb
// INCLUDING the NUL (the CA returns E_INVALIDARG otherwise, per MS-ICPR
// 3.1.4.1.1).
func certServerRequest(rpc *dcerpc.Client, caName string, csrDER, attrBytes []byte) ([]byte, uint32, error) {
	var buf bytes.Buffer
	ref := uint32(0x00020000)

	binary.Write(&buf, binary.LittleEndian, uint32(0)) // dwFlags
	binary.Write(&buf, binary.LittleEndian, ref)
	ref += 4
	writeICPRString(&buf, caName)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // pdwRequestId, inline

	binary.Write(&buf, binary.LittleEndian, uint32(len(attrBytes))) // pctbAttribs.cb
	binary.Write(&buf, binary.LittleEndian, ref)                    // pctbAttribs.pb
	ref += 4
	writeICPRByteArray(&buf, attrBytes)

	binary.Write(&buf, binary.LittleEndian, uint32(len(csrDER))) // pctbRequest.cb
	binary.Write(&buf, binary.LittleEndian, ref)                 // pctbRequest.pb
	writeICPRByteArray(&buf, csrDER)

	resp, err := rpc.CallAuth(0, buf.Bytes())
	if err != nil {
		return nil, 0, fmt.Errorf("CertServerRequest call failed: %v", err)
	}
	return parseCertServerResponse(resp)
}

// writeICPRString marshals a [unique, string] wchar_t*: maxCount, offset,
// actualCount (chars including the NUL), UTF-16LE data + NUL, padded to 4.
func writeICPRString(buf *bytes.Buffer, s string) {
	chars := utf16.Encode([]rune(s))
	binary.Write(buf, binary.LittleEndian, uint32(len(chars)+1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(len(chars)+1))
	for _, c := range chars {
		binary.Write(buf, binary.LittleEndian, c)
	}
	binary.Write(buf, binary.LittleEndian, uint16(0))
	icprPad4(buf)
}

// writeICPRByteArray marshals a conformant byte array (maxCount + data,
// padded to 4) — the pointee of a CERTTRANSBLOB's pb field.
func writeICPRByteArray(buf *bytes.Buffer, data []byte) {
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
	icprPad4(buf)
}

func icprPad4(buf *bytes.Buffer) {
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
}

// parseCertServerResponse reads the CertServerRequest response in the SAME
// per-field-deferred layout the request uses (verified byte-for-byte
// against a Server 2022 CA): pdwRequestId, pdwDisposition, then three
// CERTTRANSBLOBs — each cb, pb referent, and (when the referent is
// non-null) its conformant array right behind it — pctbCert (the PKCS#7
// chain, unused), pctbEncodedCert (the issued DER we want),
// pctbDispositionMessage (UTF-16 error text). Disposition 3/4 carries the
// cert; 5 means pending approval; the trailing HRESULT follows the blobs.
func parseCertServerResponse(resp []byte) ([]byte, uint32, error) {
	if len(resp) < 8 {
		return nil, 0, fmt.Errorf("ICPR response too short: %d bytes", len(resp))
	}
	off := 0
	u32 := func() (uint32, bool) {
		if off+4 > len(resp) {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(resp[off:])
		off += 4
		return v, true
	}
	readBlob := func() []byte {
		cb, ok1 := u32()
		ref, ok2 := u32()
		if !ok1 || !ok2 || ref == 0 {
			return nil
		}
		n, ok3 := u32()
		if !ok3 {
			return nil
		}
		size := int(n)
		if cb < n {
			size = int(cb)
		}
		if size < 0 || off+size > len(resp) {
			return nil
		}
		data := resp[off : off+size]
		off += (int(n) + 3) &^ 3
		return data
	}

	if _, ok := u32(); !ok { // pdwRequestId
		return nil, 0, fmt.Errorf("ICPR response too short for header")
	}
	disposition, _ := u32()
	_ = readBlob() // pctbCert — the PKCS#7 chain; the leaf we want is not in it
	certDER := readBlob()
	dispMsg := readBlob()

	switch disposition {
	case 3, 4: // CR_DISP_ISSUED / CR_DISP_ISSUED_OUT_OF_BAND
		return certDER, disposition, nil
	case 5: // CR_DISP_UNDER_SUBMISSION
		return nil, disposition, fmt.Errorf("certificate request pending approval")
	}
	if len(dispMsg) > 0 {
		return nil, disposition, fmt.Errorf("enrollment failed (disposition %d): %s", disposition, decodeUTF16(dispMsg))
	}
	return nil, disposition, fmt.Errorf("enrollment failed (disposition %d)", disposition)
}

// decodeUTF16 renders a UTF-16LE blob as UTF-8, dropping a trailing NUL.
func decodeUTF16(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// certRequestAttributes renders the MS-ICPR pctbAttribs payload: the
// template as "CertificateTemplate:<name>", UTF-16LE, NUL-terminated (cb
// includes the NUL — the CA returns E_INVALIDARG otherwise).
func certRequestAttributes(template string) []byte {
	return encodeUTF16LE("CertificateTemplate:" + template + "\x00")
}

// encodeUTF16LE converts s to UTF-16LE bytes (no BOM).
func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// buildCSR signs a PKCS#10 for cn with the template extension always and the
// UPN SAN extension when san is set. SignatureAlgorithm zero-value defaults
// to SHA256WithRSA for an RSA key.
func buildCSR(key *rsa.PrivateKey, template, cn, san string) ([]byte, error) {
	exts := []pkix.Extension{templateNameExtension(template)}
	if san != "" {
		sanExt, err := upnSANExtension(san)
		if err != nil {
			return nil, err
		}
		exts = append(exts, sanExt)
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		ExtraExtensions: exts,
	}, key)
}

// templateNameExtension builds the szOID_ENROLL_CERTTYPE_EXTENSION with the
// value as a DER-encoded UTF8String (tag 0x13) of the template name — the
// MS-WCCE 2.2.2.7.6 form. Verified live against a Server 2022 CA: raw
// UTF16LE (what some references suggest) makes the CA return disposition 1
// (CR_DISP_INCOMPLETE); the DER UTF8String issues. Go's asn1.Marshal of a
// string emits tag 0x13 for ASCII names, which is the UTF8String tag, so no
// hand-encoding is needed.
func templateNameExtension(template string) pkix.Extension {
	value, _ := asn1.Marshal(template)
	return pkix.Extension{Id: oidEnrollCertTypeExtension, Value: value}
}

// upnSANExtension builds a SAN extension carrying upn as an otherName. The
// nesting (RFC 4556 §3.2.2's GeneralName form, MS-WCCE's UPN type-id):
//
//	GeneralNames ::= SEQUENCE OF GeneralName
//	GeneralName  ::= [0] IMPLICIT OtherName      -- context tag 0, constructed
//	OtherName    ::= SEQUENCE {                  -- its CONTENT is what [0] wraps
//	  type-id  OBJECT IDENTIFIER,                -- szOID_NT_PRINCIPAL_NAME
//	  value    [0] EXPLICIT UTF8String }
//
// x509.CertificateRequest has no UPN field and Go's asn1 can't express
// "implicit SEQUENCE-content" from a struct, so the extension is assembled
// from RawValues: UTF8String → [0] EXPLICIT wrap → OID‖value as the [0]
// GeneralName content → SEQUENCE OF wrap. certipy's lib/certificate.py
// produces byte-identical structure (AnotherName with the UTF8String retagged
// {"explicit": 0}).
func upnSANExtension(upn string) (pkix.Extension, error) {
	utf8DER, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode UPN: %v", err)
	}
	explicitDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8DER,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("wrap UPN otherName value: %v", err)
	}
	oidDER, err := asn1.Marshal(oidNTPrincipalName)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode UPN otherName OID: %v", err)
	}
	generalNameDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: append(oidDER, explicitDER...),
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("wrap UPN otherName: %v", err)
	}
	sanDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: generalNameDER,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("wrap SAN: %v", err)
	}
	return pkix.Extension{Id: oidExtensionSubjectAltName, Value: sanDER}, nil
}

// mapCertError translates ICPR enrollment failures into plain language
// (themed-errors idiom; feature-local like mapProcError). gopacket's icpr
// surfaces a failed disposition as "certificate request failed: ... message=
// <CA text>", and the CA's disposition message carries the failing HRESULT,
// so the hex is matched on its rendered form. Codes per MS-ERREF
// (https://msdn.microsoft.com/en-us/library/cc704587.aspx):
//
//	0x80094011 CERTSRV_E_ENROLL_DENIED   — CA-wide enrollment ACL refused us
//	0x80094012 CERTSRV_E_TEMPLATE_DENIED — template unknown to the CA, or its
//	                                       ACL refuses enrollment (Windows
//	                                       returns this one code for both)
//
// Anything else — notably "pending approval" (CR_DISP_UNDER_SUBMISSION),
// whose message already carries the request ID an operator needs — passes
// through unchanged.
func mapCertError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "0x80094012"):
		return fmt.Errorf("no such certificate template, or the template does not allow enrollment by this user")
	case strings.Contains(msg, "0x80094011"):
		return fmt.Errorf("the CA does not allow enrollment by this user")
	}
	return err
}

// WriteCertPEM saves the issued cert and its key to one PEM file, cert block
// first. Parent directories are created operator-only (0700) and the file is
// written 0600 — it holds a private key. No loot helper is reused: smbclient
// takes the path as given.
func WriteCertPEM(path string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create output directory: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.Write(certPEM); err != nil {
		return fmt.Errorf("write certificate to %s: %v", path, err)
	}
	if _, err := f.Write(keyPEM); err != nil {
		return fmt.Errorf("write key to %s: %v", path, err)
	}
	return nil
}
