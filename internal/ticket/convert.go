package ticket

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/asnAppTag"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// Direction reports which way a Convert ran.
type Direction int

const (
	CCacheToKirbi Direction = iota
	KirbiToCCache
)

// String returns the direction as "ccache -> kirbi" / "kirbi -> ccache".
func (d Direction) String() string {
	if d == CCacheToKirbi {
		return "ccache -> kirbi"
	}
	return "kirbi -> ccache"
}

// Convert converts a ticket blob between ccache and kirbi, direction
// auto-detected from content via SniffFormat, and returns the converted
// blob. Every credential in a ccache becomes one KRB-CRED ticket; every
// kirbi ticket becomes one ccache entry. The output ccache is format
// version 0x0504 with the DeltaTime header MIT tools write, matching what
// `anvil ticket` and impacket produce.
func Convert(data []byte) ([]byte, Direction, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty file")
	}
	switch SniffFormat(data) {
	case FormatCCache:
		out, err := ccacheToKirbi(data)
		return out, CCacheToKirbi, err
	case FormatKirbi:
		out, err := kirbiToCCache(data)
		return out, KirbiToCCache, err
	}
	return nil, 0, fmt.Errorf("not a ccache or kirbi file (first byte 0x%02x)", data[0])
}

// ConvertFile converts the ticket file at in and writes the result to out
// (0600 — it carries session keys). Direction follows the input's content,
// not its extension.
func ConvertFile(in, out string) (Direction, error) {
	data, err := os.ReadFile(in)
	if err != nil {
		return 0, fmt.Errorf("read %s: %v", in, err)
	}
	blob, dir, err := Convert(data)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(out, blob, 0600); err != nil {
		return 0, fmt.Errorf("write %s: %v", out, err)
	}
	return dir, nil
}

// Marshal structs for KRB-CRED. gokrb5 can unmarshal KRB-CRED but its
// marshal-side struct is unexported, so these mirror it (and gopacket's
// tools/ticketConverter).

type marshalEncryptedData struct {
	EType  int    `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type marshalKrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"generalstring,optional,explicit,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
}

type marshalEncKrbCredPart struct {
	TicketInfo []marshalKrbCredInfo `asn1:"explicit,tag:0"`
}

type marshalKRBCred struct {
	PVNO    int                  `asn1:"explicit,tag:0"`
	MsgType int                  `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue        `asn1:"explicit,tag:2"`
	EncPart marshalEncryptedData `asn1:"explicit,tag:3"`
}

// ccacheToKirbi packs every non-config ccache credential into one KRB-CRED.
// The enc-part is etype 0 (unencrypted) — the tooling convention impacket
// and Rubeus both read; a KDC-produced encrypted KRB-CRED is a different
// beast. AuthTime is omitted (tag 4), matching impacket's ticketConverter:
// consumers reconstruct it from StartTime.
func ccacheToKirbi(data []byte) ([]byte, error) {
	cc, err := parseCCache(data)
	if err != nil {
		return nil, err
	}
	creds := cc.GetEntries()
	if len(creds) == 0 {
		return nil, fmt.Errorf("no tickets in ccache")
	}

	var ticketDER []byte // concatenated DER tickets, forms the SEQUENCE OF
	infos := make([]marshalKrbCredInfo, 0, len(creds))
	for _, cred := range creds {
		// Unmarshal+re-marshal normalizes the ticket blob to clean DER and
		// proves it parses before it goes into the KRB-CRED.
		var t messages.Ticket
		if err := t.Unmarshal(cred.Ticket); err != nil {
			return nil, fmt.Errorf("ccache holds an unparsable ticket: %v", err)
		}
		tb, err := t.Marshal()
		if err != nil {
			return nil, fmt.Errorf("re-marshal ticket: %v", err)
		}
		ticketDER = append(ticketDER, tb...)
		infos = append(infos, marshalKrbCredInfo{
			Key: types.EncryptionKey{
				KeyType:  cred.Key.KeyType,
				KeyValue: cred.Key.KeyValue,
			},
			PRealm:    cred.Client.Realm,
			PName:     cred.Client.PrincipalName,
			Flags:     cred.TicketFlags,
			StartTime: cred.StartTime.UTC(),
			EndTime:   cred.EndTime.UTC(),
			RenewTill: cred.RenewTill.UTC(),
			SRealm:    cred.Server.Realm,
			SName:     cred.Server.PrincipalName,
		})
	}

	// tickets [2] is an explicit context tag around a SEQUENCE OF Ticket.
	// RawValue with FullBytes semantics bypasses the struct tag, so wrap by
	// hand: inner universal SEQUENCE, outer context [2] constructed.
	innerSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ticketDER,
	}
	innerBytes, err := asn1.Marshal(innerSeq)
	if err != nil {
		return nil, fmt.Errorf("marshal tickets sequence: %v", err)
	}
	ticketsRaw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      innerBytes,
	}

	encPartBytes, err := asn1.Marshal(marshalEncKrbCredPart{TicketInfo: infos})
	if err != nil {
		return nil, fmt.Errorf("marshal EncKrbCredPart: %v", err)
	}
	encPartBytes = addASNAppTag(encPartBytes, asnAppTag.EncKrbCredPart)

	krbCredBytes, err := asn1.Marshal(marshalKRBCred{
		PVNO:    5,
		MsgType: 22, // KRB-CRED
		Tickets: ticketsRaw,
		EncPart: marshalEncryptedData{EType: 0, Cipher: encPartBytes},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal KRB-CRED: %v", err)
	}
	return addASNAppTag(krbCredBytes, asnAppTag.KRBCred), nil
}

// kirbiToCCache unpacks an unencrypted KRB-CRED into a v4 ccache. TicketInfo
// and Tickets pair by index; a kirbi missing either side is an error. Auth
// time is not carried in the kirbi form impacket writes, so ccache authtime
// takes starttime (impacket's ticketConverter does the same).
func kirbiToCCache(data []byte) ([]byte, error) {
	krbCred, encPart, err := parseKirbi(data)
	if err != nil {
		return nil, err
	}
	if len(encPart.TicketInfo) == 0 || len(krbCred.Tickets) == 0 {
		return nil, fmt.Errorf("kirbi carries no tickets")
	}

	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0x04}) // ccache version 0x0504
	// DeltaTime header, same 12-byte shape MIT and impacket write.
	binary.Write(&buf, binary.BigEndian, uint16(12))         // header length
	binary.Write(&buf, binary.BigEndian, uint16(1))          // tag: DeltaTime
	binary.Write(&buf, binary.BigEndian, uint16(8))          // tag length
	binary.Write(&buf, binary.BigEndian, uint32(0xFFFFFFFF)) // time offset seconds
	binary.Write(&buf, binary.BigEndian, uint32(0))          // time offset usec

	first := encPart.TicketInfo[0]
	writeCCachePrincipal(&buf, first.PName, first.PRealm)

	for i, info := range encPart.TicketInfo {
		if i >= len(krbCred.Tickets) {
			break
		}
		ticketBytes, err := krbCred.Tickets[i].Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal ticket %d: %v", i, err)
		}
		writeCCacheCredential(&buf, info, ticketBytes)
	}
	return buf.Bytes(), nil
}

// writeCCachePrincipal writes one principal in ccache v4 layout: name type,
// component count, realm, then each component (all big-endian length-prefixed).
func writeCCachePrincipal(buf *bytes.Buffer, name types.PrincipalName, realm string) {
	binary.Write(buf, binary.BigEndian, uint32(name.NameType))
	binary.Write(buf, binary.BigEndian, uint32(len(name.NameString)))
	binary.Write(buf, binary.BigEndian, uint32(len(realm)))
	buf.WriteString(realm)
	for _, comp := range name.NameString {
		binary.Write(buf, binary.BigEndian, uint32(len(comp)))
		buf.WriteString(comp)
	}
}

// writeCCacheCredential appends one ccache credential entry for a
// KRB-CRED-INFO plus its DER ticket.
func writeCCacheCredential(buf *bytes.Buffer, info messages.KrbCredInfo, ticketBytes []byte) {
	writeCCachePrincipal(buf, info.PName, info.PRealm)
	writeCCachePrincipal(buf, info.SName, info.SRealm)

	// Session key: keytype, then a second etype slot ccache v4 leaves unused.
	binary.Write(buf, binary.BigEndian, uint16(info.Key.KeyType))
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint16(len(info.Key.KeyValue)))
	buf.Write(info.Key.KeyValue)

	// authtime mirrors starttime: the kirbi form doesn't carry it.
	binary.Write(buf, binary.BigEndian, uint32(info.StartTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(info.StartTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(info.EndTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(info.RenewTill.Unix()))

	buf.WriteByte(0) // is_skey: no

	// bitStringFlags applies the pyasn1 BitLength-31 correction for
	// impacket-produced kirbis.
	binary.Write(buf, binary.BigEndian, bitStringFlags(info.Flags))

	binary.Write(buf, binary.BigEndian, uint32(0)) // addresses: none
	binary.Write(buf, binary.BigEndian, uint32(0)) // authdata: none

	binary.Write(buf, binary.BigEndian, uint32(len(ticketBytes)))
	buf.Write(ticketBytes)

	binary.Write(buf, binary.BigEndian, uint32(0)) // second ticket: none
}

// addASNAppTag wraps DER bytes in an ASN.1 APPLICATION tag.
func addASNAppTag(b []byte, tag int) []byte {
	r := asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        tag,
		Bytes:      b,
	}
	ab, _ := asn1.Marshal(r)
	return ab
}
