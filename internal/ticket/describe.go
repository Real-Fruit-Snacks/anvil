package ticket

import (
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/credentials"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/etypeID"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/flags"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
)

// Format identifies a ticket file's on-disk encoding.
type Format int

const (
	FormatUnknown Format = iota
	FormatCCache         // MIT credential cache, first byte 0x05
	FormatKirbi          // DER KRB-CRED message, first byte 0x76
)

// String returns the lowercase format name for display.
func (f Format) String() string {
	switch f {
	case FormatCCache:
		return "ccache"
	case FormatKirbi:
		return "kirbi"
	}
	return "unknown"
}

// SniffFormat classifies a ticket blob by content, never by file extension.
// A ccache opens with 0x05 (its format byte); a kirbi is a DER KRB-CRED,
// which opens with the ASN.1 APPLICATION 22 constructed tag 0x76.
func SniffFormat(data []byte) Format {
	if len(data) == 0 {
		return FormatUnknown
	}
	switch data[0] {
	case 0x05:
		return FormatCCache
	case 0x76:
		return FormatKirbi
	}
	return FormatUnknown
}

// Entry is one ticket's descriptive fields, normalized across ccache and
// kirbi encodings. Principal names are pre-joined with "/" (e.g.
// "krbtgt/LAB.LOCAL"); times are UTC. Nothing is decrypted: TicketEType
// comes from the ticket's unencrypted outer layer, the session key itself
// is never exposed here.
type Entry struct {
	Client       string    // client principal, e.g. "Administrator"
	ClientRealm  string    // client realm, e.g. "LAB.LOCAL"
	Server       string    // service principal, e.g. "krbtgt/LAB.LOCAL"
	ServerRealm  string    // service realm
	SessionEType int32     // etype of the session key
	TicketEType  int32     // etype the ticket itself is encrypted with; valid when TicketOK
	TicketOK     bool      // whether the embedded ticket blob parsed
	AuthTime     time.Time // initial authentication time (zero when the file omits it)
	StartTime    time.Time // validity start
	EndTime      time.Time // expiry
	RenewTill    time.Time // renewal deadline (zero when absent)
	Flags        uint32    // ticket flags, big-endian ccache layout
	FlagNames    []string  // set flag names, impacket-style (e.g. "forwardable")
}

// Description is the parsed content of a ccache or kirbi file.
type Description struct {
	Format  Format  // detected encoding
	Client  string  // default client principal as name@REALM ("" when unknown)
	Entries []Entry // one per ticket, cache config entries excluded
}

// Describe parses a ccache or kirbi blob — the format is auto-detected by
// SniffFormat — and returns a normalized view of every ticket it carries.
func Describe(data []byte) (*Description, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	switch SniffFormat(data) {
	case FormatCCache:
		return describeCCache(data)
	case FormatKirbi:
		return describeKirbi(data)
	}
	return nil, fmt.Errorf("not a ccache or kirbi file (first byte 0x%02x)", data[0])
}

// describeCCache normalizes every non-config credential in a ccache.
func describeCCache(data []byte) (*Description, error) {
	cc, err := parseCCache(data)
	if err != nil {
		return nil, err
	}
	d := &Description{
		Format: FormatCCache,
		Client: displayPrincipal(
			strings.Join(cc.DefaultPrincipal.PrincipalName.NameString, "/"),
			cc.DefaultPrincipal.Realm),
	}
	for _, cred := range cc.GetEntries() {
		e := Entry{
			Client:       strings.Join(cred.Client.PrincipalName.NameString, "/"),
			ClientRealm:  cred.Client.Realm,
			Server:       strings.Join(cred.Server.PrincipalName.NameString, "/"),
			ServerRealm:  cred.Server.Realm,
			SessionEType: cred.Key.KeyType,
			AuthTime:     cred.AuthTime,
			StartTime:    cred.StartTime,
			EndTime:      cred.EndTime,
			RenewTill:    cred.RenewTill,
			Flags:        bitStringFlags(cred.TicketFlags),
		}
		e.FlagNames = flagNames(e.Flags)
		// The ticket blob's outer layer is plaintext: the enc-part etype is
		// always readable without keys. A corrupt blob only costs this field.
		var t messages.Ticket
		if err := t.Unmarshal(cred.Ticket); err == nil {
			e.TicketOK = true
			e.TicketEType = t.EncPart.EType
		}
		d.Entries = append(d.Entries, e)
	}
	return d, nil
}

// describeKirbi normalizes every ticket in an unencrypted KRB-CRED.
func describeKirbi(data []byte) (*Description, error) {
	krbCred, encPart, err := parseKirbi(data)
	if err != nil {
		return nil, err
	}
	d := &Description{Format: FormatKirbi}
	for i, info := range encPart.TicketInfo {
		if i >= len(krbCred.Tickets) {
			break // TicketInfo without a matching ticket; nothing more to pair
		}
		tkt := krbCred.Tickets[i]
		e := Entry{
			Client:       strings.Join(info.PName.NameString, "/"),
			ClientRealm:  info.PRealm,
			Server:       strings.Join(info.SName.NameString, "/"),
			ServerRealm:  info.SRealm,
			SessionEType: info.Key.KeyType,
			TicketEType:  tkt.EncPart.EType,
			TicketOK:     true,
			AuthTime:     info.AuthTime,
			StartTime:    info.StartTime,
			EndTime:      info.EndTime,
			RenewTill:    info.RenewTill,
			Flags:        bitStringFlags(info.Flags),
		}
		// PName/SName are optional in KRB-CRED-INFO; fall back to the
		// ticket's own (always present) sname and realm.
		if e.Server == "" {
			e.Server = strings.Join(tkt.SName.NameString, "/")
		}
		if e.ServerRealm == "" {
			e.ServerRealm = tkt.Realm
		}
		e.FlagNames = flagNames(e.Flags)
		d.Entries = append(d.Entries, e)
	}
	if len(d.Entries) > 0 {
		d.Client = displayPrincipal(d.Entries[0].Client, d.Entries[0].ClientRealm)
	}
	return d, nil
}

// parseCCache decodes ccache bytes. The gokrb5 parser slices without bounds
// checks, so a truncated file panics; convert that into an error.
func parseCCache(data []byte) (cc *credentials.CCache, err error) {
	defer func() {
		if r := recover(); r != nil {
			cc, err = nil, fmt.Errorf("invalid ccache file: %v", r)
		}
	}()
	cc = new(credentials.CCache)
	err = cc.Unmarshal(data)
	return
}

// parseKirbi decodes a KRB-CRED blob and its (unencrypted) EncKrbCredPart.
// Encrypted KRB-CREDs — produced by a KDC, not by ticket tooling — are
// rejected: impacket's ticketConverter draws the same line.
func parseKirbi(data []byte) (krbCred *messages.KRBCred, encPart *messages.EncKrbCredPart, err error) {
	defer func() {
		if r := recover(); r != nil {
			krbCred, encPart, err = nil, nil, fmt.Errorf("invalid kirbi file: %v", r)
		}
	}()
	krbCred = new(messages.KRBCred)
	if err := krbCred.Unmarshal(data); err != nil {
		return nil, nil, fmt.Errorf("invalid kirbi file: %v", err)
	}
	if krbCred.EncPart.EType != 0 {
		return nil, nil, fmt.Errorf("encrypted KRB-CRED (etype %d) not supported; only unencrypted kirbi files", krbCred.EncPart.EType)
	}
	encPart = new(messages.EncKrbCredPart)
	if err := encPart.Unmarshal(krbCred.EncPart.Cipher); err != nil {
		return nil, nil, fmt.Errorf("invalid kirbi file: bad EncKrbCredPart: %v", err)
	}
	return krbCred, encPart, nil
}

// displayPrincipal renders name@REALM, tolerating either side being empty.
func displayPrincipal(name, realm string) string {
	switch {
	case name == "":
		return realm
	case realm == "":
		return name
	}
	return name + "@" + realm
}

// ticketFlagNames maps KerberosFlags bit positions (RFC 4120 §5.3, bit 0 is
// the MSB) to impacket's lowercase names — the same spelling describeTicket
// and secretsdump users already read.
var ticketFlagNames = []struct {
	bit  int
	name string
}{
	{flags.Reserved, "reserved"},
	{flags.Forwardable, "forwardable"},
	{flags.Forwarded, "forwarded"},
	{flags.Proxiable, "proxiable"},
	{flags.Proxy, "proxy"},
	{flags.MayPostDate, "may_postdate"},
	{flags.PostDated, "postdated"},
	{flags.Invalid, "invalid"},
	{flags.Renewable, "renewable"},
	{flags.Initial, "initial"},
	{flags.PreAuthent, "pre_authent"},
	{flags.HWAuthent, "hw_authent"},
	{flags.OKAsDelegate, "ok_as_delegate"},
	{flags.EncPARep, "enc_pa_rep"},
}

// bitStringFlags flattens a KerberosFlags BitString to the big-endian uint32
// layout ccache uses on disk. Both ccache entries (raw 4 file bytes in
// BitString form) and kirbi KRB-CRED-INFO flags (a true ASN.1 BIT STRING)
// funnel through here. A BitLength of 31 marks pyasn1's named-bit encoding,
// which impacket-produced kirbis carry: the value sits one bit high and
// shifts back down (gopacket's ticketConverter does the same correction).
func bitStringFlags(bf asn1.BitString) uint32 {
	var v uint32
	for i := 0; i < len(bf.Bytes) && i < 4; i++ {
		v |= uint32(bf.Bytes[i]) << uint(24-8*i)
	}
	if bf.BitLength == 31 {
		v >>= 1
	}
	return v
}

// flagNames decodes the set flags in a ccache-layout uint32: KerberosFlags
// bit i is uint32 bit (31-i).
func flagNames(v uint32) []string {
	var names []string
	for _, f := range ticketFlagNames {
		if v&(1<<uint(31-f.bit)) != 0 {
			names = append(names, f.name)
		}
	}
	return names
}

// ETypeName maps a Kerberos encryption type to its common name, spelled the
// way impacket prints it; unknown types render as etype_<n>.
func ETypeName(etype int32) string {
	switch etype {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return "aes128_cts_hmac_sha1_96"
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return "aes256_cts_hmac_sha1_96"
	case etypeID.RC4_HMAC:
		return "rc4_hmac"
	case etypeID.RC4_HMAC_EXP:
		return "rc4_hmac_exp"
	case etypeID.DES_CBC_MD5:
		return "des_cbc_md5"
	case etypeID.DES3_CBC_SHA1_KD:
		return "des3_cbc_sha1_kd"
	}
	return fmt.Sprintf("etype_%d", etype)
}
