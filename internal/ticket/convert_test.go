package ticket

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/credentials"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/asnAppTag"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// TestConvertCCacheToKirbiFixture: the fixture converts to a kirbi that
// sniffs as kirbi and holds the same single TGT.
func TestConvertCCacheToKirbiFixture(t *testing.T) {
	out, dir, err := Convert(readFixture(t, fixtureCCache))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if dir != CCacheToKirbi {
		t.Errorf("direction = %v, want CCacheToKirbi", dir)
	}
	if SniffFormat(out) != FormatKirbi {
		t.Fatalf("output sniffs as %v, want kirbi (first byte 0x%02x)", SniffFormat(out), out[0])
	}
	d, err := Describe(out)
	if err != nil {
		t.Fatalf("Describe converted kirbi: %v", err)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(d.Entries))
	}
	checkGoldenEntry(t, d.Entries[0])
}

// TestConvertRoundTrip: ccache -> kirbi -> ccache preserves principals,
// session key, times, flags, and the ticket blob itself.
func TestConvertRoundTrip(t *testing.T) {
	kirbi, _, err := Convert(readFixture(t, fixtureCCache))
	if err != nil {
		t.Fatalf("ccache->kirbi: %v", err)
	}
	rt, dir, err := Convert(kirbi)
	if err != nil {
		t.Fatalf("kirbi->ccache: %v", err)
	}
	if dir != KirbiToCCache {
		t.Errorf("direction = %v, want KirbiToCCache", dir)
	}
	if SniffFormat(rt) != FormatCCache {
		t.Fatalf("round-trip sniffs as %v, want ccache", SniffFormat(rt))
	}

	tmp := filepath.Join(t.TempDir(), "rt.ccache")
	if err := os.WriteFile(tmp, rt, 0600); err != nil {
		t.Fatal(err)
	}
	orig, err := credentials.LoadCCache(filepath.Join("testdata", fixtureCCache))
	if err != nil {
		t.Fatalf("load original: %v", err)
	}
	back, err := credentials.LoadCCache(tmp)
	if err != nil {
		t.Fatalf("load round-trip: %v", err)
	}

	if got := back.DefaultPrincipal.Realm; got != wantRealm {
		t.Errorf("default realm = %q, want %q", got, wantRealm)
	}
	if names := back.DefaultPrincipal.PrincipalName.NameString; len(names) != 1 || names[0] != wantClient {
		t.Errorf("default principal = %v, want [%s]", names, wantClient)
	}
	if len(back.Credentials) != 1 {
		t.Fatalf("round-trip credentials = %d, want 1", len(back.Credentials))
	}
	o, b := orig.Credentials[0], back.Credentials[0]

	if got := strings.Join(b.Server.PrincipalName.NameString, "/"); got != wantServer {
		t.Errorf("server = %q, want %q", got, wantServer)
	}
	if b.Key.KeyType != o.Key.KeyType || !bytes.Equal(b.Key.KeyValue, o.Key.KeyValue) {
		t.Error("session key changed across round-trip")
	}
	// kirbi drops AuthTime; kirbiToCCache mirrors it from StartTime
	// (impacket's convention), so authtime==starttime after the trip.
	if b.AuthTime.Unix() != b.StartTime.Unix() {
		t.Errorf("round-trip authtime %v != starttime %v", b.AuthTime, b.StartTime)
	}
	if b.StartTime.Unix() != o.StartTime.Unix() || b.EndTime.Unix() != o.EndTime.Unix() ||
		b.RenewTill.Unix() != o.RenewTill.Unix() {
		t.Error("validity times changed across round-trip")
	}
	if bitStringFlags(b.TicketFlags) != wantFlags {
		t.Errorf("round-trip flags = 0x%08x, want 0x%08x", bitStringFlags(b.TicketFlags), wantFlags)
	}

	// The ticket blob: same service, realm, etype, and ciphertext.
	var ot, bt messages.Ticket
	if err := ot.Unmarshal(o.Ticket); err != nil {
		t.Fatalf("unmarshal original ticket: %v", err)
	}
	if err := bt.Unmarshal(b.Ticket); err != nil {
		t.Fatalf("unmarshal round-trip ticket: %v", err)
	}
	if bt.Realm != ot.Realm || !bt.SName.Equal(ot.SName) {
		t.Error("ticket service identity changed across round-trip")
	}
	if bt.EncPart.EType != ot.EncPart.EType || !bytes.Equal(bt.EncPart.Cipher, ot.EncPart.Cipher) {
		t.Error("ticket enc-part changed across round-trip")
	}
}

// TestConvertMultiEntry: a ccache holding two credentials converts to one
// KRB-CRED carrying two tickets, and back to a two-entry ccache.
func TestConvertMultiEntry(t *testing.T) {
	orig, err := credentials.LoadCCache(filepath.Join("testdata", fixtureCCache))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	cred := orig.Credentials[0]

	mk := func(sname string) kerberos.CacheEntry {
		return kerberos.CacheEntry{
			TicketBytes: cred.Ticket,
			SessionKey:  cred.Key,
			CName:       types.PrincipalName{NameType: 1, NameString: []string{wantClient}},
			CRealm:      wantRealm,
			SName:       types.PrincipalName{NameType: 2, NameString: strings.Split(sname, "/")},
			SRealm:      wantRealm,
			AuthTime:    cred.StartTime,
			EndTime:     cred.EndTime,
			RenewTill:   cred.RenewTill,
			Flags:       wantFlags,
		}
	}
	multi := filepath.Join(t.TempDir(), "multi.ccache")
	if err := kerberos.SaveMultiCCache(multi, []kerberos.CacheEntry{
		mk("krbtgt/LAB.LOCAL"), mk("cifs/dc01.lab.local"),
	}); err != nil {
		t.Fatalf("SaveMultiCCache: %v", err)
	}
	data, err := os.ReadFile(multi)
	if err != nil {
		t.Fatal(err)
	}

	kirbi, _, err := Convert(data)
	if err != nil {
		t.Fatalf("ccache->kirbi: %v", err)
	}
	kd, err := Describe(kirbi)
	if err != nil {
		t.Fatalf("Describe kirbi: %v", err)
	}
	if len(kd.Entries) != 2 {
		t.Fatalf("kirbi entries = %d, want 2", len(kd.Entries))
	}
	if kd.Entries[1].Server != "cifs/dc01.lab.local" {
		t.Errorf("second service = %q, want cifs/dc01.lab.local", kd.Entries[1].Server)
	}

	rt, _, err := Convert(kirbi)
	if err != nil {
		t.Fatalf("kirbi->ccache: %v", err)
	}
	rd, err := Describe(rt)
	if err != nil {
		t.Fatalf("Describe round-trip: %v", err)
	}
	if len(rd.Entries) != 2 {
		t.Fatalf("round-trip entries = %d, want 2", len(rd.Entries))
	}
	if rd.Entries[0].Server != wantServer || rd.Entries[1].Server != "cifs/dc01.lab.local" {
		t.Errorf("round-trip services = %q, %q", rd.Entries[0].Server, rd.Entries[1].Server)
	}
}

func TestConvertErrors(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "empty file"},
		{"unknown magic", []byte("PK\x03\x04"), "not a ccache or kirbi file"},
		{"truncated ccache", trunc(readFixture(t, fixtureCCache), 20), "invalid ccache"},
		{"truncated kirbi", trunc(readFixture(t, fixtureKirbi), 40), "invalid kirbi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Convert(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Convert error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestConvertCCacheNoTickets: a well-formed ccache with only a default
// principal converts to nothing.
func TestConvertCCacheNoTickets(t *testing.T) {
	// Version 4 header (12-byte DeltaTime) followed by only a default
	// principal — well-formed, but holding zero credentials.
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0x04})
	buf.Write([]byte{0x00, 0x0c, 0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00})
	writeCCachePrincipal(&buf, types.PrincipalName{NameType: 1, NameString: []string{"alice"}}, "LAB.LOCAL")

	_, _, err := Convert(buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "no tickets in ccache") {
		t.Errorf("Convert error = %v, want no tickets in ccache", err)
	}
}

// TestConvertEncryptedKirbi: a KRB-CRED with an encrypted enc-part (etype
// != 0) is refused, matching impacket's ticketConverter.
func TestConvertEncryptedKirbi(t *testing.T) {
	blob, err := asn1.Marshal(marshalKRBCred{
		PVNO:    5,
		MsgType: 22,
		EncPart: marshalEncryptedData{EType: 23, Cipher: []byte{0xde, 0xad}},
	})
	if err != nil {
		t.Fatal(err)
	}
	blob = addASNAppTag(blob, asnAppTag.KRBCred)

	_, _, err = Convert(blob)
	if err == nil || !strings.Contains(err.Error(), "encrypted KRB-CRED") {
		t.Errorf("Convert error = %v, want encrypted KRB-CRED", err)
	}
}

// TestConvertFile exercises the file-level wrapper: output lands 0600 and
// the direction is returned.
func TestConvertFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "t.kirbi") // extension lies; content rules
	if err := os.WriteFile(in, readFixture(t, fixtureCCache), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "t.ccache")
	d, err := ConvertFile(in, out)
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	if d != CCacheToKirbi {
		t.Errorf("direction = %v, want CCacheToKirbi", d)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if SniffFormat(blob) != FormatKirbi {
		t.Errorf("output sniffs as %v, want kirbi", SniffFormat(blob))
	}

	if _, err := ConvertFile(filepath.Join(dir, "missing.ccache"), out); err == nil ||
		!strings.Contains(err.Error(), "read") {
		t.Errorf("missing input error = %v, want read error", err)
	}
}
