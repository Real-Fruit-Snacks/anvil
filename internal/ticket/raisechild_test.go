package ticket

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/credentials"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/adtype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// Synthetic parent (forest root) and child domains + SIDs. Values are
// irrelevant offline; only their structural relationship matters.
const (
	childDomain = "child.corp.local"
	childSID    = "S-1-5-21-1004336348-1177238915-682003330"
	parentSID   = "S-1-5-21-2781415573-3701874478-2306985198"
)

func baseChildOptions() ChildOptions {
	return ChildOptions{
		User:            "Administrator",
		ChildDomain:     childDomain,
		ChildDomainSID:  childSID,
		ParentDomainSID: parentSID,
		KrbtgtHash:      testHash,
	}
}

// TestForgeChildValidationErrors: bad input fails before anything is written.
func TestForgeChildValidationErrors(t *testing.T) {
	t.Chdir(t.TempDir())

	cases := []struct {
		name    string
		mutate  func(*ChildOptions)
		wantErr string
	}{
		{"missing user", func(o *ChildOptions) { o.User = "" }, "-user is required"},
		{"missing child domain", func(o *ChildOptions) { o.ChildDomain = "" }, "-child-domain is required"},
		{"missing child sid", func(o *ChildOptions) { o.ChildDomainSID = "" }, "-child-sid is required"},
		{"child sid with rid", func(o *ChildOptions) { o.ChildDomainSID = childSID + "-500" }, "want S-1-5-21"},
		{"child sid garbage", func(o *ChildOptions) { o.ChildDomainSID = "nope" }, "invalid domain SID"},
		{"missing parent sid", func(o *ChildOptions) { o.ParentDomainSID = "" }, "-parent-sid is required"},
		{"parent sid with rid", func(o *ChildOptions) { o.ParentDomainSID = parentSID + "-519" }, "want S-1-5-21"},
		{"parent sid not a domain sid", func(o *ChildOptions) { o.ParentDomainSID = "S-1-5-18" }, "want S-1-5-21"},
		{"child equals parent", func(o *ChildOptions) { o.ParentDomainSID = childSID }, "must differ"},
		{"missing hash", func(o *ChildOptions) { o.KrbtgtHash = "" }, "-krbtgt is required"},
		{"bad hash", func(o *ChildOptions) { o.KrbtgtHash = "abcd" }, "want 32 hex chars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := baseChildOptions()
			tc.mutate(&opts)
			_, err := ForgeChild(opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ForgeChild error = %v, want substring %q", err, tc.wantErr)
			}
			entries, _ := os.ReadDir(".")
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".ccache") {
					t.Errorf("ccache %s written despite validation failure", e.Name())
				}
			}
		})
	}
}

// TestForgeChildExtraSIDInPAC is the core raiseChild assertion: forge with
// synthetic parent/child SIDs, then decrypt the forged ticket bytes with the
// child krbtgt key and re-parse the PAC. The forest-root Enterprise Admins
// SID (<parentSID>-519) must land in the PAC's ExtraSIDs (SIDHistory), the
// logon domain must be the CHILD, and the LOGON_EXTRA_SIDS user flag must be
// set. The decrypt/re-parse path mirrors gopacket's tools/describeTicket.
func TestForgeChildExtraSIDInPAC(t *testing.T) {
	t.Chdir(t.TempDir())

	opts := baseChildOptions()
	path, err := ForgeChild(opts)
	if err != nil {
		t.Fatalf("ForgeChild: %v", err)
	}
	if path != "Administrator.ccache" {
		t.Errorf("path = %q, want Administrator.ccache", path)
	}

	cc, err := credentials.LoadCCache(path)
	if err != nil {
		t.Fatalf("LoadCCache round-trip: %v", err)
	}
	if got := cc.DefaultPrincipal.Realm; got != "CHILD.CORP.LOCAL" {
		t.Errorf("default principal realm = %q, want CHILD.CORP.LOCAL", got)
	}
	if len(cc.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cc.Credentials))
	}
	cred := cc.Credentials[0]
	if sname := strings.Join(cred.Server.PrincipalName.NameString, "/"); sname != "krbtgt/CHILD.CORP.LOCAL" {
		t.Errorf("server principal = %q, want krbtgt/CHILD.CORP.LOCAL", sname)
	}

	pac := pacFromTicket(t, cred.Ticket, testHash)

	wantExtra := parentSID + "-519"
	if len(pac.ExtraSIDs) != 1 || pac.ExtraSIDs[0].String() != wantExtra {
		t.Errorf("PAC ExtraSIDs = %v, want exactly [%s]", sidStrings(pac.ExtraSIDs), wantExtra)
	}
	if pac.UserFlags&kerberos.LogonExtraSIDs == 0 {
		t.Errorf("PAC UserFlags = %#x, want LOGON_EXTRA_SIDS (%#x) set", pac.UserFlags, kerberos.LogonExtraSIDs)
	}
	if got := pac.DomainSID.String(); got != childSID {
		t.Errorf("PAC logon domain SID = %q, want child %q", got, childSID)
	}
	if pac.Username != "Administrator" {
		t.Errorf("PAC username = %q, want Administrator", pac.Username)
	}
	if pac.UserID != 500 {
		t.Errorf("PAC user RID = %d, want default 500", pac.UserID)
	}
}

// TestForgeChildCustomUserID: a non-default RID is honored in the PAC.
func TestForgeChildCustomUserID(t *testing.T) {
	t.Chdir(t.TempDir())

	opts := baseChildOptions()
	opts.User = "da-child"
	opts.UserID = 1105
	path, err := ForgeChild(opts)
	if err != nil {
		t.Fatalf("ForgeChild: %v", err)
	}

	cc, err := credentials.LoadCCache(path)
	if err != nil {
		t.Fatalf("LoadCCache round-trip: %v", err)
	}
	pac := pacFromTicket(t, cc.Credentials[0].Ticket, testHash)
	if pac.UserID != 1105 {
		t.Errorf("PAC user RID = %d, want 1105", pac.UserID)
	}
	if pac.Username != "da-child" {
		t.Errorf("PAC username = %q, want da-child", pac.Username)
	}
}

// TestForgeChildBadOutDir: a bad -out path errors and leaves no stray ccache.
func TestForgeChildBadOutDir(t *testing.T) {
	t.Chdir(t.TempDir())

	opts := baseChildOptions()
	opts.Out = filepath.Join("no-such-dir", "x.ccache")
	if _, err := ForgeChild(opts); err == nil {
		t.Fatal("ForgeChild: want error for missing -out directory")
	}
	if _, statErr := os.Stat("Administrator.ccache"); !os.IsNotExist(statErr) {
		t.Errorf("stray intermediate ccache left in cwd after failed move")
	}
}

// pacFromTicket decrypts a forged ticket's enc-part with the krbtgt key
// (usage 2, TGS-REP ticket) and parses the PAC out of the authorization
// data — the same walk gopacket's tools/describeTicket performs.
func pacFromTicket(t *testing.T, ticketBytes []byte, keyHex string) *kerberos.PAC {
	t.Helper()

	var tkt messages.Ticket
	if err := tkt.Unmarshal(ticketBytes); err != nil {
		t.Fatalf("unmarshal ticket: %v", err)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	etype, err := crypto.GetEtype(tkt.EncPart.EType)
	if err != nil {
		t.Fatalf("get etype %d: %v", tkt.EncPart.EType, err)
	}
	plain, err := etype.DecryptMessage(key, tkt.EncPart.Cipher, 2)
	if err != nil {
		t.Fatalf("decrypt enc-part: %v", err)
	}

	var enc messages.EncTicketPart
	if err := enc.Unmarshal(plain); err != nil {
		t.Fatalf("unmarshal enc-part: %v", err)
	}
	for _, ad := range enc.AuthorizationData {
		if ad.ADType != adtype.ADIfRelevant {
			continue
		}
		var inner types.AuthorizationData
		if err := inner.Unmarshal(ad.ADData); err != nil {
			t.Fatalf("unmarshal AD-IF-RELEVANT: %v", err)
		}
		for _, e := range inner {
			if e.ADType != adtype.ADWin2KPAC {
				continue
			}
			pac, err := kerberos.ParsePAC(e.ADData)
			if err != nil {
				t.Fatalf("parse PAC: %v", err)
			}
			return pac
		}
	}
	t.Fatal("no AD-WIN2K-PAC in ticket authorization data")
	return nil
}

func sidStrings(sids []*kerberos.SID) []string {
	out := make([]string, len(sids))
	for i, s := range sids {
		out[i] = s.String()
	}
	return out
}
