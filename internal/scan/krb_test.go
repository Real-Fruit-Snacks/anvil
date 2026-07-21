package scan

import (
	"bytes"
	"encoding/binary"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/errorcode"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/msgtype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

func mustMarshalKRBError(t *testing.T, k messages.KRBError) []byte {
	t.Helper()
	b, err := k.Marshal()
	if err != nil {
		t.Fatalf("marshal KRBError: %v", err)
	}
	return b
}

func TestParseKDCReply(t *testing.T) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "LAB.LOCAL"},
	}
	withCRealm := func(crealm string, code int32) []byte {
		k := messages.NewKRBError(sname, "", code, "test")
		k.CRealm = crealm
		return mustMarshalKRBError(t, k)
	}

	cases := []struct {
		name      string
		b         []byte
		wantRealm string
		wantReply string
	}{
		{
			// The expected live-KDC verdict: client name is not in the
			// database, srealm carries the KDC's own realm.
			"principal unknown carries realm",
			mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "Client not found")),
			"LAB.LOCAL", "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		},
		{
			// A wrong request realm still yields an error that names the
			// serving realm — the probe treats any KRB-ERROR as success.
			"wrong realm still names KDC realm",
			mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", errorcode.KDC_ERR_WRONG_REALM, "")),
			"LAB.LOCAL", "KDC_ERR_WRONG_REALM",
		},
		{
			"preauth required",
			mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", errorcode.KDC_ERR_PREAUTH_REQUIRED, "")),
			"LAB.LOCAL", "KDC_ERR_PREAUTH_REQUIRED",
		},
		{
			// Codes outside gokrb5's table keep Lookup's whole rendering.
			"unknown error code kept whole",
			mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", 999, "")),
			"LAB.LOCAL", "Unknown ErrorCode 999",
		},
		{
			// srealm empty (e.g. a KDC answering ANVIL.INVALID by echoing
			// only the client realm): CRealm is strictly a fallback.
			"empty srealm falls back to crealm",
			withCRealm("CHILD.LAB.LOCAL", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN),
			"CHILD.LAB.LOCAL", "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		},
		{
			"both realms empty yields empty realm",
			withCRealm("", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN),
			"", "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		},
	}
	for _, c := range cases {
		realm, reply, err := parseKDCReply(c.b)
		if err != nil {
			t.Errorf("%s: parseKDCReply err = %v, want nil", c.name, err)
			continue
		}
		if realm != c.wantRealm || reply != c.wantReply {
			t.Errorf("%s: parseKDCReply = (%q, %q), want (%q, %q)", c.name, realm, reply, c.wantRealm, c.wantReply)
		}
	}
}

func TestParseKDCReplyErrors(t *testing.T) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "LAB.LOCAL"},
	}
	valid := mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, ""))

	// A KRB-ERROR with its application tag byte flipped to AS-REP's
	// (0x60|11 = 0x6B): the KDC issued a ticket for a principal that was
	// never supposed to exist — reported plainly, not as a parse error.
	asRep := append([]byte(nil), valid...)
	asRep[0] = 0x60 | 11

	cases := []struct {
		name        string
		b           []byte
		wantErrPart string
	}{
		{"as-rep for nonexistent principal", asRep, "unexpected AS-REP"},
		{"random garbage", []byte("not kerberos at all"), "not a KRB-ERROR"},
		{"empty reply", nil, "not a KRB-ERROR"},
		{"truncated krb-error", valid[:len(valid)/2], "not a KRB-ERROR"},
	}
	for _, c := range cases {
		_, _, err := parseKDCReply(c.b)
		if err == nil {
			t.Errorf("%s: parseKDCReply err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: parseKDCReply err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

func TestErrorName(t *testing.T) {
	cases := []struct {
		name string
		code int32
		want string
	}{
		{"principal unknown", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "KDC_ERR_C_PRINCIPAL_UNKNOWN"},
		{"etype nosupp", errorcode.KDC_ERR_ETYPE_NOSUPP, "KDC_ERR_ETYPE_NOSUPP"},
		{"wrong realm", errorcode.KDC_ERR_WRONG_REALM, "KDC_ERR_WRONG_REALM"},
		{"unknown code", 4242, "Unknown ErrorCode 4242"},
	}
	for _, c := range cases {
		if got := errorName(c.code); got != c.want {
			t.Errorf("%s: errorName(%d) = %q, want %q", c.name, c.code, got, c.want)
		}
	}
}

func TestKRBFrameRoundTrip(t *testing.T) {
	payload := []byte("kerberos message bytes")
	var buf bytes.Buffer
	if err := writeKRBFrame(&buf, payload); err != nil {
		t.Fatalf("writeKRBFrame: %v", err)
	}
	if got := binary.BigEndian.Uint32(buf.Bytes()[:4]); got != uint32(len(payload)) {
		t.Fatalf("frame prefix = %d, want %d", got, len(payload))
	}
	got, err := readKRBFrame(&buf)
	if err != nil {
		t.Fatalf("readKRBFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip = %q, want %q", got, payload)
	}
}

func TestReadKRBFrameErrors(t *testing.T) {
	prefix := func(n uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		return b[:]
	}
	cases := []struct {
		name        string
		b           []byte
		wantErrPart string
	}{
		{"empty stream", nil, "EOF"},
		{"short prefix", []byte{0, 0}, "EOF"},
		{"zero length", prefix(0), "implausible"},
		// Over the 1 MiB cap: must be rejected before allocation, so a
		// hostile peer cannot make us buffer on its say-so.
		{"length over cap", prefix(0xFFFFFFFF), "implausible"},
		{"truncated body", append(prefix(8), []byte("abc")...), "EOF"},
	}
	for _, c := range cases {
		_, err := readKRBFrame(bytes.NewReader(c.b))
		if err == nil {
			t.Errorf("%s: readKRBFrame err = nil, want error containing %q", c.name, c.wantErrPart)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: readKRBFrame err = %q, want substring %q", c.name, err, c.wantErrPart)
		}
	}
}

var principalPattern = regexp.MustCompile(`^anvil-[0-9a-f]{8}$`)

func TestBuildASReq(t *testing.T) {
	b, err := buildASReq("LAB.LOCAL")
	if err != nil {
		t.Fatalf("buildASReq: %v", err)
	}
	var req messages.ASReq
	if err := req.Unmarshal(b); err != nil {
		t.Fatalf("unmarshaling built AS-REQ: %v", err)
	}
	if req.MsgType != msgtype.KRB_AS_REQ {
		t.Errorf("msg type = %d, want KRB_AS_REQ (%d)", req.MsgType, msgtype.KRB_AS_REQ)
	}
	if req.ReqBody.Realm != "LAB.LOCAL" {
		t.Errorf("realm = %q, want LAB.LOCAL", req.ReqBody.Realm)
	}
	if got := req.ReqBody.SName.NameString; len(got) != 2 || got[0] != "krbtgt" || got[1] != "LAB.LOCAL" {
		t.Errorf("sname = %v, want [krbtgt LAB.LOCAL]", got)
	}
	if req.ReqBody.SName.NameType != nametype.KRB_NT_SRV_INST {
		t.Errorf("sname type = %d, want KRB_NT_SRV_INST", req.ReqBody.SName.NameType)
	}
	if req.ReqBody.CName.NameType != nametype.KRB_NT_PRINCIPAL {
		t.Errorf("cname type = %d, want KRB_NT_PRINCIPAL", req.ReqBody.CName.NameType)
	}
	if got := req.ReqBody.CName.NameString; len(got) != 1 || !principalPattern.MatchString(got[0]) {
		t.Errorf("cname = %v, want one name matching %s", got, principalPattern)
	}
}

// TestProbeKRBAgainstScriptedKDC runs the whole probe — dial, framing,
// parse — against a loopback listener playing a one-shot KDC. Hermetic:
// loopback only, no external network.
func TestProbeKRBAgainstScriptedKDC(t *testing.T) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "LAB.LOCAL"},
	}
	reply := mustMarshalKRBError(t, messages.NewKRBError(sname, "LAB.LOCAL", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "Client not found"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the framed AS-REQ (this also proves the probe's framing is
		// readable by our own reader), then answer with the framed error.
		if _, err := readKRBFrame(conn); err != nil {
			return
		}
		_ = writeKRBFrame(conn, reply)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	info := probeKRB("127.0.0.1", port, 5*time.Second, "LAB.LOCAL")
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error != "" {
		t.Errorf("Error = %q, want empty", info.Error)
	}
	if info.Realm != "LAB.LOCAL" {
		t.Errorf("Realm = %q, want LAB.LOCAL", info.Realm)
	}
	if info.KDCReply != "KDC_ERR_C_PRINCIPAL_UNKNOWN" {
		t.Errorf("KDCReply = %q, want KDC_ERR_C_PRINCIPAL_UNKNOWN", info.KDCReply)
	}
}

func TestProbeKRBConnectionRefused(t *testing.T) {
	// Grab a loopback port and release it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	info := probeKRB("127.0.0.1", port, 2*time.Second, "")
	if !info.Probed {
		t.Error("Probed = false, want true")
	}
	if info.Error == "" {
		t.Error("Error = empty, want dial failure recorded")
	}
	if info.Realm != "" || info.KDCReply != "" {
		t.Errorf("Realm/KDCReply = %q/%q, want both empty on dial failure", info.Realm, info.KDCReply)
	}
}
