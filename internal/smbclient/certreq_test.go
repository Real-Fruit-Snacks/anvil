package smbclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// testKey generates one RSA-2048 key per test run — CSR building needs a real
// key, and 2048 matches what CertRequest generates.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func TestTemplateNameExtension(t *testing.T) {
	cases := []struct {
		name     string
		template string
		want     []byte
	}{
		{
			// DER UTF8String: tag 0x13, len 4, "User" — the MS-WCCE form a
			// Server 2022 CA actually issues against (verified live).
			name:     "built-in User template",
			template: "User",
			want:     []byte{0x13, 0x04, 0x55, 0x73, 0x65, 0x72},
		},
		{
			name:     "custom template",
			template: "CorpWebServer",
			want:     append([]byte{0x13, 0x0d}, []byte("CorpWebServer")...),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ext := templateNameExtension(c.template)
			if got := ext.Id.String(); got != "1.3.6.1.4.1.311.20.2" {
				t.Errorf("template extension OID = %s, want 1.3.6.1.4.1.311.20.2", got)
			}
			if ext.Critical {
				t.Errorf("template extension marked critical — MS-WCCE requires FALSE")
			}
			if !reflect.DeepEqual(ext.Value, c.want) {
				t.Errorf("template extension value = %x, want %x", ext.Value, c.want)
			}
		})
	}
}

func TestUPNSANExtension(t *testing.T) {
	// Hand-computed DER for SAN = one otherName UPN "administrator@corp.local":
	// SEQUENCE { [0] { OID 1.3.6.1.4.1.311.20.2.3, [0] EXPLICIT UTF8String } }
	// (RFC 4556 GeneralName nesting; certipy emits the identical structure).
	want := []byte{
		0x30, 0x2a, // SEQUENCE, 42 bytes
		0xa0, 0x28, // [0] GeneralName otherName, 40 bytes
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03, // OID 1.3.6.1.4.1.311.20.2.3
		0xa0, 0x1a, // [0] EXPLICIT, 26 bytes
		0x0c, 0x18, // UTF8String, 24 bytes
		'a', 'd', 'm', 'i', 'n', 'i', 's', 't', 'r', 'a', 't', 'o', 'r',
		'@', 'c', 'o', 'r', 'p', '.', 'l', 'o', 'c', 'a', 'l',
	}

	ext, err := upnSANExtension("administrator@corp.local")
	if err != nil {
		t.Fatalf("upnSANExtension: %v", err)
	}
	if got := ext.Id.String(); got != "2.5.29.17" {
		t.Errorf("SAN extension OID = %s, want 2.5.29.17", got)
	}
	if !reflect.DeepEqual(ext.Value, want) {
		t.Errorf("SAN extension value:\n got %x\nwant %x", ext.Value, want)
	}
}

func TestBuildCSR(t *testing.T) {
	cases := []struct {
		name     string
		template string
		cn       string
		san      string
		wantSAN  bool
	}{
		{"template only, no SAN", "User", "alice", "", false},
		{"with UPN SAN (ESC1 form)", "CorpWebServer", "alice", "administrator@corp.local", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csrDER, err := buildCSR(testKey(t), c.template, c.cn, c.san)
			if err != nil {
				t.Fatalf("buildCSR: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("ParseCertificateRequest: %v", err)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("CSR signature invalid: %v", err)
			}
			if csr.Subject.CommonName != c.cn {
				t.Errorf("subject CN = %q, want %q", csr.Subject.CommonName, c.cn)
			}

			var tmplExt, sanExt bool
			for _, e := range csr.Extensions {
				switch e.Id.String() {
				case "1.3.6.1.4.1.311.20.2":
					tmplExt = true
					if want := templateNameExtension(c.template).Value; !reflect.DeepEqual(e.Value, want) {
						t.Errorf("template extension in CSR = %x, want %x", e.Value, want)
					}
				case "2.5.29.17":
					sanExt = true
					want, err := upnSANExtension(c.san)
					if err != nil {
						t.Fatalf("upnSANExtension: %v", err)
					}
					if !reflect.DeepEqual(e.Value, want.Value) {
						t.Errorf("SAN extension in CSR = %x, want %x", e.Value, want.Value)
					}
				}
			}
			if !tmplExt {
				t.Errorf("CSR carries no szOID_ENROLL_CERTTYPE_EXTENSION")
			}
			if sanExt != c.wantSAN {
				t.Errorf("SAN extension present = %v, want %v", sanExt, c.wantSAN)
			}
		})
	}
}

func TestCertRequestAttributes(t *testing.T) {
	cases := []struct {
		template string
		want     string // decoded payload (UTF-16LE, NUL-terminated)
	}{
		{"User", "CertificateTemplate:User"},
		{"CorpWebServer", "CertificateTemplate:CorpWebServer"},
	}
	for _, c := range cases {
		t.Run(c.template, func(t *testing.T) {
			got := certRequestAttributes(c.template)
			if len(got)%2 != 0 {
				t.Fatalf("odd byte count %d", len(got))
			}
			decoded := decodeUTF16(got)
			if decoded != c.want {
				t.Errorf("certRequestAttributes(%q) decoded = %q, want %q", c.template, decoded, c.want)
			}
			// cb includes the NUL terminator (E_INVALIDARG from the CA otherwise).
			if got[len(got)-2] != 0 || got[len(got)-1] != 0 {
				t.Errorf("payload not NUL-terminated: % x", got[len(got)-4:])
			}
		})
	}
}

func TestMapCertError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // substring of the mapped error; equal to input when unchanged
	}{
		{
			// Rendered form of a Windows CA template denial: the HRESULT rides
			// inside the CA's disposition message.
			name: "template denied or unknown",
			err: errors.New("certificate request failed: disposition=2 (0x00000002), message=" +
				"Denied by Policy Module 0x80094012, The permissions on the certificate template do not allow the current user to enroll"),
			want: "no such certificate template",
		},
		{
			name: "CA-wide enrollment denied",
			err: errors.New("certificate request failed: disposition=2 (0x00000002), message=" +
				"Denied by Policy Module 0x80094011"),
			want: "does not allow enrollment by this user",
		},
		{
			name: "pending approval passes through (keeps the request ID)",
			err:  errors.New("certificate request pending approval (requestID=42)"),
			want: "certificate request pending approval (requestID=42)",
		},
		{
			name: "unrecognized failure passes through",
			err:  errors.New("CertServerRequest call failed: io timeout"),
			want: "CertServerRequest call failed: io timeout",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapCertError(c.err)
			if !strings.Contains(got.Error(), c.want) {
				t.Errorf("mapCertError(%v) = %q, want substring %q", c.err, got, c.want)
			}
		})
	}
}

func TestWriteCertPEM(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3, 4}})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{5, 6, 7, 8}})

	path := filepath.Join(t.TempDir(), "loot", "adcs", "user.pem")
	if err := WriteCertPEM(path, certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertPEM: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	// Cert block first, key block second, nothing else in the file.
	certBlock, rest := pem.Decode(data)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block = %+v, want CERTIFICATE", certBlock)
	}
	keyBlock, rest := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("second PEM block = %+v, want PRIVATE KEY", keyBlock)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Errorf("trailing data after key block: %q", rest)
	}

	// Key material is written owner-only — enforceable and asserted on POSIX;
	// Windows ACLs don't map the mode bits back, so there the check is moot.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("file mode = %o, want 0600", perm)
		}
	}
}
