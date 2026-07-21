package cli

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/spf13/cobra"

	"anvil/internal/pkinit"
	"anvil/internal/ui"
)

// gettgtOptions carries the raw `anvil gettgt` flag values.
type gettgtOptions struct {
	user     string
	domain   string
	password string
	hashes   string
	cert     string
	dcIP     string
	out      string
}

// gettgtPlan is the validated, normalized form of the gettgt flags: the
// realm uppercased for the exchange, the NT half split out of --hashes,
// and the default ccache path filled in. cert/key are the PKINIT path.
type gettgtPlan struct {
	user     string
	domain   string // DNS form, as given (KDC resolution fallback)
	realm    string // domain uppercased — the form the KDC exchange uses
	password string // empty when authenticating with an NT hash
	ntHash   string // bare NT hash, 32 hex chars; empty with -p
	cert     *x509.Certificate
	key      *rsa.PrivateKey
	dcIP     string
	out      string
}

func newGetTGTCmd() *cobra.Command {
	var opts gettgtOptions

	cmd := &cobra.Command{
		Use:   "gettgt",
		Short: "Request a TGT from the KDC and save it as a ccache",
		Long: "Request a Ticket Granting Ticket with a password (-p) or NT hash " +
			"(--hashes) and write it as a ccache. The KDC is resolved via the " +
			"-d domain unless --dc-ip overrides it. Load the result with " +
			"KRB5CCNAME for `anvil connect -k`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := planGetTGT(opts)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}

			var result *kerberos.TGTResult
			if plan.cert != nil {
				// PKINIT path: one PA-PK-AS exchange with the certificate
				// (RFC 4556 RSA mode — internal/pkinit builds the CMS
				// SignedData and unwraps the reply key).
				result, err = pkinit.TGTWithCert(plan.domain, plan.dcIP, plan.user, plan.cert, plan.key, flagTimeout)
				if err != nil {
					ui.PrintErr(err.Error())
					os.Exit(1)
				}
			} else {
				// One AS-REQ/AS-REP exchange against the KDC (TCP/88, 4-byte
				// length prefix) with PA-ENC-TIMESTAMP pre-auth. pkg/kerberos
				// derives an RC4-HMAC key (etype 23) from either credential —
				// MD4 of the UTF-16LE password, or the NT hash directly — and
				// uppercases the domain into the realm itself.
				result, err = kerberos.GetTGT(&kerberos.TGTRequest{
					Username: plan.user,
					Password: plan.password,
					Domain:   plan.domain,
					NTHash:   plan.ntHash,
					DCIP:     plan.dcIP,
				})
				if err != nil {
					ui.PrintErr(mapGetTGTError(err, plan.user, plan.realm).Error())
					os.Exit(1)
				}
			}
			if err := kerberos.SaveTGT(plan.out, result); err != nil {
				ui.PrintErr(fmt.Sprintf("save ticket: %v", err))
				os.Exit(1)
			}

			fmt.Printf("%s  %s@%s\n", ui.Muted.Sprint("TGT"), plan.user, plan.realm)
			fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "ccache"), plan.out)
			ui.Faint.Printf("use: KRB5CCNAME=%s anvil connect -k -u %s -d %s --host <fqdn>\n",
				plan.out, plan.user, plan.realm)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.user, "user", "u", "", "username to request the TGT for (required)")
	f.StringVarP(&opts.domain, "domain", "d", "", "DNS domain / realm, e.g. lab.local (required)")
	f.StringVarP(&opts.password, "password", "p", "", "account password (mutually exclusive with --hashes)")
	f.StringVar(&opts.hashes, "hashes", "", "account NTLM hashes LMHASH:NTHASH — only the NT half is used (mutually exclusive with -p)")
	f.StringVar(&opts.cert, "cert", "", "certificate+key PEM for PKINIT (certreq loot format; -p/--hashes not allowed)")
	f.StringVar(&opts.dcIP, "dc-ip", "", "KDC address override (default: resolve via the domain)")
	f.StringVar(&opts.out, "out", "", "ccache output path (default <user>.ccache)")
	return cmd
}

// planGetTGT validates the flags and normalizes them into a gettgtPlan.
// Exactly one credential is required: pre-auth needs a single key source,
// and passing two would leave which one authenticated the TGT ambiguous.
func planGetTGT(opts gettgtOptions) (gettgtPlan, error) {
	if opts.domain == "" {
		return gettgtPlan{}, fmt.Errorf("-d is required (DNS realm, e.g. lab.local)")
	}

	plan := gettgtPlan{
		user:     opts.user,
		domain:   strings.TrimSuffix(opts.domain, "."),
		password: opts.password,
		dcIP:     opts.dcIP,
		out:      opts.out,
	}
	// Kerberos realms are the DNS domain uppercased. A trailing root dot
	// ("lab.local.") is DNS notation, not part of the realm name.
	plan.realm = strings.ToUpper(plan.domain)

	switch {
	case opts.cert != "":
		if opts.password != "" || opts.hashes != "" {
			return gettgtPlan{}, fmt.Errorf("--cert cannot be combined with -p/--hashes — the certificate IS the credential")
		}
		pemBytes, err := os.ReadFile(opts.cert)
		if err != nil {
			return gettgtPlan{}, fmt.Errorf("cannot read certificate PEM %s: %v", opts.cert, err)
		}
		cert, key, err := pkinit.ParsePEMCertKey(pemBytes)
		if err != nil {
			return gettgtPlan{}, fmt.Errorf("cannot parse certificate PEM %s: %v", opts.cert, err)
		}
		plan.cert, plan.key = cert, key
		if plan.user == "" {
			// PKINIT's principal comes from the cert: SAN UPN first
			// (svc-kerb@... for an ESC1-issued cert), subject CN as fallback.
			plan.user = upnFromCert(cert)
			if plan.user == "" {
				plan.user = cert.Subject.CommonName
			}
			if plan.user == "" {
				return gettgtPlan{}, fmt.Errorf("--cert: no UPN in the SAN and no subject CN — pass -u explicitly")
			}
		}
		// The exchange takes the bare user; the realm comes from -d.
		if i := strings.Index(plan.user, "@"); i >= 0 {
			plan.user = plan.user[:i]
		}
	case opts.password == "" && opts.hashes == "":
		return gettgtPlan{}, fmt.Errorf("one credential is required: -p <password>, --hashes <LM:NT>, or --cert <pem>")
	case opts.password != "" && opts.hashes != "":
		return gettgtPlan{}, fmt.Errorf("-p and --hashes are mutually exclusive — pass exactly one credential")
	}
	if opts.user == "" && opts.cert == "" {
		return gettgtPlan{}, fmt.Errorf("-u is required")
	}

	if opts.hashes != "" {
		nt, err := ntHashHalf(opts.hashes)
		if err != nil {
			return gettgtPlan{}, err
		}
		plan.ntHash = nt
	}
	if plan.out == "" {
		plan.out = plan.user + ".ccache"
	}
	return plan, nil
}

// upnFromCert extracts the Microsoft UPN from a certificate's SAN
// (otherName with type-id szOID_NT_PRINCIPAL_NAME, 1.3.6.1.4.1.311.20.2.3).
// Go's x509 does not decode UPN otherNames into any field, so the
// extension is walked by hand; "" when absent.
func upnFromCert(cert *x509.Certificate) string {
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUPN := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			continue
		}
		for _, n := range names {
			if n.Class != asn1.ClassContextSpecific || n.Tag != 0 || len(n.Bytes) == 0 {
				continue
			}
			// otherName (GeneralName [0]) content: the type-id OID TLV
			// followed by the [0] EXPLICIT UTF8String value.
			rest := n.Bytes
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(rest, &oid)
			if err != nil || !oid.Equal(oidUPN) || len(rest) == 0 {
				continue
			}
			var v asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &v); err != nil || v.Tag != 0 {
				continue
			}
			var upn string
			if _, err := asn1.Unmarshal(v.Bytes, &upn); err == nil {
				return upn
			}
		}
	}
	return ""
}

// ntHashHalf accepts a bare NT hash or secretsdump-style LM:NT and returns
// the NT half; RC4-HMAC pre-auth keys derive only from the NT half, the LM
// half is vestigial. An NT hash is 16 bytes = 32 hex chars.
func ntHashHalf(hashes string) (string, error) {
	s := hashes
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid --hashes: NT hash is not hex")
	}
	if len(raw) != 16 {
		return "", fmt.Errorf("invalid --hashes: want 32 hex chars (16 bytes) for the NT hash, got %d", len(s))
	}
	return s, nil
}

// mapGetTGTError themes the failures operators hit most — an unreachable
// KDC and a rejected credential — in plain language. pkg/kerberos already
// renders the rarer KRB-ERROR codes readably; those pass through.
func mapGetTGTError(err error, user, realm string) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "failed to connect to KDC"):
		return fmt.Errorf("KDC unreachable — check --dc-ip and the network route (%v)", err)
	case strings.Contains(s, "PREAUTH_FAILED"):
		return fmt.Errorf("wrong password or NT hash for %s@%s (KDC_ERR_PREAUTH_FAILED)", user, realm)
	case strings.Contains(s, "C_PRINCIPAL_UNKNOWN"):
		return fmt.Errorf("no such user %s@%s (KDC_ERR_C_PRINCIPAL_UNKNOWN)", user, realm)
	}
	return err
}

// gettgtLongFlags are gettgt's documented single-dash long flags
// (-hashes, -dc-ip, -out, ...). rewriteTicketArgs needs a "gettgt" case
// referencing this map for the impacket-style forms to parse.
var gettgtLongFlags = map[string]bool{
	"user": true, "password": true, "hashes": true, "cert": true,
	"domain": true, "dc-ip": true, "out": true, "help": true,
}
