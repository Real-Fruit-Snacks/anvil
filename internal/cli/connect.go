package cli

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mandiant/gopacket/pkg/session"
	"github.com/spf13/cobra"

	"anvil/internal/shell"
	"anvil/internal/smbclient"
	"anvil/internal/ui"
)

func newConnectCmd() *cobra.Command {
	var (
		host      string
		port      int
		targetIP  string
		user      string
		password  string
		domain    string
		hashes    string
		kerberos  bool
		dcIP      string
		dcHost    string
		syncClock bool
	)

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Authenticated SMB session with interactive shell",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			if kerberos && net.ParseIP(host) != nil {
				// The SPN (cifs/<host>) needs a name the KDC knows.
				return fmt.Errorf("kerberos requires the target FQDN — pass --host <fqdn> and --target-ip %s", host)
			}
			if syncClock && !kerberos {
				// The offset is applied to kerberos timestamps only.
				return fmt.Errorf("--sync-clock only applies to kerberos — pass -k as well")
			}

			creds := &session.Credentials{
				Domain:      domain,
				Username:    user,
				Password:    password,
				Hash:        hashes,
				UseKerberos: kerberos,
				DCIP:        dcIP,
				DCHost:      dcHost,
			}

			nullSession := !kerberos && user == "" && password == "" && hashes == ""
			switch {
			case nullSession:
				ui.Faint.Println("no credentials supplied — attempting null session")
			case !kerberos && user != "" && password == "" && hashes == "":
				// Hidden password prompt (gopacket pkg/session helper).
				if err := session.EnsurePassword(creds); err != nil {
					return err
				}
			}

			if syncClock {
				// Measure before dialing anything kerberos-related: the
				// offset must be in place when Connect builds AP-REQs.
				ntpTarget := dcIP
				if ntpTarget == "" {
					ntpTarget = host
				}
				offset, err := smbclient.NTPOffset(ntpTarget, flagTimeout)
				if err != nil {
					return fmt.Errorf("--sync-clock: %v", err)
				}
				smbclient.SetClockOffset(offset)
				ui.Faint.Printf("  clock offset vs %s: %+v (applied to kerberos timestamps)\n",
					ntpTarget, offset.Round(time.Millisecond))
			}

			sess, err := smbclient.Connect(host, port, targetIP, creds, flagTimeout, nullSession)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			defer sess.Close()

			printRecap(sess, creds, nullSession)

			if code := shell.Run(sess); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "target host (IP or hostname; FQDN for -k) (required)")
	cmd.Flags().IntVar(&port, "port", 445, "SMB port")
	cmd.Flags().StringVar(&targetIP, "target-ip", "", "connect via this IP while keeping --host as the SPN name")
	cmd.Flags().StringVarP(&user, "user", "u", "", "username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password (prompted if -u given without -p; with -k, used to mint a TGT when no ccache is found)")
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "domain (kerberos realm with -k)")
	cmd.Flags().StringVar(&hashes, "hashes", "", "NTLM hashes LMHASH:NTHASH (pass-the-hash)")
	cmd.Flags().BoolVarP(&kerberos, "kerberos", "k", false, "use kerberos (ccache from KRB5CCNAME or <user>.ccache)")
	cmd.Flags().StringVar(&dcIP, "dc-ip", "", "KDC address override for kerberos")
	cmd.Flags().StringVar(&dcHost, "dc-host", "", "DC hostname override for kerberos")
	cmd.Flags().BoolVar(&syncClock, "sync-clock", false, "query the DC's clock via NTP and offset kerberos timestamps by it (with -k; defeats clock skew on forged-ticket logons)")
	return cmd
}

// printRecap prints one faint line summarizing the established session.
func printRecap(sess *smbclient.Session, creds *session.Credentials, nullSession bool) {
	who := "null session"
	if !nullSession {
		who = creds.Username
		if creds.Domain != "" {
			who = creds.Domain + "\\" + creds.Username
		}
	}

	recap := fmt.Sprintf("connected %s as %s", sess.Host(), who)
	if dnsHost, dnsTree := sess.ServerInfo(); dnsHost != "" {
		recap += " — server " + dnsHost
		if dnsTree != "" {
			recap += " (" + dnsTree + ")"
		}
	}
	ui.Faint.Println(recap)
}
