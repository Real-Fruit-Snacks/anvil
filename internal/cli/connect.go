package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/spf13/cobra"

	"anvil/internal/shell"
	"anvil/internal/smbclient"
	"anvil/internal/ui"
)

func newConnectCmd() *cobra.Command {
	var (
		host       string
		port       int
		targetIP   string
		user       string
		password   string
		domain     string
		hashes     string
		kerberos   bool
		dcIP       string
		dcHost     string
		syncClock  bool
		transcript string
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

			// The transcript starts only once the session is up, so a
			// failed connect leaves no empty file behind. Capture covers
			// the recap and the whole shell; restore runs explicitly
			// before any os.Exit (defers are skipped on that path).
			var restoreTranscript func()
			if transcript != "" {
				if restoreTranscript, err = startTranscript(transcript, sess.Host()); err != nil {
					ui.PrintErr(fmt.Sprintf("could not start transcript (%v) — session continues without it", err))
				} else {
					ui.Faint.Printf("  transcript: %s\n", transcript)
				}
			}

			printRecap(sess, creds, nullSession)

			code := shell.Run(sess)
			if restoreTranscript != nil {
				restoreTranscript()
			}
			if code != 0 {
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
	cmd.Flags().StringVar(&transcript, "transcript", "", "record all session output to this file as well as the terminal (created 0600)")
	return cmd
}

// startTranscript tees everything written to stdout into path (0600,
// parents created 0700) while keeping the terminal live: os.Stdout is
// swapped for a pipe whose reader copies into both the real stdout and the
// file. fatih/color caches its own Output writer at package init, so the
// themed ui.* printers would bypass the swap — color.Output is redirected
// alongside os.Stdout. A "# anvil transcript <host> started <RFC3339>"
// marker is written immediately; the returned closure restores both
// writers, drains the pipe so no tail output is lost, appends
// "# ended <RFC3339>", and closes the file. Pure Go — os.Pipe behaves the
// same on Windows. stderr is never touched, so the hidden password prompt
// and cobra's own diagnostics stay on the real terminal.
func startTranscript(path, host string) (restore func(), err error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create transcript directory: %v", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open transcript file: %v", err)
	}
	fmt.Fprintf(f, "# anvil transcript %s started %s\n", host, time.Now().UTC().Format(time.RFC3339))

	pr, pw, err := os.Pipe()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open transcript pipe: %v", err)
	}
	real := os.Stdout
	realColor := color.Output
	os.Stdout = pw
	color.Output = pw
	done := make(chan struct{})
	go func() {
		// Terminal first in the MultiWriter: output stays live even if
		// the file write ever stalls.
		io.Copy(io.MultiWriter(real, f), pr)
		close(done)
	}()

	return func() {
		os.Stdout = real // new writes bypass the pipe
		color.Output = realColor
		pw.Close() // reader sees EOF once queued bytes have drained
		<-done     // everything pending has landed in terminal + file
		pr.Close()
		fmt.Fprintf(f, "# ended %s\n", time.Now().UTC().Format(time.RFC3339))
		f.Close()
	}, nil
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
