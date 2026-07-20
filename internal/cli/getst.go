package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"anvil/internal/getst"
	"anvil/internal/ui"
)

func newGetSTCmd() *cobra.Command {
	var opts getst.Options

	cmd := &cobra.Command{
		Use:   "getst",
		Short: "Impersonate a user onto a service via S4U2Self+S4U2Proxy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := getst.Run(opts)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}

			realm := strings.ToUpper(opts.Domain)
			fmt.Printf("%s  %s@%s -> %s\n", ui.Muted.Sprint("SERVICE TICKET"), opts.Impersonate, realm, opts.SPN)
			fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "ccache"), out)
			ui.Faint.Printf("use: KRB5CCNAME=%s anvil connect -k --host %s\n", out, getst.SPNHost(opts.SPN))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.SPN, "spn", "", "target service SPN, e.g. cifs/dc01.corp.local (required)")
	f.StringVar(&opts.Impersonate, "impersonate", "", "user to impersonate (required)")
	f.StringVarP(&opts.User, "user", "u", "", "requesting account, e.g. machine account from addcomputer (required)")
	f.StringVarP(&opts.Password, "password", "p", "", "requesting account's password")
	f.StringVar(&opts.Hash, "hashes", "", "requesting account's NTLM hashes LMHASH:NTHASH")
	f.StringVarP(&opts.Domain, "domain", "d", "", "DNS realm, e.g. lab.local (required)")
	f.StringVar(&opts.DCIP, "dc-ip", "", "KDC address override")
	f.StringVar(&opts.Out, "out", "", "ccache output path (default <user>@<spn>.ccache)")
	return cmd
}
