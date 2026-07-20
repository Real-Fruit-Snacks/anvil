package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"anvil/internal/ticket"
	"anvil/internal/ui"
)

// NewConvertCmd builds the `anvil convert` command: ccache <-> kirbi
// conversion, direction auto-detected from the input's content.
func NewConvertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "convert <in> <out>",
		Short: "Convert a ticket file between ccache and kirbi",
		Long: "Convert a Kerberos ticket file between ccache and kirbi (KRB-CRED) " +
			"formats — ccache for `anvil connect -k`, kirbi for impacket/Rubeus " +
			"tooling. The direction is auto-detected from the input's content, " +
			"not its extension, and every ticket in the file is converted. " +
			"Fully offline; the output file is written 0600.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := ticket.ConvertFile(args[0], args[1])
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			fmt.Printf("%s  %s\n", ui.Muted.Sprint("CONVERT"), dir)
			fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "out"), args[1])
			return nil
		},
	}
}
