// Package cli wires the cobra command tree for anvil.
package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"anvil/internal/ui"
)

// Version is the anvil release version.
const Version = "0.7.0"

var (
	flagTimeout time.Duration
	flagJSON    bool
	flagDebug   bool
)

var rootCmd = &cobra.Command{
	Use:   "anvil",
	Short: "Active Directory recon and attack tool",
	Long: "anvil — Active Directory recon/attack tool built on Mandiant's gopacket.\n" +
		"For authorized security testing only.",
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ui.SetDebug(flagDebug)
	},
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	rewriteTicketArgs(os.Args[1:])
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", 3*time.Second, "per-connection timeout")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit machine-readable JSON, no color")
	rootCmd.PersistentFlags().BoolVar(&flagDebug, "debug", false, "verbose debug logging to stderr")
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newConnectCmd())
	rootCmd.AddCommand(newTicketCmd())
	rootCmd.AddCommand(newGetSTCmd())
	rootCmd.AddCommand(NewDescribeCmd())
	rootCmd.AddCommand(NewConvertCmd())
	rootCmd.AddCommand(newGetTGTCmd())
	rootCmd.AddCommand(newSprayCmd())
	rootCmd.AddCommand(newUserenumCmd())
	rootCmd.AddCommand(newSamdumpCmd())
	rootCmd.AddCommand(newLsadumpCmd())
	rootCmd.AddCommand(newNtdsdumpCmd())
	rootCmd.AddCommand(newRelayCmd())
}
