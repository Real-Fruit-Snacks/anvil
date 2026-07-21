package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"anvil/internal/lsa"
	"anvil/internal/ui"
)

// newLsadumpCmd builds the `anvil lsadump` command: the offline counterpart
// of the `lsadump` shell op, taking previously-exported SECURITY+SYSTEM
// hives instead of pulling them off a live target over winreg.
func newLsadumpCmd() *cobra.Command {
	var systemPath, securityPath string
	cmd := &cobra.Command{
		Use:   "lsadump",
		Short: "Decrypt LSA secrets and cached logons from offline hives",
		Long: "Decrypt LSA secrets and cached domain logons (MSCashV2) from SECURITY " +
			"and SYSTEM hives previously exported from a Windows host (reg save " +
			"HKLM\\SECURITY / HKLM\\SYSTEM, or a VSS copy). The boot key is derived " +
			"from SYSTEM and everything is decrypted locally; output is identical " +
			"to the live `lsadump` shell op. Fully offline; no target connection " +
			"is made.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := lsadumpOffline(systemPath, securityPath)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			printLSAResult(res)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&systemPath, "system", "", "path to the SYSTEM hive (required)")
	f.StringVar(&securityPath, "security", "", "path to the SECURITY hive (required)")
	return cmd
}

// lsadumpOffline reads both hives and returns the parsed LSA result.
// Unreadable files surface as "cannot read <path>: ..." — the repo's
// plain-language error idiom.
func lsadumpOffline(systemPath, securityPath string) (*lsa.Result, error) {
	if systemPath == "" || securityPath == "" {
		return nil, fmt.Errorf("--system and --security are both required")
	}
	systemData, err := os.ReadFile(systemPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", systemPath, err)
	}
	securityData, err := os.ReadFile(securityPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", securityPath, err)
	}
	return lsa.Dump(systemData, securityData)
}

// printLSAResult renders the result EXACTLY like the live `lsadump` shell
// op (shell.cmdLsadump): CACHED LOGONS first, then LSA SECRETS, both
// two-space indented. Keep the two in sync so live and offline output diff
// clean.
func printLSAResult(res *lsa.Result) {
	if len(res.CachedLogons) == 0 && len(res.Lines()) == 0 {
		ui.Faint.Println("  (no LSA secrets)")
		return
	}
	if len(res.CachedLogons) > 0 {
		ui.Muted.Println("  CACHED LOGONS")
		for _, c := range res.CachedLogons {
			fmt.Printf("  %s\n", lsa.FormatCached(c))
		}
	}
	if lines := res.Lines(); len(lines) > 0 {
		ui.Muted.Println("  LSA SECRETS")
		for _, l := range lines {
			fmt.Printf("  %s\n", l)
		}
	}
}
