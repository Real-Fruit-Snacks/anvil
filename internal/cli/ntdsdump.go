package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"anvil/internal/ntds"
	"anvil/internal/ui"
)

// newNtdsdumpCmd builds the `anvil ntdsdump` command: the offline
// counterpart of the `ntdsdump` shell op, taking an NTDS.dit plus SYSTEM
// hive the caller already has (VSS copy, offline DC) instead of pulling
// them off a live DC through a shadow copy.
func newNtdsdumpCmd() *cobra.Command {
	var systemPath, ntdsPath string
	cmd := &cobra.Command{
		Use:   "ntdsdump",
		Short: "Dump domain account hashes from an offline NTDS.dit",
		Long: "Dump domain account NT/LM hashes from an NTDS.dit database plus the " +
			"SYSTEM hive that holds its boot key (both from a VSS copy or an offline " +
			"DC). The PEK is decrypted with the boot key and every account's hashes " +
			"locally — printed in secretsdump layout with the domain prefix derived " +
			"from the SYSTEM hive. Fully offline; the dump reflects the last ESE " +
			"flush (edb.log is not replayed), so very recent changes may be missing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lines, err := ntdsdumpOffline(systemPath, ntdsPath)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			printNtdsDump(lines)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&systemPath, "system", "", "path to the SYSTEM hive (required)")
	f.StringVar(&ntdsPath, "ntds", "", "path to the NTDS.dit database (required)")
	return cmd
}

// ntdsdumpOffline reads the dit and hive and renders every domain account
// in secretsdump layout (DOMAIN\user:RID:lm:nt:::). The domain prefix comes
// from the SYSTEM hive's TCP/IP parameters — offline there is no NTLM
// challenge to fall back on like the live path has. Unreadable files
// surface as "cannot read <path>: ...".
func ntdsdumpOffline(systemPath, ntdsPath string) ([]string, error) {
	if systemPath == "" || ntdsPath == "" {
		return nil, fmt.Errorf("--system and --ntds are both required")
	}
	systemData, err := os.ReadFile(systemPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", systemPath, err)
	}
	ntdsData, err := os.ReadFile(ntdsPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", ntdsPath, err)
	}
	users, err := ntds.Dump(ntdsData, systemData)
	if err != nil {
		return nil, err // parser errors are already plain-language themed
	}
	domain := ntds.Domain(systemData)
	lines := make([]string, 0, len(users))
	for _, u := range users {
		lines = append(lines, ntds.Format(domain, u))
	}
	return lines, nil
}

// printNtdsDump renders the account lines like the live shell op (raw
// secretsdump lines, then a faint count), plus the trailing ESE caveat the
// README documents for the live path: no edb.log replay, so the dump
// reflects the directory as of the last flush.
func printNtdsDump(lines []string) {
	if len(lines) == 0 {
		ui.Faint.Println("  no accounts found")
	} else {
		for _, l := range lines {
			fmt.Println(l)
		}
		ui.Faint.Printf("  %d accounts\n", len(lines))
	}
	ui.Faint.Println("  note: dump reflects the last ESE flush (no edb.log replay) — recent accounts may be missing")
}
