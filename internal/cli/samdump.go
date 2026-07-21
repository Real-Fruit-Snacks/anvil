package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"anvil/internal/sam"
	"anvil/internal/ui"
)

// newSamdumpCmd builds the `anvil samdump` command: the offline counterpart
// of the `samdump` shell op. Instead of saving the hives on a live target
// over winreg, it takes previously-exported SAM+SYSTEM hives and runs the
// same local parse/decrypt path.
func newSamdumpCmd() *cobra.Command {
	var systemPath, samPath string
	cmd := &cobra.Command{
		Use:   "samdump",
		Short: "Dump local account hashes from offline SAM+SYSTEM hives",
		Long: "Dump local account NT/LM hashes from SAM and SYSTEM hives previously " +
			"exported from a Windows host (reg save HKLM\\SAM / HKLM\\SYSTEM, or a VSS " +
			"copy). The boot key is derived from SYSTEM and every account's hashes are " +
			"decrypted locally — printed in secretsdump layout, same as the live " +
			"`samdump` shell op. Fully offline; no target connection is made.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lines, err := samdumpOffline(systemPath, samPath)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			printSamDump(lines)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&systemPath, "system", "", "path to the SYSTEM hive (required)")
	f.StringVar(&samPath, "sam", "", "path to the SAM hive (required)")
	return cmd
}

// samdumpOffline reads both hives and renders every local account in
// secretsdump layout (user:RID:lm:nt:::). Unreadable files surface as
// "cannot read <path>: ..." — the repo's plain-language error idiom.
func samdumpOffline(systemPath, samPath string) ([]string, error) {
	if systemPath == "" || samPath == "" {
		return nil, fmt.Errorf("--system and --sam are both required")
	}
	systemData, err := os.ReadFile(systemPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", systemPath, err)
	}
	samData, err := os.ReadFile(samPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", samPath, err)
	}
	users, err := sam.Dump(systemData, samData)
	if err != nil {
		return nil, err // parser errors are already plain-language themed
	}
	lines := make([]string, 0, len(users))
	for _, u := range users {
		lines = append(lines, sam.Format(u))
	}
	return lines, nil
}

// printSamDump renders the account lines exactly like the live shell op
// (shell.cmdSamdump): raw secretsdump lines, no indentation or section
// header.
func printSamDump(lines []string) {
	if len(lines) == 0 {
		ui.Faint.Println("  no local accounts found")
		return
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}
