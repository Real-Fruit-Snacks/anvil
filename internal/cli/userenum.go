package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"anvil/internal/krbuser"
	"anvil/internal/ui"
)

func newUserenumCmd() *cobra.Command {
	var domain, dcIP, usersFile, outFile string

	cmd := &cobra.Command{
		Use:   "userenum",
		Short: "Kerberos user enumeration via bare AS-REQs (no credentials)",
		Long: "Send one AS-REQ per username to the KDC and classify the reply: " +
			"KDC_ERR_PREAUTH_REQUIRED means the account exists, KDC_ERR_C_PRINCIPAL_UNKNOWN " +
			"means it does not, KDC_ERR_CLIENT_REVOKED means locked/disabled, and a live " +
			"AS-REP means the account is AS-REP roastable (no preauth). No password material " +
			"is sent, so this touches no account state and trips no lockout threshold.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := krbuser.ValidateTarget(domain, dcIP); err != nil {
				return err
			}
			users, err := krbuser.LoadUsers(usersFile)
			if err != nil {
				return err
			}

			fmt.Printf("%s  %s via %s %s\n",
				ui.Muted.Sprint("USERENUM"),
				strings.ToUpper(domain),
				dcIP,
				ui.Faint.Sprintf("(%d users)", len(users)))

			counts := map[krbuser.Verdict]int{}
			var outLines []string
			for _, u := range users {
				r := krbuser.EnumUser(domain, dcIP, u, flagTimeout)
				counts[r.Verdict]++
				printUserenumLine(r)
				outLines = append(outLines, fmt.Sprintf("%s %s", r.Username, r.Verdict))
			}

			fmt.Println()
			ui.Muted.Println("SUMMARY")
			printCount("valid", counts[krbuser.VerdictValid], ui.Accent)
			printCount("no preauth", counts[krbuser.VerdictValidNoPreauth], ui.Warm)
			printCount("invalid", counts[krbuser.VerdictInvalid], nil)
			printCount("locked", counts[krbuser.VerdictLocked], ui.Warm)
			printCount("errors", counts[krbuser.VerdictError], nil)
			printCount("total", len(users), nil)

			if outFile != "" {
				body := strings.Join(outLines, "\n") + "\n"
				if err := os.WriteFile(outFile, []byte(body), 0o644); err != nil {
					return fmt.Errorf("cannot write --out file: %v", err)
				}
				ui.Faint.Printf("  wrote %d verdicts to %s\n", len(outLines), outFile)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&domain, "domain", "d", "", "DNS domain / realm, e.g. lab.local (required)")
	f.StringVar(&dcIP, "dc-ip", "", "KDC address, optionally host:port (required)")
	f.StringVarP(&usersFile, "users", "u", "", "username file, one per line, '#' comments (required)")
	f.StringVar(&outFile, "out", "", "also write '<user> <VERDICT>' lines to this file")
	return cmd
}

// printUserenumLine renders one user's verdict: faint for INVALID (the
// expected bulk answer), accent for VALID, warm for LOCKED and for the
// roastable no-preauth finding (color on signal only), red for errors.
func printUserenumLine(r krbuser.Result) {
	name := fmt.Sprintf("%-24s", r.Username)
	switch r.Verdict {
	case krbuser.VerdictValid:
		fmt.Printf("  %s%s\n", name, ui.Accent.Sprint(r.Verdict))
	case krbuser.VerdictValidNoPreauth:
		fmt.Printf("  %s%s %s\n", name, ui.Warm.Sprint(r.Verdict), ui.Warm.Sprint("(roastable)"))
	case krbuser.VerdictInvalid:
		fmt.Printf("  %s%s\n", name, ui.Faint.Sprint(r.Verdict))
	case krbuser.VerdictLocked:
		fmt.Printf("  %s%s\n", name, ui.Warm.Sprint(r.Verdict))
	default:
		fmt.Printf("  %s%s %s\n", name, ui.Red.Sprint(r.Verdict), ui.Muted.Sprint(r.Detail))
	}
}

// printCount prints one summary kv row; zero counts for the color-coded
// verdicts are omitted so the summary shows only what was found (total is
// always shown).
func printCount(label string, n int, c *color.Color) {
	if n == 0 && label != "total" {
		return
	}
	value := fmt.Sprintf("%d", n)
	if c != nil {
		value = c.Sprint(value)
	}
	fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", label), value)
}
