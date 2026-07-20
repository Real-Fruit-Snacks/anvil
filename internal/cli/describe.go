package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"anvil/internal/ticket"
	"anvil/internal/ui"
)

// NewDescribeCmd builds the `anvil describe` command: parse a ccache or
// kirbi file and print every ticket it carries.
func NewDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <file>",
		Short: "Show the tickets inside a ccache or kirbi file",
		Long: "Parse a Kerberos ticket file — ccache or kirbi, auto-detected by " +
			"content, not extension — and print each ticket: client, service, " +
			"validity times, encryption types, and flags. Fully offline; " +
			"nothing is decrypted and no key is needed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				ui.PrintErr(fmt.Sprintf("read %s: %v", args[0], err))
				os.Exit(1)
			}
			d, err := ticket.Describe(data)
			if err != nil {
				ui.PrintErr(err.Error())
				os.Exit(1)
			}
			printDescription(d)
			return nil
		},
	}
}

// printDescription renders a ticket.Description in the Terminal Workbench
// idiom: muted uppercase section labels, aligned key/value rows, color only
// on signal (expired times are warm).
func printDescription(d *ticket.Description) {
	noun := "tickets"
	if len(d.Entries) == 1 {
		noun = "ticket"
	}
	header := ui.Muted.Sprintf("%-7s", strings.ToUpper(d.Format.String()))
	if d.Client != "" {
		fmt.Printf("%s  %s  %s\n", header, ui.AccentAlt.Sprint(d.Client),
			ui.Faint.Sprintf("%d %s", len(d.Entries), noun))
	} else {
		fmt.Printf("%s  %s\n", header, ui.Faint.Sprintf("%d %s", len(d.Entries), noun))
	}

	now := time.Now()
	for i, e := range d.Entries {
		fmt.Println()
		ui.Muted.Printf("TICKET %d\n", i+1)
		describeKV("client", joinPrincipal(e.Client, e.ClientRealm), ui.AccentAlt)
		describeKV("service", joinPrincipal(e.Server, e.ServerRealm), ui.AccentAlt)
		describeKV("session key", ticket.ETypeName(e.SessionEType), nil)
		if e.TicketOK {
			describeKV("ticket enc", ticket.ETypeName(e.TicketEType), nil)
		}
		describeKV("auth time", plainTime(e.AuthTime), nil)
		describeKV("start time", plainTime(e.StartTime), nil)
		describeKV("end time", describeTime(e.EndTime, now), expiryColor(e.EndTime, now))
		if !e.RenewTill.IsZero() && e.RenewTill.Unix() > 0 {
			describeKV("renew till", describeTime(e.RenewTill, now), expiryColor(e.RenewTill, now))
		}
		flags := fmt.Sprintf("0x%08x", e.Flags)
		if len(e.FlagNames) > 0 {
			flags += " (" + strings.Join(e.FlagNames, ", ") + ")"
		}
		describeKV("flags", flags, nil)
	}
}

// describeKV prints one key/value row: two-space indent, muted 15-wide key
// column, optional value color.
func describeKV(key, value string, c *color.Color) {
	if c != nil {
		value = c.Sprint(value)
	}
	fmt.Printf("  %s%s\n", ui.Muted.Sprintf("%-15s", key), value)
}

// plainTime renders an issue-side timestamp (auth/start) in UTC. These are
// in the past by definition, so unlike end/renew-till they never carry an
// expiry annotation. A zero time means the file didn't carry the field.
func plainTime(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// describeTime renders an expiry-side timestamp (end/renew-till) in UTC,
// marking expiry. A zero time means the file didn't carry the field.
func describeTime(t, now time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "-"
	}
	s := t.UTC().Format("2006-01-02 15:04:05 UTC")
	if now.After(t) {
		s += " (expired)"
	}
	return s
}

// expiryColor warms expired timestamps; valid and absent times stay neutral.
func expiryColor(t, now time.Time) *color.Color {
	if t.IsZero() || t.Unix() <= 0 {
		return nil
	}
	if now.After(t) {
		return ui.Warm
	}
	return nil
}

// joinPrincipal renders name@REALM for display, tolerating either side
// being empty (kirbi files may omit the client).
func joinPrincipal(name, realm string) string {
	switch {
	case name == "":
		return realm
	case realm == "":
		return name
	}
	return name + "@" + realm
}
