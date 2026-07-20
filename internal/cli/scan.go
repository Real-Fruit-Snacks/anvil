package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"anvil/internal/scan"
	"anvil/internal/ui"
)

func newScanCmd() *cobra.Command {
	var portsFlag string

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Unauthenticated target profile (ports, SMB, RPC, LDAP)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			defs, err := parsePorts(portsFlag)
			if err != nil {
				return err
			}

			profile := scan.Run(target, scan.Options{
				Ports:   defs,
				Timeout: flagTimeout,
			})

			if flagJSON {
				out, err := json.MarshalIndent(profile, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(out))
				return nil
			}

			ui.PrintProfile(profile)
			return nil
		},
	}

	cmd.Flags().StringVar(&portsFlag, "ports", "", "comma-separated TCP ports to probe (default: AD port set)")
	return cmd
}

func parsePorts(s string) ([]scan.PortDef, error) {
	if strings.TrimSpace(s) == "" {
		return scan.DefaultPorts, nil
	}

	var defs []scan.PortDef
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		defs = append(defs, scan.PortDef{Port: n, Service: scan.ServiceName(n)})
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("no valid ports in --ports")
	}
	return defs, nil
}
