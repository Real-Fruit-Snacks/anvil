package cli

import "testing"

func TestRootCommandTree(t *testing.T) {
	names := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"scan", "connect", "ticket"} {
		if !names[want] {
			t.Errorf("root command missing subcommand %q", want)
		}
	}
}

func TestPersistentFlags(t *testing.T) {
	for _, name := range []string{"timeout", "json"} {
		if rootCmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("persistent flag --%s not registered", name)
		}
	}
}

func TestCommandFlags(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		switch c.Name() {
		case "scan":
			if c.Flags().Lookup("ports") == nil {
				t.Error("scan: --ports not registered")
			}
		case "connect":
			for _, name := range []string{"host", "port", "target-ip", "user", "password", "domain", "hashes", "kerberos", "dc-ip", "dc-host"} {
				if c.Flags().Lookup(name) == nil {
					t.Errorf("connect: --%s not registered", name)
				}
			}
		case "ticket":
			for _, name := range []string{"krbtgt", "nthash", "spn", "domain", "domain-sid", "user", "out"} {
				if c.Flags().Lookup(name) == nil {
					t.Errorf("ticket: --%s not registered", name)
				}
			}
		}
	}
}

func TestRewriteTicketArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			"single-dash contract form",
			[]string{"ticket", "-krbtgt", "aa", "-domain", "lab.local", "-domain-sid", "S-1-5-21-1-2-3", "-user", "alice"},
			[]string{"ticket", "--krbtgt", "aa", "--domain", "lab.local", "--domain-sid", "S-1-5-21-1-2-3", "--user", "alice"},
		},
		{
			"single-dash silver form",
			[]string{"ticket", "-nthash", "aa", "-spn", "cifs/dc01.lab.local", "-domain", "lab.local"},
			[]string{"ticket", "--nthash", "aa", "--spn", "cifs/dc01.lab.local", "--domain", "lab.local"},
		},
		{
			"double-dash untouched",
			[]string{"ticket", "--krbtgt", "aa"},
			[]string{"ticket", "--krbtgt", "aa"},
		},
		{
			"equals form",
			[]string{"ticket", "-out=x.ccache"},
			[]string{"ticket", "--out=x.ccache"},
		},
		{
			"shorthands untouched",
			[]string{"ticket", "-h"},
			[]string{"ticket", "-h"},
		},
		{
			"unknown single-dash untouched",
			[]string{"ticket", "-bogus", "x"},
			[]string{"ticket", "-bogus", "x"},
		},
		{
			"double-dash terminator stops rewriting",
			[]string{"ticket", "--", "-krbtgt"},
			[]string{"ticket", "--", "-krbtgt"},
		},
		{
			"other commands untouched",
			[]string{"connect", "--user", "ticket", "-domain", "CORP"},
			[]string{"connect", "--user", "ticket", "-domain", "CORP"},
		},
		{
			"persistent flags before subcommand",
			[]string{"--debug", "ticket", "-krbtgt", "aa"},
			[]string{"--debug", "ticket", "--krbtgt", "aa"},
		},
		{
			"timeout value skipped",
			[]string{"--timeout", "5s", "ticket", "-user", "alice"},
			[]string{"--timeout", "5s", "ticket", "--user", "alice"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := append([]string(nil), tc.in...)
			rewriteTicketArgs(got)
			if len(got) != len(tc.want) {
				t.Fatalf("rewriteTicketArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("rewriteTicketArgs(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
