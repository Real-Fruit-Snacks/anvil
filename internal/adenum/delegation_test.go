package adenum

import (
	"testing"

	"github.com/mandiant/gopacket/pkg/ldap"
)

func TestDelegationTypeName(t *testing.T) {
	cases := []struct {
		in   ldap.DelegationType
		want string
	}{
		{ldap.DelegationUnconstrained, "unconstrained"},
		{ldap.DelegationConstrainedWithoutTransition, "constrained"},
		{ldap.DelegationConstrainedWithTransition, "constrained"},
		{ldap.DelegationResourceBased, "RBCD"},
		{ldap.DelegationType("FutureType"), "FutureType"},
	}
	for _, tc := range cases {
		if got := delegationTypeName(tc.in); got != tc.want {
			t.Errorf("delegationTypeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestToDelegationRows(t *testing.T) {
	entries := []ldap.DelegationEntry{
		{AccountName: "DC01$", AccountType: "Computer", DelegationType: ldap.DelegationUnconstrained, DelegationTo: "N/A"},
		{AccountName: "svc-web", AccountType: "User", DelegationType: ldap.DelegationConstrainedWithoutTransition, DelegationTo: "http/web01.lab.local"},
		{AccountName: "svc-web", AccountType: "User", DelegationType: ldap.DelegationConstrainedWithoutTransition, DelegationTo: "cifs/web01.lab.local"},
		// Duplicate SPN collapses into the same row once.
		{AccountName: "svc-web", AccountType: "User", DelegationType: ldap.DelegationConstrainedWithoutTransition, DelegationTo: "http/web01.lab.local"},
		// Protocol transition still maps to plain "constrained".
		{AccountName: "svc-sql", AccountType: "User", DelegationType: ldap.DelegationConstrainedWithTransition, DelegationTo: "mssql/db01.lab.local"},
		{AccountName: "alice", AccountType: "User", DelegationType: ldap.DelegationResourceBased, DelegationTo: "DC01$"},
		{AccountName: "alice", AccountType: "User", DelegationType: ldap.DelegationResourceBased, DelegationTo: "WEB01$"},
	}

	want := []DelegationRow{
		{Name: "DC01$", Type: "unconstrained", Target: "N/A"},
		{Name: "svc-web", Type: "constrained", Target: "http/web01.lab.local, cifs/web01.lab.local"},
		{Name: "svc-sql", Type: "constrained", Target: "mssql/db01.lab.local"},
		{Name: "alice", Type: "RBCD", Target: "DC01$, WEB01$"},
	}

	got := toDelegationRows(entries)
	if len(got) != len(want) {
		t.Fatalf("toDelegationRows returned %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestToDelegationRowsEmpty(t *testing.T) {
	if rows := toDelegationRows(nil); len(rows) != 0 {
		t.Errorf("toDelegationRows(nil) = %+v, want empty", rows)
	}
}
