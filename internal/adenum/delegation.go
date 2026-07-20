package adenum

import (
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
)

// DelegationRow is one account's delegation configuration. Type is one of
// "unconstrained", "constrained", or "RBCD". Target is the comma-joined SPN
// list for constrained delegation, the resource identity for RBCD, and "N/A"
// for unconstrained.
type DelegationRow struct {
	Name   string
	Type   string
	Target string
}

// Delegation enumerates delegation relationships on the DC over LDAP,
// mirroring gopacket's tools/findDelegation, whose queries live in pkg/ldap's
// FindDelegation. Disabled accounts are excluded, matching the reference
// tool's defaults.
func Delegation(dc string, creds *session.Credentials) ([]DelegationRow, error) {
	client, baseDN, err := connect(dc, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	entries, err := client.FindDelegation(baseDN, false, "")
	if err != nil {
		return nil, fmt.Errorf("delegation search: %v", err)
	}
	return toDelegationRows(entries), nil
}

// toDelegationRows flattens pkg/ldap's entries (one per SPN target) into
// contract rows: one row per (account, delegation type) with targets joined
// by ", ". First-seen order is preserved; duplicate targets collapse.
func toDelegationRows(entries []ldap.DelegationEntry) []DelegationRow {
	type key struct{ name, typ string }

	var order []key
	targets := make(map[key][]string)
	seen := make(map[key]map[string]bool)

	for _, e := range entries {
		k := key{e.AccountName, delegationTypeName(e.DelegationType)}
		if _, ok := targets[k]; !ok {
			order = append(order, k)
			seen[k] = make(map[string]bool)
		}
		if e.DelegationTo == "" || seen[k][e.DelegationTo] {
			continue
		}
		seen[k][e.DelegationTo] = true
		targets[k] = append(targets[k], e.DelegationTo)
	}

	rows := make([]DelegationRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, DelegationRow{
			Name:   k.name,
			Type:   k.typ,
			Target: strings.Join(targets[k], ", "),
		})
	}
	return rows
}

// delegationTypeName maps pkg/ldap's delegation types to the contract values.
// Constrained with protocol transition collapses into "constrained" — the
// contract has no separate value for it.
func delegationTypeName(t ldap.DelegationType) string {
	switch t {
	case ldap.DelegationUnconstrained:
		return "unconstrained"
	case ldap.DelegationConstrainedWithTransition, ldap.DelegationConstrainedWithoutTransition:
		return "constrained"
	case ldap.DelegationResourceBased:
		return "RBCD"
	default:
		return string(t)
	}
}
