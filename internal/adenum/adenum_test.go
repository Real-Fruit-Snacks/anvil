package adenum

import (
	"reflect"
	"testing"
	"time"
)

// The filters are the contract with AD: they must mirror the gopacket
// reference tools (tools/GetADUsers -all, tools/GetADComputers) exactly.
func TestUsersFilter(t *testing.T) {
	want := "(&(sAMAccountName=*)(objectCategory=user))"
	if got := usersFilter(); got != want {
		t.Errorf("usersFilter() = %q, want %q", got, want)
	}
}

func TestComputersFilter(t *testing.T) {
	want := "(&(objectCategory=computer)(objectClass=computer))"
	if got := computersFilter(); got != want {
		t.Errorf("computersFilter() = %q, want %q", got, want)
	}
}

func TestUsersAttributes(t *testing.T) {
	want := []string{"sAMAccountName", "displayName", "adminCount", "pwdLastSet", "lastLogon"}
	if got := usersAttributes(); !reflect.DeepEqual(got, want) {
		t.Errorf("usersAttributes() = %v, want %v", got, want)
	}
}

func TestComputersAttributes(t *testing.T) {
	want := []string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion"}
	if got := computersAttributes(); !reflect.DeepEqual(got, want) {
		t.Errorf("computersAttributes() = %v, want %v", got, want)
	}
}

func TestFormatFileTime(t *testing.T) {
	// 133485408000000000 FILETIME = 1704067200 Unix = 2024-01-01 00:00:00 UTC.
	const ft = "133485408000000000"
	want := time.Unix(1704067200, 0).Format("2006-01-02 15:04:05")

	cases := []struct{ in, want string }{
		{"", "<never>"},
		{"0", "<never>"},
		{"notanumber", "N/A"},
		{ft, want},
	}
	for _, c := range cases {
		if got := formatFileTime(c.in); got != c.want {
			t.Errorf("formatFileTime(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
