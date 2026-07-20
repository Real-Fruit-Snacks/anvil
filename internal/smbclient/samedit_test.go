package smbclient

import (
	"errors"
	"strings"
	"testing"
)

func TestStripDomainPrefix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare name", "alice", "alice"},
		{"domain qualified", `HACKERBLUEPRINT\alice`, "alice"},
		{"builtin qualified", `BUILTIN\Administrators`, "Administrators"},
		{"machine account", `CORP\WS01$`, "WS01$"},
		{"empty", "", ""},
		{"trailing backslash", `CORP\`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripDomainPrefix(tt.in); got != tt.want {
				t.Errorf("stripDomainPrefix(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMapSAMRError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // substring expected in the mapped message; "" = passthrough
	}{
		{
			name: "access denied",
			err:  errors.New("SamrSetInformationUser failed: NTSTATUS 0xc0000022"),
			want: "Domain Admins",
		},
		{
			name: "no such user",
			err:  errors.New("SamrOpenUser failed: NTSTATUS 0xc0000064"),
			want: "no such user",
		},
		{
			name: "no such group",
			err:  errors.New("SamrOpenGroup failed: NTSTATUS 0xc0000066"),
			want: "no such group",
		},
		{
			name: "already a member of a group",
			err:  errors.New("SamrAddMemberToGroup failed: NTSTATUS 0xc0000067"),
			want: "already a member",
		},
		{
			name: "not a member of a group",
			err:  errors.New("SamrRemoveMemberFromGroup failed: NTSTATUS 0xc0000068"),
			want: "not a member",
		},
		{
			name: "password policy rejection",
			err:  errors.New("SamrSetInformationUser failed: NTSTATUS 0xc000006c"),
			want: "domain policy",
		},
		{
			name: "wrong old password",
			err:  errors.New("SamrUnicodeChangePasswordUser2 failed: NTSTATUS 0xc000006a"),
			want: "old password is incorrect",
		},
		{
			name: "no such alias",
			err:  errors.New("SamrOpenAlias failed: NTSTATUS 0xc0000151"),
			want: "no such local group",
		},
		{
			name: "not a member of an alias",
			err:  errors.New("SamrRemoveMemberFromAlias failed: NTSTATUS 0xc0000152"),
			want: "not a member",
		},
		{
			name: "already a member of an alias",
			err:  errors.New("SamrAddMemberToAlias failed: NTSTATUS 0xc0000153"),
			want: "already a member",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSAMRError(tt.err)
			if !strings.Contains(got.Error(), tt.want) {
				t.Errorf("mapSAMRError(%v) = %q, want substring %q", tt.err, got, tt.want)
			}
			// The original NTSTATUS text is preserved for context.
			if !strings.Contains(got.Error(), tt.err.Error()) {
				t.Errorf("mapSAMRError(%v) = %q, want original text preserved", tt.err, got)
			}
		})
	}

	t.Run("passthrough", func(t *testing.T) {
		err := errors.New("connection refused")
		if got := mapSAMRError(err); got != err {
			t.Errorf("mapSAMRError(%v) = %v, want passthrough", err, got)
		}
	})
}
