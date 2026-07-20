package smbclient

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestSMBPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`docs\file.txt`, "docs/file.txt"},
		{`a/b\c`, "a/b/c"},
		{`..\up\here`, "../up/here"},
		{"plain", "plain"},
		{`C:\deep\path`, "C:/deep/path"},
	}
	for _, c := range cases {
		if got := smbPath(c.in); got != c.want {
			t.Errorf("smbPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestXMLEscape(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"amp", "a&b", "a&amp;b"},
		{"lt gt", "<x>", "&lt;x&gt;"},
		{"quot", `"q"`, "&quot;q&quot;"},
		{"apos", "it's", "it&apos;s"},
		{"amp first ordering", "&amp;", "&amp;amp;"},
		{"combined", `a&<b>"'`, "a&amp;&lt;b&gt;&quot;&apos;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := xmlEscape(c.in); got != c.want {
				t.Errorf("xmlEscape(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not exist sentinel", fmt.Errorf("ls: %w", os.ErrNotExist), "no such file or directory"},
		{"permission sentinel", os.ErrPermission, "access denied"},
		{"no share", errors.New("no share selected"), "no share selected — use <share> first"},
		{"not a directory", errors.New("not a directory"), "not a directory"},
		{"bare win32 access denied", errors.New("OpenSCManager failed: 0x00000005"), "access denied"},
		{"rpc op rng", errors.New("RPC Fault: status=0x1c010002"), "not supported on this server (unknown RPC opnum)"},
		{"invalid level", errors.New("NetrSessionEnum failed: NTSTATUS 0x0000007c"), "not supported on this server (invalid level)"},
		{"bad network name", errors.New("response error: {Network Name Not Found}"), "network name not found on the server"},
		{"unknown passthrough", errors.New("something weird happened"), "something weird happened"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Describe(c.err); got != c.want {
				t.Errorf("Describe(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}
