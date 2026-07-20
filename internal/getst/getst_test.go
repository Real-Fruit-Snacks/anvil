package getst

import (
	"errors"
	"strings"
	"testing"
)

func TestSPNHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cifs/dc01.lab.local", "dc01.lab.local"},
		{"cifs/dc01.lab.local:445", "dc01.lab.local"},
		{"MSSQLSvc/sql01.corp.local:1433", "sql01.corp.local"},
		{"HTTP/web01", "web01"},
		{"nohost", "nohost"},
	}
	for _, c := range cases {
		if got := SPNHost(c.in); got != c.want {
			t.Errorf("SPNHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNTHalf(t *testing.T) {
	if got := ntHalf("aad3:31d6"); got != "31d6" {
		t.Errorf("ntHalf lm:nt = %q", got)
	}
	if got := ntHalf("31d6"); got != "31d6" {
		t.Errorf("ntHalf bare = %q", got)
	}
	if got := ntHalf(""); got != "" {
		t.Errorf("ntHalf empty = %q", got)
	}
}

func TestDefaultOut(t *testing.T) {
	if got := defaultOut("Administrator", "cifs/dc01.lab.local"); got != "Administrator@cifs_dc01.lab.local.ccache" {
		t.Errorf("defaultOut = %q", got)
	}
}

func TestRunValidation(t *testing.T) {
	base := Options{
		SPN: "cifs/dc01.lab.local", Impersonate: "Administrator",
		Domain: "lab.local", User: "ANVX$", Password: "pw",
	}
	cases := []struct {
		name    string
		mutate  func(*Options)
		wantErr string
	}{
		{"missing spn", func(o *Options) { o.SPN = "" }, "-spn is required"},
		{"missing impersonate", func(o *Options) { o.Impersonate = "" }, "-impersonate is required"},
		{"missing domain", func(o *Options) { o.Domain = "" }, "-d is required"},
		{"missing user", func(o *Options) { o.User = "" }, "-u is required"},
		{"missing creds", func(o *Options) { o.Password = ""; o.Hash = "" }, "password (-p) or --hashes is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mutate(&opts)
			_, err := Run(opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Run error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestMapS4UError(t *testing.T) {
	if got := mapS4UError(errors.New("KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found")).Error(); !strings.Contains(got, "no constrained-delegation rights") {
		t.Errorf("principal mapping = %q", got)
	}
	if got := mapS4UError(errors.New("KDC_ERR_BADOPTION")).Error(); !strings.Contains(got, "delegation not allowed") {
		t.Errorf("badoption mapping = %q", got)
	}
	if got := mapS4UError(errors.New("KDC error code 13: ")).Error(); !strings.Contains(got, "delegation not allowed") {
		t.Errorf("numeric badoption mapping = %q", got)
	}
	if got := mapS4UError(errors.New("boom")); got.Error() != "boom" {
		t.Errorf("passthrough = %q", got)
	}
}
