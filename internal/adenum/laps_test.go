package adenum

import (
	"regexp"
	"testing"
)

// TestLAPSFilter pins the query to tools/GetLAPSPassword's filter — change
// one and the other must change too.
func TestLAPSFilter(t *testing.T) {
	want := "(&(objectCategory=computer)(objectClass=computer)" +
		"(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))"
	if got := lapsFilter(); got != want {
		t.Errorf("lapsFilter() = %q, want %q", got, want)
	}
}

func TestParseLAPSv2JSON(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"bare object", `{"n":"Administrator","t":"1dd1597e9faef4e","p":"++Jf%0uQs4(amVm@c5K@"}`, "Administrator", "++Jf%0uQs4(amVm@c5K@", true},
		{"trailing metadata", `{"n":"Administrator","t":"1dd","p":"secret"}trailing-junk`, "Administrator", "secret", true},
		{"password containing brace", `{"n":"Administrator","t":"1dd","p":"pa}ss"}`, "Administrator", "pa}ss", true},
		{"not json", "garbage", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass, ok := parseLAPSv2JSON(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && (user != tc.wantUser || pass != tc.wantPass) {
				t.Errorf("got (%q, %q), want (%q, %q)", user, pass, tc.wantUser, tc.wantPass)
			}
		})
	}
}

func TestFormatLAPSExpiry(t *testing.T) {
	for _, in := range []string{"", "0", "notanumber"} {
		if got := formatLAPSExpiry(in); got != "N/A" {
			t.Errorf("formatLAPSExpiry(%q) = %q, want N/A", in, got)
		}
	}

	// 2026-07-20 00:00:00 UTC == FILETIME 134289792000000000. Format is
	// local time, so only the shape is asserted.
	got := formatLAPSExpiry("134289792000000000")
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`).MatchString(got) {
		t.Errorf("formatLAPSExpiry(valid FILETIME) = %q, want YYYY-MM-DD HH:MM:SS", got)
	}
}
