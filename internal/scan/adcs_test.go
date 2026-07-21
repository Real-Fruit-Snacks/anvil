package scan

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyCertsrv(t *testing.T) {
	hdr := func(values ...string) http.Header {
		h := http.Header{}
		for _, v := range values {
			h.Add("WWW-Authenticate", v)
		}
		return h
	}

	cases := []struct {
		name        string
		statusCode  int
		header      http.Header
		wantPresent bool
		wantSchemes []string
	}{
		{
			// The ESC8 verdict: challenged enrollment endpoint offering NTLM.
			"401 with single NTLM challenge",
			http.StatusUnauthorized, hdr("NTLM"),
			true, []string{"NTLM"},
		},
		{
			// IIS sends one challenge per header line; first-seen order
			// is preserved so the reported list reads like the wire.
			"401 with multiple scheme headers keeps wire order",
			http.StatusUnauthorized, hdr("Negotiate", "NTLM"),
			true, []string{"Negotiate", "NTLM"},
		},
		{
			"401 basic with realm reduced to bare scheme",
			http.StatusUnauthorized, hdr(`Basic realm="dc01.lab.local"`),
			true, []string{"Basic"},
		},
		{
			"401 duplicate schemes deduped to first occurrence",
			http.StatusUnauthorized, hdr("NTLM", "Negotiate", "NTLM"),
			true, []string{"NTLM", "Negotiate"},
		},
		{
			// RFC 7235 tokens are case-insensitive; the first form seen
			// is the one kept.
			"401 dedup is case-insensitive keeping first form",
			http.StatusUnauthorized, hdr("ntlm", "NTLM"),
			true, []string{"ntlm"},
		},
		{
			"401 blank challenge values are skipped",
			http.StatusUnauthorized, hdr("", "   ", "NTLM"),
			true, []string{"NTLM"},
		},
		{
			// A bare 401 with no challenge headers still proves the app
			// is there; schemes come back nil, not an empty slice.
			"401 without challenge headers is still presence",
			http.StatusUnauthorized, hdr(),
			true, nil,
		},
		{
			// Anonymous 200 on the enrollment pages: non-default, and a
			// finding in its own right.
			"200 is anonymous enrollment with no schemes",
			http.StatusOK, nil,
			true, nil,
		},
		{
			"404 means the endpoint is absent",
			http.StatusNotFound, nil,
			false, nil,
		},
		{
			"403 forbidden is not proof of the enrollment app",
			http.StatusForbidden, nil,
			false, nil,
		},
		{
			// The client never follows redirects, and a redirect off the
			// path is not enrollment at this URL.
			"302 redirect is not enrollment",
			http.StatusFound, nil,
			false, nil,
		},
		{
			"500 server error is not presence",
			http.StatusInternalServerError, nil,
			false, nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, schemes := classifyCertsrv(tc.statusCode, tc.header)
			if present != tc.wantPresent {
				t.Errorf("present = %v, want %v", present, tc.wantPresent)
			}
			if !slices.Equal(schemes, tc.wantSchemes) {
				t.Errorf("schemes = %v, want %v", schemes, tc.wantSchemes)
			}
		})
	}
}

func TestProbeADCS(t *testing.T) {
	// certsrvHandler answers /certsrv/ with the given status and
	// challenges, counting requests so tests can assert the one-GET-per-
	// URL discipline. Any other path 404s.
	certsrvHandler := func(count *atomic.Int32, status int, challenges ...string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/certsrv/" {
				http.NotFound(w, r)
				return
			}
			count.Add(1)
			for _, c := range challenges {
				w.Header().Add("WWW-Authenticate", c)
			}
			w.WriteHeader(status)
		})
	}

	t.Run("401 NTLM challenge over http reports web enrollment", func(t *testing.T) {
		var count atomic.Int32
		srv := httptest.NewServer(certsrvHandler(&count, http.StatusUnauthorized, "NTLM"))
		defer srv.Close()
		target := strings.TrimPrefix(srv.URL, "http://")

		info := probeADCS(target, true, false, 5*time.Second)

		if !info.Probed {
			t.Error("Probed = false, want true")
		}
		if info.Error != "" {
			t.Errorf("Error = %q, want empty", info.Error)
		}
		if !info.WebEnrollment {
			t.Error("WebEnrollment = false, want true")
		}
		if want := "http://" + target + "/certsrv/"; info.URL != want {
			t.Errorf("URL = %q, want %q", info.URL, want)
		}
		if !slices.Equal(info.AuthSchemes, []string{"NTLM"}) {
			t.Errorf("AuthSchemes = %v, want [NTLM]", info.AuthSchemes)
		}
		if n := count.Load(); n != 1 {
			t.Errorf("server saw %d requests, want exactly 1", n)
		}
	})

	t.Run("self-signed https 401 is accepted and reports schemes", func(t *testing.T) {
		var count atomic.Int32
		// NewTLSServer's certificate is self-signed: this passing proves
		// the harvest-not-validate TLS config is in effect.
		srv := httptest.NewTLSServer(certsrvHandler(&count, http.StatusUnauthorized, "Negotiate", "NTLM"))
		defer srv.Close()
		target := strings.TrimPrefix(srv.URL, "https://")

		info := probeADCS(target, false, true, 5*time.Second)

		if !info.WebEnrollment {
			t.Errorf("WebEnrollment = false, want true (Error = %q)", info.Error)
		}
		if want := "https://" + target + "/certsrv/"; info.URL != want {
			t.Errorf("URL = %q, want %q", info.URL, want)
		}
		if !slices.Equal(info.AuthSchemes, []string{"Negotiate", "NTLM"}) {
			t.Errorf("AuthSchemes = %v, want [Negotiate NTLM]", info.AuthSchemes)
		}
		if n := count.Load(); n != 1 {
			t.Errorf("server saw %d requests, want exactly 1", n)
		}
	})

	t.Run("404 reports endpoint absent without error", func(t *testing.T) {
		var count atomic.Int32
		srv := httptest.NewServer(certsrvHandler(&count, http.StatusNotFound))
		defer srv.Close()
		target := strings.TrimPrefix(srv.URL, "http://")

		info := probeADCS(target, true, false, 5*time.Second)

		if !info.Probed {
			t.Error("Probed = false, want true")
		}
		if info.Error != "" {
			t.Errorf("Error = %q, want empty — an answering server is not an error", info.Error)
		}
		if info.WebEnrollment {
			t.Error("WebEnrollment = true, want false for 404")
		}
	})

	t.Run("https failure falls back to http without an error", func(t *testing.T) {
		var count atomic.Int32
		// Plain-HTTP server probed with both ports "open": the https GET
		// dies in the TLS handshake (transport error), the http GET then
		// answers 401. Proves 443-first ordering, fallback, and that a
		// transport error alongside an answering URL yields no Error.
		srv := httptest.NewServer(certsrvHandler(&count, http.StatusUnauthorized, "NTLM"))
		defer srv.Close()
		target := strings.TrimPrefix(srv.URL, "http://")

		info := probeADCS(target, true, true, 5*time.Second)

		if !info.WebEnrollment {
			t.Errorf("WebEnrollment = false, want true after fallback (Error = %q)", info.Error)
		}
		if want := "http://" + target + "/certsrv/"; info.URL != want {
			t.Errorf("URL = %q, want the http fallback %q", info.URL, want)
		}
		if info.Error != "" {
			t.Errorf("Error = %q, want empty once any URL answered", info.Error)
		}
		// The TLS handshake fails before any HTTP request is sent, so
		// the handler only ever sees the single http GET.
		if n := count.Load(); n != 1 {
			t.Errorf("server saw %d requests, want exactly 1", n)
		}
	})

	t.Run("all URLs failing transport-wise records first error", func(t *testing.T) {
		// Loopback port 1 is closed; both schemes fail to connect.
		info := probeADCS("127.0.0.1:1", true, true, 2*time.Second)

		if !info.Probed {
			t.Error("Probed = false, want true")
		}
		if info.Error == "" {
			t.Error("Error = empty, want the dial failure when nothing answered")
		}
		if info.WebEnrollment {
			t.Error("WebEnrollment = true, want false")
		}
	})

	t.Run("neither port open probes nothing", func(t *testing.T) {
		info := probeADCS("192.0.2.1", false, false, time.Second)
		if info.Probed {
			t.Error("Probed = true, want false when no URL was attempted")
		}
	})
}
