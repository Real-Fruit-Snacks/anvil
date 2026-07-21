package scan

// AD CS web-enrollment probe — ESC8 surface discovery.
//
// AD Certificate Services offers an optional web-enrollment role: an ASP
// application at /certsrv/ on the CA host (or a dedicated enrollment
// server) that lets domain users request certificates over HTTP. That
// endpoint is the relay target for ESC8. IIS protects it with an HTTP
// 401 challenge, historically offering NTLM (and Negotiate, which falls
// back to NTLM) — and NTLM authentication to an HTTP service can be
// relayed. An attacker who coerces a machine account's authentication
// (PetitPotam, the printer bug, ...) relays it to /certsrv/, enrolls a
// certificate as the victim machine, and holds persistent credentials
// for that account — domain admin when the victim is a DC. That is WHY
// an unauthenticated scanner probes this path: the 401 challenge itself,
// and the schemes it offers, are the finding. The probe sends no
// credentials and never completes an authentication.
//
// The verdict comes from the status line and headers of one GET per URL;
// redirects are never followed (IIS answers /certsrv with a redirect to
// the trailing-slash form, which is why the URL already carries it) and
// the body is drained only to close the connection cleanly.

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxCertsrvBody caps how much of a /certsrv/ response body is drained
// before the connection is closed. The classification never reads the
// body; the copy exists so a keep-alive server finishes its write and
// the socket closes without a RST, bounded so a hostile peer cannot make
// the scan chew on an endless stream.
const maxCertsrvBody = 4096

// probeADCS checks target for the AD CS web-enrollment endpoint. p443
// gates the https:// attempt and p80 the http:// one; when both ports
// are open HTTPS is tried first and HTTP only if HTTPS shows the
// endpoint absent or fails outright, so URL records the scheme that
// actually presented /certsrv/ — relevant context, since enrollment
// over HTTPS with extended protection is what blunts the ESC8 relay.
// target is interpolated into the URL verbatim (bare host in normal
// scans, host:port when pointing at a nonstandard listener).
//
// Verdict rules: the first URL answering with the endpoint present wins
// and sets WebEnrollment/URL/AuthSchemes. If every attempted URL fails
// at transport level, Error carries the first failure. If at least one
// URL answered but none showed enrollment, the service is simply absent
// — Probed, not an error. With neither port open nothing was probed and
// Probed stays false.
func probeADCS(target string, p80, p443 bool, timeout time.Duration) *ADCSInfo {
	var urls []string
	if p443 {
		urls = append(urls, "https://"+target+"/certsrv/")
	}
	if p80 {
		urls = append(urls, "http://"+target+"/certsrv/")
	}
	if len(urls) == 0 {
		return &ADCSInfo{}
	}

	info := &ADCSInfo{Probed: true}
	var firstErr error
	answered := false

	for _, u := range urls {
		status, header, err := getCertsrv(u, timeout)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		answered = true
		if present, schemes := classifyCertsrv(status, header); present {
			info.WebEnrollment = true
			info.URL = u
			info.AuthSchemes = schemes
			return info
		}
	}

	if !answered && firstErr != nil {
		info.Error = firstErr.Error()
	}
	return info
}

// getCertsrv issues the single GET one URL is allowed and returns the
// status code and response headers with the body drained and closed.
func getCertsrv(url string, timeout time.Duration) (int, http.Header, error) {
	client := &http.Client{
		Timeout: timeout,
		// ErrUseLastResponse surfaces 3xx responses instead of following
		// them: one request per URL, and a redirect is itself a verdict
		// (not enrollment at this exact path).
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if strings.HasPrefix(url, "https://") {
		// Certificates are harvested, not trust-validated: /certsrv/ is
		// typically served with a cert from the AD-internal PKI (or
		// self-signed) that this client has no reason to trust out of
		// band, and the verdict needs only the HTTP status and headers.
		// Same capture-not-validate posture as the TLS certificate
		// harvest (TLSInfo in profile.go).
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCertsrvBody))
	return resp.StatusCode, resp.Header, nil
}

// classifyCertsrv decides from one response whether /certsrv/ is the AD
// CS web-enrollment application:
//
//   - 401 — present. The enrollment pages require authentication, so a
//     challenge on this exact path is the IIS-hosted app; schemes are
//     lifted from the WWW-Authenticate headers. NTLM in that list is the
//     ESC8 relay surface.
//   - 200 — present, schemes nil. The enrollment pages answering
//     anonymously is NOT the default configuration (a stock install
//     challenges); anonymous reachability of certificate enrollment is
//     itself a notable misconfiguration.
//   - 404 — absent.
//   - anything else (3xx, 403, 5xx) — not proof of the enrollment app;
//     treated as absent.
func classifyCertsrv(statusCode int, header http.Header) (present bool, schemes []string) {
	switch statusCode {
	case http.StatusUnauthorized:
		return true, parseAuthSchemes(header.Values("WWW-Authenticate"))
	case http.StatusOK:
		return true, nil
	default:
		return false, nil
	}
}

// parseAuthSchemes reduces WWW-Authenticate header values to bare scheme
// names, deduplicated case-insensitively (RFC 7235 schemes are
// case-insensitive tokens) in first-seen order, keeping the first form
// seen. Auth-params are stripped at the first space ("Basic realm=..."
// → "Basic"). Values are not split on commas: a comma-separated
// challenge list within one header line is genuinely ambiguous to
// tokenize (commas are legal inside auth-params too), and IIS — the
// only server that hosts /certsrv/ — sends one challenge per header
// line.
func parseAuthSchemes(values []string) []string {
	var schemes []string
	seen := map[string]bool{}
	for _, v := range values {
		token := v
		if i := strings.IndexByte(token, ' '); i >= 0 {
			token = token[:i]
		}
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if key := strings.ToLower(token); !seen[key] {
			seen[key] = true
			schemes = append(schemes, token)
		}
	}
	return schemes
}
