package smbclient

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"anvil/internal/ui"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/epmapper"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// PipeInfo is one named pipe found on the server, categorized against the
// built-in known-pipe database (pipedb.go).
type PipeInfo struct {
	Name     string // pipe path relative to \pipe\ ("samr", "sql\query")
	Category string // admin, file, system, database, security-av, terminal, web, virtualization, devops, backup — or "unknown"
	Note     string // short description from the DB; empty for unknown pipes
}

const (
	// pipeMaxDepth caps the recursive IPC$ walk. Real pipe directories are
	// shallow (\pipe\MSSQL$X\sql\query is the deepest common shape); the
	// cap guards against a hostile or broken server presenting cycles.
	pipeMaxDepth = 4
	// pipeMaxEntries caps collected names — same reason.
	pipeMaxEntries = 4096
)

// EnumPipes lists the server's named pipes and categorizes each against
// the known-pipe database. The result is the UNION of three sources, all
// riding the same session:
//
//  1. Recursive directory listing of the IPC$ share root (the classic
//     impacket listPath('IPC$', '*') technique). The NPFS root enumerates
//     the server's materialized pipes, including non-RPC ones (browser
//     crashpad pipes, Docker, agents). IPC$ is mounted directly via the
//     smb2 session and unmounted on return, so the shell's selected share
//     and working directory are untouched.
//  2. RPC endpoint mapper ept_lookup over the session's \pipe\epmapper
//     endpoint, extracting pipe names from ncacn_np bindings. A failure
//     here is non-fatal when the listing worked.
//  3. CREATE-probes of the well-known names in the pipe DB. This is
//     load-bearing on modern Windows, not a fallback: the RPC runtime
//     answers opens of \pipe\samr, \pipe\svcctl, \pipe\lsarpc etc.
//     WITHOUT materializing an NPFS directory entry or an EPM
//     registration — verified on Server 2022, where these names are
//     openable yet invisible to both enumeration paths (even while an
//     RPC client is actively bound). Probing a name is also how a pipe
//     that answers access denied is detected: it exists but rejects the
//     current credentials, which is itself recon signal.
//
// If the listing fails (hardened servers deny QUERY_DIRECTORY on IPC$)
// the EPM + probe results are used; a themed error is returned only when
// nothing could be enumerated at all.
func (s *Session) EnumPipes() ([]PipeInfo, error) {
	names, listErr := s.listPipesIPC()
	epmNames, epmErr := s.listPipesEPM()
	switch {
	case listErr != nil:
		ui.Debugf("enumpipes: IPC$ listing failed: %v", listErr)
		ui.Faint.Println("  IPC$ pipe listing failed — using endpoint mapper + well-known pipe probes")
		names = nil
	case epmErr != nil:
		ui.Debugf("enumpipes: endpoint mapper merge skipped: %v", epmErr)
	}
	names = append(names, epmNames...)

	// Dedupe by normalized name, then probe the DB names the two
	// enumeration paths did not surface.
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[normalizePipeName(n)] = true
	}
	names = append(names, s.probeWellKnownPipes(have)...)

	if len(names) == 0 {
		switch {
		case listErr != nil && epmErr != nil:
			return nil, mapPipesError(fmt.Errorf("IPC$ listing: %v; endpoint mapper: %v", listErr, epmErr), s.null)
		case listErr != nil:
			// Listing failed, EPM saw nothing, and every probe missed —
			// e.g. a null session against a hardened host.
			return nil, mapPipesError(fmt.Errorf("IPC$ listing: %v", listErr), s.null)
		}
		// Both paths worked; the server genuinely shows no pipes.
	}

	seen := make(map[string]bool, len(names))
	pipes := make([]PipeInfo, 0, len(names))
	for _, n := range names {
		key := normalizePipeName(n)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		cat, note := categorizePipe(n)
		pipes = append(pipes, PipeInfo{Name: n, Category: cat, Note: note})
	}
	sort.Slice(pipes, func(i, j int) bool {
		return strings.ToLower(pipes[i].Name) < strings.ToLower(pipes[j].Name)
	})
	return pipes, nil
}

// probeWellKnownPipes CREATE-probes the exact known-pipe DB names absent
// from have (the normalized names already found) and returns the ones
// that answered. Open success means the pipe exists; access denied means
// it exists but rejects the current credentials (reported either way);
// not-found means absent. Transport-level errors are logged and skipped
// — probing must never sink the enumeration.
func (s *Session) probeWellKnownPipes(have map[string]bool) []string {
	var found []string
	for _, kp := range knownPipes {
		if have[kp.name] {
			continue
		}
		f, err := s.client.OpenPipe(kp.name)
		switch {
		case err == nil:
			f.Close()
			found = append(found, kp.name)
		case errors.Is(err, os.ErrPermission):
			found = append(found, kp.name)
		case smb.IsNotFound(err):
			// absent — the common case for third-party product pipes
		default:
			ui.Debugf("enumpipes: probe %s: %v", kp.name, err)
		}
	}
	return found
}

// listPipesIPC walks the IPC$ share root and returns pipe paths relative
// to \pipe\ ("samr", "sql\query"). Directory entries that are themselves
// directories (NPFS supports subdirectories: sql\, MSSQL$X\) are recursed
// into; only leaf entries are pipes.
func (s *Session) listPipesIPC() ([]string, error) {
	sh, err := s.client.Session.Mount("IPC$")
	if err != nil {
		return nil, fmt.Errorf("mount IPC$: %v", err)
	}
	defer sh.Umount()

	var names []string
	if err := walkPipes(sh, "", 0, &names); err != nil {
		return nil, err
	}
	return names, nil
}

// walkPipes collects leaf names under dir ("" = share root) into names.
// Unreadable subdirectories are skipped, not fatal: a single denied
// directory must not sink the whole enumeration.
func walkPipes(sh *smb2.Share, dir string, depth int, names *[]string) error {
	if depth > pipeMaxDepth || len(*names) >= pipeMaxEntries {
		return nil
	}
	entries, err := sh.ReadDir(dir)
	if err != nil {
		if dir == "" {
			return fmt.Errorf("list IPC$ root: %v", err)
		}
		ui.Debugf("enumpipes: skipping unreadable pipe directory %q: %v", dir, err)
		return nil
	}
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			continue
		}
		rel := name
		if dir != "" {
			rel = dir + `\` + name
		}
		if e.IsDir() {
			if err := walkPipes(sh, rel, depth+1, names); err != nil {
				return err
			}
			continue
		}
		*names = append(*names, rel)
		if len(*names) >= pipeMaxEntries {
			return nil
		}
	}
	return nil
}

// listPipesEPM enumerates named pipes via the endpoint mapper's ept_lookup
// over the existing session's \pipe\epmapper endpoint, mirroring the
// unauthenticated TCP variant in internal/scan. Only ncacn_np bindings
// yield pipe names; the result is the set of RPC interfaces that registered
// a pipe endpoint — on Windows typically a subset of the IPC$ listing.
func (s *Session) listPipesEPM() ([]string, error) {
	pipe, err := s.client.OpenPipe("epmapper")
	if err != nil {
		return nil, fmt.Errorf("open epmapper pipe: %v", err)
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(epmapper.UUID, epmapper.MajorVersion, epmapper.MinorVersion); err != nil {
		return nil, fmt.Errorf("bind epmapper: %v", err)
	}

	eps, err := epmapper.NewEpmClient(rpc).Lookup()
	if err != nil {
		return nil, fmt.Errorf("ept_lookup: %v", err)
	}

	seen := make(map[string]bool)
	var names []string
	for _, ep := range eps {
		for _, b := range ep.Bindings {
			name, ok := pipeNameFromBinding(b)
			if !ok {
				continue
			}
			key := strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true
			names = append(names, name)
		}
	}
	return names, nil
}

// pipeNameFromBinding extracts the pipe name from an ncacn_np endpoint
// binding as rendered by pkg/dcerpc/epmapper — "ncacn_np:HOST[\pipe\name]"
// or "ncacn_np:[\pipe\name]" → "name". ok is false for other protocol
// sequences (ncacn_ip_tcp, ncalrpc, ...) or bindings without a pipe part.
func pipeNameFromBinding(binding string) (name string, ok bool) {
	if !strings.HasPrefix(binding, "ncacn_np:") {
		return "", false
	}
	l := strings.IndexByte(binding, '[')
	r := strings.LastIndexByte(binding, ']')
	if l < 0 || r <= l+1 {
		return "", false
	}
	name = strings.ReplaceAll(binding[l+1:r], "/", `\`)
	name = strings.TrimLeft(name, `\`)
	if strings.HasPrefix(strings.ToLower(name), `pipe\`) {
		name = name[len(`pipe\`):]
	}
	if name == "" {
		return "", false
	}
	return name, true
}

// mapPipesError translates the pipe-enumeration failure modes into
// actionable messages (feature-local, like mapPasswordError et al.).
// Both enumeration paths ride the authenticated session, so access
// denied almost always means a null/guest session or hardened IPC$.
func mapPipesError(err error, nullSession bool) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Network Name Not Found"):
		// STATUS_BAD_NETWORK_NAME — no IPC$ share at all (non-Windows SMB).
		return fmt.Errorf("IPC$ share not available on this server")
	case strings.Contains(msg, "0x1c010002"):
		// nca_s_op_rng_error — EPM bound but ept_lookup unimplemented.
		return fmt.Errorf("endpoint mapper lookup not supported on this server")
	case nullSession:
		return fmt.Errorf("pipe enumeration needs credentials — a null session cannot list pipes")
	case strings.Contains(msg, "Access is denied"), // STATUS_ACCESS_DENIED text
		strings.Contains(msg, "0x00000005"), // Win32 ERROR_ACCESS_DENIED
		strings.Contains(msg, "0xc0000022"), // STATUS_ACCESS_DENIED numeric
		os.IsPermission(err):
		return fmt.Errorf("access denied (IPC$ pipe listing requires an authenticated session)")
	case strings.Contains(msg, "i/o timeout"):
		return fmt.Errorf("timed out enumerating pipes")
	}
	return err
}
