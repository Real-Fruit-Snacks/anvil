# Changelog

## Unreleased

## 0.7.0 — the AD CS attack chain

The AD Certificate Services story runs end to end in-tool: detect
(`adenum adcs` flagging ESC1 templates), enroll (`certreq` over
MS-ICPR, enrollee-supplied SANs included), and authenticate
(`gettgt --cert` PKINIT → `connect -k`) — every link verified live
against a Windows Server 2022 CA, including an ESC1-issued cert
authenticating as a different user with no password involved.

- **certreq**: certificate enrollment from the connect shell — `certreq
  <template> [-cn <name>] [-san <upn>] [-ca <host\CA-Name>] [-out
  <file.pem>]` requests a certificate from the domain's enterprise CA
  over MS-ICPR on the session's cert pipe (the CA is discovered via LDAP
  enrollment services; `-ca` overrides). The template is carried per
  MS-WCCE as both a CSR extension and the request's
  `CertificateTemplate` attribute; paired with `adenum adcs` (which flags
  ENROLLEE_SUPPLIES_SUBJECT), `-san <upn>` works the ESC1
  enrollee-supplied-subject path. Output is PEM (issued cert + generated
  key; one openssl line converts to PKCS#12). Samba's CA-less denial is
  asserted in e2e; issuance (baseline User cert + ESC1 SAN cert against
  HACKERBLUEPRINT-CA) is verified manually against the Windows Server
  2022 CA.

- **PKINIT**: `anvil gettgt --cert <file.pem> [-u <user>] -d <domain>
  [--dc-ip <ip>] [-out <ccache>]` turns an issued client certificate
  into a TGT via the RFC 4556 PA-PK-AS exchange (Diffie-Hellman mode
  — the form modern Windows KDCs accept; RSA mode is refused because
  its 3DES reply encryption is unavailable, confirmed live with
  KDC_ERR_ETYPE_NOSUPP): the AS-REQ is signed with the certificate's
  key inside a hand-rolled minimal CMS SignedData — no new
  dependencies. Input is the certreq loot PEM (issued cert + PKCS#8
  key, no password); the client principal defaults to the cert's SAN
  UPN, else the subject CN, with `-u` overriding. Cert/PEM problems
  and KDC denials are themed; the ccache lands through the existing
  gettgt save path. The ESC1 chain is now end-to-end in-tool:
  `adenum adcs` → `certreq -san` → `gettgt --cert` → `connect -k`.
  Samba's KDC trusts no cert we can mint, so e2e asserts the clean
  denial (themed error, non-zero exit, no ccache); the full
  cert→TGT→`connect -k` loop is verified manually against the Windows
  Server 2022 DC with a certreq-issued cert — including an ESC1 SAN
  cert authenticating as a different user without its password.

## 0.6.0 — operator batch and portfwd activation

Day-to-day operating additions across the board: kerberos account
discovery and spraying, offline dumps, ticket minting in-tool, ADCS and
trust enumeration, loot/transcript plumbing, and one-command PortProxy
tunnels.

- **Operator batch**: eight additions for day-to-day engagements.
  `anvil userenum` (kerberos AS-REQ oracle — VALID / VALID_NOPREAUTH /
  INVALID / LOCKED per user, no account state touched) and `anvil spray`
  (one password × user list over kerberos; aborts loudly on the first
  lockout verdict so a thresholded domain can't have accounts locked by
  the run). `anvil gettgt` mints a ccache from password or NT hash
  (TCP/88, RC4-HMAC — no external tools for `connect -k`). Offline
  dumps: `anvil samdump|lsadump|ntdsdump --system <hive>
  --sam/--security/--ntds <hive>` run the live parsers on hives held
  locally, output identical to the live path. In the shell: `whoami`
  (session user + SID + full token groups via LDAP tokenGroups —
  requested in a base-scope read because Samba refuses tokenGroups on a
  subtree search — resolved to names over lsarpc), `trusts` (trustedDomain
  enumeration with MS-ADTS direction/type/attribute rendering), `adenum
  adcs` (certificate-template enumeration; ENROLLEE_SUPPLIES_SUBJECT
  flagged as the ESC1 condition), `loot <dir>` + `--out <file>` on
  samdump/lsadump/dcsync/ntdsdump/kerberoast/asrep (hashcat/secretsdump
  lines to `~/.anvil/loot/<host>/`), and `connect --transcript <file>`
  (tee all session output to a 0600 file, terminal stays live).

- **portfwd activation**: `portfwd add <listen> <connect> --activate`
  takes a PortProxy rule live instead of waiting for a reboot: after
  the registry write the shell checks the target's IPv6 stack over
  winreg (`DisabledComponents` — at `0xff` portproxy rules are inert),
  adds an inbound Windows Firewall rule named `anv-portfwd-<port>` via
  the exec channel, and restarts iphlpsvc. Each step prints one line
  and warns rather than aborting on failure — the firewall warning
  carries a ready-made netsh command, the iphlpsvc one points at a
  manual restart or reboot — and the change tracker records each hop.
  `portfwd remove <listen> --deactivate` unwinds the chain (rule
  removed, firewall rule deleted, iphlpsvc restarted). On Samba the
  registry write lands but every activation step fails with a themed
  warning — no Tcpip6 key, no atsvc on the exec channel, no iphlpsvc
  service — and the session survives.

## 0.5.0 — scan service probes

- **scan service probes**: two more unauthenticated signals, and 80/443
  join the default port set (now 16). TLS cert harvest (636/3389/5986 —
  subject CN, issuer, SANs, expiry with expired/&lt;30-day flagging;
  certs captured, not trust-validated) and an AD CS web-enrollment
  check (unauth GET of `/certsrv/`: 401 + NTLM challenge = ESC8 relay
  candidate hint, anonymous 200 called out, schemes parsed from
  WWW-Authenticate). Both ride probe selection as `tls` and `adcs`.
  Samba's LDAPS cert has a negative serial number, which Go's x509
  rejects at parse time even with InsecureSkipVerify — e2e asserts the
  themed error; the harvest itself (enterprise-CA cert on 636,
  self-signed RDP cert on 3389) is verified manually against the
  Windows Server 2022 DC.

## 0.4.0 — shell operations and unauthenticated attack surface

The SMB shell grows an operations layer (service/task/registry control,
resumable downloads, event logs, session resilience and a write-op audit
trail), and `scan` learns five attack-surface probes plus per-probe
selection.

- **download cwd fix**: `download` resolved relative remote paths against
  the share root instead of the session's current directory — a `cd`
  followed by `download file.txt` missed the file. It now joins the
  client cwd exactly like `ls`/`get`/`find` (found during live Server
  2022 verification; e2e regression added: `cd docs` + `download
  note.txt`).
- **scan probe selection**: `anvil scan --only smb,ldap` whitelists and
  `--skip nullsession,krb` blacklists the phase-2 probes (`smb`, `rpc`,
  `ldap`, `krb`, `nullsession`; both flags together are a usage error).
  The port sweep always runs; a probe fires when its port is open and it
  is selected.
- **scan attack surface**: five new unauthenticated signals riding the
  existing port set. Clock skew from the SMB2 negotiate's SystemTime
  (hint + `--sync-clock` pointer past the 5-minute kerberos tolerance);
  an RPC well-known-UUID table annotating the endpoint dump (SAMR,
  LSARPC, DRSUAPI, SVCCTL, SRVSVC, WKSSVC, NETLOGON, winreg, eventlog,
  TSCH, epmapper — every UUID verified against gopacket/impacket/MS
  specs) with HINTS for exposed coercion interfaces (MS-RPRN PrinterBug,
  MS-EFSR PetitPotam — both its UUIDs, MS-FSRVP ShadowCoerce, MS-DFSNM
  DFSCoerce, MS-PAR PrintNightmare); a kerberos realm probe (one AS-REQ
  for a random nonexistent principal — the KRB-ERROR confirms the KDC
  and carries the realm, no lockout surface); root-DSE extras
  (domain/forest functional levels, SASL mechanisms, forest root from
  the schema context); and a null-session share attempt. The
  null-session probe surfaces a gopacket quirk as signal: pkg/smb
  hardwires RequireMessageSigning and its smb2 aborts anonymous/guest
  sessions, so a server that ACCEPTED the null logon is reported as
  "accepted but blocked by client signing requirement" — itself a
  finding.
- **Service & task management**: `svc <start|stop|config> <name>
  [disabled|demand|auto]` over SVCCTL (start/stop wait for the state
  transition; bare `config` reads start type + state) and `tasks` /
  `taskshow <path>` / `taskrun <path>` / `taskdel <path>` over the TSCH
  pipe `exec` uses — same admin requirement, same themed denial on Samba.
- **Registry writes + search**: `reg set <key> <value> <type> <data>`
  (REG_SZ, REG_EXPAND_SZ, REG_BINARY as hex, REG_DWORD, REG_QWORD,
  REG_MULTI_SZ as `a|b|c`), `reg delvalue`, `reg createkey` (missing
  parents created), `reg delkey`, and `reg search <root> <pattern>
  [maxdepth] [limit]` — all over the session's winreg pipe.
- **Recon without new channels**: `time` (srvsvc NetrRemoteTOD — clock,
  zone, uptime; Samba reports tod_msecs=0 so lab uptime reads 0s),
  `procs` (process list from the registry performance hives — the
  Sysinternals PsList channel, no WMI, world-readable; counter indexes
  resolved from the target's title database with the kernel PerfOS
  registration constants as fallback), and `enumpipes` (union of the IPC$
  NPFS listing, an endpoint-mapper lookup, and CREATE-probes of
  well-known names — load-bearing on Server 2022, where the RPC runtime
  answers `\pipe\samr` & co. without materializing them in either
  listing; categorized against a built-in known-pipe database, and a pipe
  answering access denied is reported as existing-but-denied recon
  signal).
- **Resumable downloads**: `download <remote> <local> [--resume]
  [--restart]` — 64 KiB chunks (a single SMB2 credit), progress state
  under `~/.anvil/downloads/`; resume validates the remote size and
  mtime before continuing.
- **Share search**: `find [start] [-name glob | -regex re] [-i]
  [-size [+|-|=]N<B|KB|MB|GB>] [-newer N] [-older N] [-type file|dir]
  [-maxdepth N] [-limit N] [-timeout d]` — recursive walk of the selected
  share over the existing session (one tree connect, RTT-bound);
  unreadable subdirectories are skipped and a timeout returns partial
  results with a warning.
- **Event logs**: `eventlog list` / `eventlog query <log> [--minutes N]
  [--id N] [--type t] [--source s] [--contains x] [--limit n]` — wevtutil
  runs over the exec channel and the XML is parsed locally, so it
  inherits `exec`'s admin requirement and its Samba denial.
- **PortProxy relay**: `portfwd list|add <listen> <connect>|remove
  <listen>|clear` edits the v4tov4 PortProxy store
  (`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`) in the
  exact layout `netsh interface portproxy` writes; rules activate after
  an iphlpsvc restart or reboot and persist until removed.
- **Session resilience & audit**: `ping` (liveness probe — a srvsvc
  share enum, SMB2 having no echo op), `reconnect` (re-dial with the
  stored connect parameters, re-attaching the selected share), an idle
  keepalive that pings before the first command after five quiet minutes
  (piggybacked on dispatch so the wire is never touched concurrently),
  `changes [--save] [--clear]` (write-op audit of every remote mutation
  attempted — file ops, exec family, registry, svc/tasks/portfwd, AD
  write primitives — with a summary banner at shell exit and JSON save to
  `~/.anvil/logs/changes/`), and `! <cmd>` (local shell escape; `!<n>`
  re-runs history entry n).
- **`connect --sync-clock`**: with `-k`, measures the NTP offset against
  the DC before dialing and stamps kerberos authenticators with server
  time, so a skewed client passes the ±5-minute checks. The gokrb5 fork
  hardcodes `time.Now()`, so the offset is applied where anvil builds
  wire timestamps itself (AP-REQ authenticators) and reply verification's
  Clockskew is widened past the measured offset; ccache flows only —
  password-based `-k` declines to the stock path (its AS exchange is
  library-internal and unreachable).
- **RemoteRegistry handling**: winreg consumers (procs, portfwd, reg,
  hive dumps) lazily start the target's RemoteRegistry service when it is
  demand-stopped and restore its prior state at shell exit.
- **Execution diversity**: four ways to run a command on a target, sharing
  one readback + verified-cleanup pattern — `exec` (TSCH), `psexec`
  (temporary Windows service via SVCCTL, runs as SYSTEM; batch-file
  indirection since a service binary path can't redirect),
  `wmiexec` (Win32_Process.Create over one transient DCOM channel, runs as
  the connected user), `dcomexec` (ShellWindows → ShellBrowserWindow →
  MMC20; hardened servers refuse GUI-class remote activation — impacket
  included — and anvil says so per object). `wmiquery <WQL>` runs WQL over
  the same channel. go-msrpc's global GSSAPI registry panics on
  re-registration, so mechanisms are registered once per process.
- **ACL primitives**: `dacledit` (read/grant/revoke DACL ACEs; presets
  dcsync/fullcontrol/genericall/resetpassword/writedacl/writemembers/
  writeowner) and `owneredit` over one transient LDAP channel. Only the
  touched SD portion is written; Server 2022's DACL canonicalization
  (GENERIC_ALL stored as FULL_CONTROL) is handled.
- **SAMR writes**: `sampasswd` (change-with-old via
  SamrUnicodeChangePasswordUser2 — no LDAP, no admin; enforces policy
  including history) and `samadd`/`samdel` group membership incl. Builtin
  aliases. gopacket's SAMR admin reset (SetInformationUser level 18)
  corrupts accounts on Server 2022 — deliberately not wired.
- **Enumeration**: `lookupsid` — LSA RID brute-force (default 500–4000,
  batched) over the session's lsarpc pipe; resolves a full lab domain in
  ~200 ms. Read-only.
- **Ticket utilities**: `anvil describe <file>` (ccache/kirbi inspector,
  content-sniffed, expiry flagged) and `anvil convert <in> <out>`
  (ccache↔kirbi; round-trip verified against a live KDC).
- **Forward-looking**: `badsuccessor` (dMSA abuse, CVE-2025-53779 —
  request bytes cross-checked against impacket's implementation; clean
  "no dMSA schema" denial pre-2025) and `raisechild` (child→forest-root
  golden ticket with Enterprise Admins SIDHistory; PAC construction
  unit-verified, clean refusal in single-domain forests). Success paths
  need a Server 2025 DC / multi-domain forest respectively.
- **Shell**: exec-family commands (exec/psexec/wmiexec/dcomexec/wmiquery)
  take the verbatim remainder of the line — splitArgs no longer eats
  quotes that are data to the remote side (WQL literals, quoted remote
  commands).
- **Verified against Windows Server 2022**: the full feature matrix was
  exercised against a real Windows DC — dcsync, golden/silver tickets
  with `connect -k`, RBCD + `getst` impersonation, `ntdsdump` (hashes
  match dcsync one-for-one), `samdump`/`lsadump`/`dpapi`, `kerberoast`/
  `asrep`, `exec`, `changepasswd` (both paths, including the first-ever
  verification of change-with-old), `addcomputer`/`delcomputer`.
- **Services enumeration fix**: `services` no longer misattributes
  states. Windows packs REnumServicesStatusW's records immediately after
  the referent — no maxCount/actualCount header — in documented
  [nameOff][displayOff][SERVICE_STATUS] order; the old parse invented the
  header and gave every service the PREVIOUS record's state (~half the
  list inverted on Server 2022) and dropped the first record. The layout
  is sniffed from the first record; Samba's shape still parses.
- **changepasswd error mapping**: an incorrect old password (00000056)
  says so instead of blaming password policy; 0000052D's hint names
  minimum password age as a cause; NUL/control bytes embedded in Windows
  LDAP error text are stripped before printing.
- **Small fixes**: `reg query` rejects surplus arguments (an unquoted
  path with a space silently queried the wrong key); the dpapi summary no
  longer claims "no credential blobs found" when blobs existed but failed
  to decrypt; `exec` task-register failure only says "admin required" for
  access-denied (0x8004131a gets a malformed-XML hint).
- **Light-mode palette**: both Terminal Workbench ramps are now supported
  (THEME-SPEC §6). Dark stays the default; `ANVIL_THEME=light` or a
  `COLORFGBG` light background (7/15) selects the light ramp so colored
  output stays legible on light terminals. `ANVIL_THEME=dark` forces dark.
- **Write primitives**: `changepasswd <user> <new> [old]` — reset an AD
  user's password (admin, replace `unicodePwd`) or change it with the old
  password (delete + add, MS-ADTS 3.1.1.3.1.5) over one transient LDAPS
  channel, falling back to plain LDAP when the TLS handshake fails.

## 0.3.0 — the full arc

The SMB shell grows from a file browser into a complete AD attack toolkit.

- **File management**: `rm`, `mkdir`, `rmdir`, `rename`, `cat` (8 MiB cap).
- **Enumeration**: `shares` with per-share access probing (smbmap-style),
  `sessions` (srvsvc), `users`/`groups`/`members` (SAMR), `loggedon`
  (wkssvc), `services` (SVCCTL), `adenum users|computers|delegation|laps`
  (LDAP).
- **Remote execution**: `exec` via Task Scheduler (TSCH) with verified
  task/output cleanup.
- **Credential access**: `reg query`/`reg save` (WINREG), `samdump` (SAM),
  `lsadump` (LSA secrets + MSCashV2), `dcsync` (DRSUAPI replication),
  `ntdsdump` (VSS shadow copy + offline NTDS.dit), `dpapi` (Credential
  Manager blobs — DPAPI_SYSTEM keys plus password/NT-hash derived
  per-user masterkeys).
- **Kerberos**: `connect -k` (ccache auth), `kerberoast` (RC4 TGS),
  `asrep` (AS-REP roasting), `anvil ticket` (golden/silver forging),
  `anvil getst` (S4U2Self+S4U2Proxy impersonation).
- **Write primitives**: `addcomputer`/`delcomputer` (SAMR + LDAP),
  `rbcd get|set|clear` (msDS-AllowedToActOnBehalfOfOtherIdentity).
- Notable gopacket workarounds discovered en route: the GSS
  channel-binding checksum structure and SMB 3.1.1 preauth-hash pin
  required for kerberos-over-SMB to interop with Samba and Windows.

## 0.2.0 — sessions, polish, and the test lab

- `anvil connect`: authenticated persistent SMB session with interactive
  shell (readline, NTLM / pass-the-hash / null session paths).
- `anvil scan` reports the true max SMB dialect via a proper SMB 3.1.1
  negotiate with preauth-integrity context (with legacy fallback).
- Windows version info + application manifest embedded
  (`goversioninfo`, `--version` flag).
- Docker Samba AD DC test lab (`make env-up` / `make e2e`) with an
  assertion suite covering scan, connect, and pass-the-hash.

## 0.1.0 — first light

- `anvil scan <target>`: unauthenticated AD target profiler — TCP
  reachability of the AD port set, SMB dialect/signing/OS fingerprint,
  RPC endpoint-mapper dump, LDAP posture (signing, channel binding, root
  DSE), and data-driven hints. Terminal Workbench output, JSON mode.
- Cross-platform scaffolding: pure Go, `CGO_ENABLED=0`, Windows + Linux
  builds, Makefile, Terminal Workbench theme.
