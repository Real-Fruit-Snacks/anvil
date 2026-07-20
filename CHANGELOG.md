# Changelog

## Unreleased

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
