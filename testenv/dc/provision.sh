#!/usr/bin/env bash
# Provision the Samba AD DC on first start, then run samba in the foreground.
# State lives in named volumes (/var/lib/samba, /etc/samba), so restarts with
# existing volumes skip provisioning entirely.
set -euo pipefail

REALM="LAB.LOCAL"
DOMAIN="LAB"
HOST_NAME="dc01"
ADMINPASS='Lab!Admin#2026'
ALICE_PASS='AlicePass#2026'
KRBTGT_PASS='Krbtgt#Lab2026'
SHARE_NAME="LABSHARE"
SHARE_PATH="/srv/labshare"
SMB_CONF="/etc/samba/smb.conf"
STATE_DIR="/state"

mkdir -p "$STATE_DIR" "$SHARE_PATH"

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
	echo "[provision] no sam.ldb — provisioning realm ${REALM}"

	# samba-tool refuses to overwrite an existing smb.conf
	rm -f "$SMB_CONF"

	samba-tool domain provision \
		--realm="$REALM" \
		--domain="$DOMAIN" \
		--adminpass="$ADMINPASS" \
		--server-role=dc \
		--use-rfc2307 \
		--host-name="$HOST_NAME" \
		--dns-backend=SAMBA_INTERNAL

	# Samba AD defaults to requiring signed/TLS-protected LDAP binds, which
	# goldap's simple bind fails against ("ldap bind (authenticated user
	# required)"). Windows DCs allow simple binds over 389 by default; flip
	# the lab to that behavior so the roast LDAP lookups (kerberoast SPN
	# search, asrep DONT_REQ_PREAUTH search) work over the lab network.
	sed -i 's/^\[global\]/[global]\n   ldap server require strong auth = no/' "$SMB_CONF"
	echo "[provision] smb.conf: ldap server require strong auth = no (Windows-like simple LDAP binds)"

	echo "[provision] creating user alice"
	samba-tool user create alice "$ALICE_PASS"

	# The AD provision registers HOST/* SPNs only; kerberos SMB sessions need
	# cifs/dc01.lab.local tickets to decrypt, and smbd reads secrets.keytab
	# once at startup — so the SPN and keytab entry must exist BEFORE samba
	# starts (adding them later does not work).
	samba-tool spn add cifs/dc01.lab.local DC01\$
	samba-tool domain exportkeytab /var/lib/samba/private/secrets.keytab \
		--principal=cifs/dc01.lab.local
	echo "[provision] added cifs/dc01.lab.local SPN + keytab entry"

	# SPN on alice so kerberoasting has a target in the lab
	samba-tool spn add HTTP/alice.lab.local alice
	echo "[provision] added SPN HTTP/alice.lab.local to alice"

	# Extract alice's NT hash: pdbedit -L -w alice →
	# alice:UID:LMHASH:NTHASH:[U ]:LCT-...
	pdbedit -L -w alice | cut -d: -f4 > "$STATE_DIR/alice.nthash"
	echo "[provision] alice NT hash recorded to /state/alice.nthash"

	# Set krbtgt to a known password, then extract its secrets for the e2e
	# golden-ticket section. Samba realities (verified on bookworm's 4.17):
	#  - setpassword randomizes krbtgt's stored hash on every set (alice/bob
	#    are deterministic), so KRBTGT_PASS is NOT the real password; the
	#    extracted hash below is the authoritative stored value.
	#  - the KDC's krbtgt entry holds AES keys only (no arcfour, even at
	#    provision time), so an RC4 golden ticket forged from the NT hash is
	#    rejected with KRB_AP_ERR_BADKEYVER. The AES256 key is extracted too
	#    (/state/krbtgt.aes256) — the only viable golden path on Samba.
	samba-tool user setpassword krbtgt --newpassword="$KRBTGT_PASS"
	pdbedit -L -w krbtgt | cut -d: -f4 > "$STATE_DIR/krbtgt.nthash"
	echo "[provision] krbtgt NT hash recorded to /state/krbtgt.nthash"

	samba-tool domain exportkeytab /tmp/krbtgt.keytab --principal=krbtgt
	KRBTGT_AES256=$(klist -K -e -k /tmp/krbtgt.keytab | awk '/aes256-cts-hmac-sha1-96/ {gsub(/[()]/, "", $NF); sub(/^0x/, "", $NF); print $NF; exit}')
	if [[ ! "$KRBTGT_AES256" =~ ^[0-9a-f]{64}$ ]]; then
		echo "[provision] ERROR: bad krbtgt AES256 key '$KRBTGT_AES256'" >&2
		exit 1
	fi
	echo "$KRBTGT_AES256" > "$STATE_DIR/krbtgt.aes256"
	rm -f /tmp/krbtgt.keytab
	echo "[provision] krbtgt AES256 key recorded to /state/krbtgt.aes256"

	# Extract the DC machine account's secrets for the e2e silver-ticket
	# section. DC01$ is NOT setpassword'd first: smbd's machine credentials
	# must stay in sync with the secrets.keytab it loaded at startup, and
	# Samba randomizes the stored hash on setpassword anyway (krbtgt note
	# above) — so the hash already in sam.ldb, extracted here, is
	# authoritative. Unlike krbtgt (AES-only), DC01$ holds an arcfour key
	# matching its NT hash (visible in secrets.keytab for DC01$ and
	# cifs/dc01.lab.local alike), so an RC4 silver ticket forged from this
	# NT hash decrypts at the service. The AES256 key is kept too, via the
	# same exportkeytab path as krbtgt.
	pdbedit -L -w 'DC01$' | cut -d: -f4 > "$STATE_DIR/dc01.nthash"
	if [[ ! "$(tr -d '[:space:]' <"$STATE_DIR/dc01.nthash")" =~ ^[0-9A-Fa-f]{32}$ ]]; then
		echo "[provision] ERROR: bad DC01\$ NT hash in $STATE_DIR/dc01.nthash" >&2
		exit 1
	fi
	echo "[provision] DC01\$ NT hash recorded to /state/dc01.nthash"

	samba-tool domain exportkeytab /tmp/dc01.keytab --principal='DC01$'
	DC01_AES256=$(klist -K -e -k /tmp/dc01.keytab | awk '/aes256-cts-hmac-sha1-96/ {gsub(/[()]/, "", $NF); sub(/^0x/, "", $NF); print $NF; exit}')
	if [[ ! "$DC01_AES256" =~ ^[0-9a-f]{64}$ ]]; then
		echo "[provision] ERROR: bad DC01\$ AES256 key '$DC01_AES256'" >&2
		exit 1
	fi
	echo "$DC01_AES256" > "$STATE_DIR/dc01.aes256"
	rm -f /tmp/dc01.keytab
	echo "[provision] DC01\$ AES256 key recorded to /state/dc01.aes256"

	# GPP fixture: a Groups.xml with a cpassword under SYSVOL\Policies for
	# the gpp command (plaintext is "Lab!GPP#2026" — deterministic output of
	# the published GPP AES key at zero IV).
	mkdir -p /var/lib/samba/sysvol/lab.local/Policies
	cat > /var/lib/samba/sysvol/lab.local/Policies/Groups.xml <<'GPPEOF'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2" changed="2024-01-15 08:30:00" uid="{ABCD1234-5678-90AB-CDEF-0123456789AB}">
    <Properties action="U" newName="" description="" cpassword="kWdVT+5RaKyqQvJ5Y/f9vj/X7m+/orgkCGss2H19U9U=" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="LocalAdmin"/>
  </User>
</Groups>
GPPEOF
	echo "[provision] planted GPP fixture (Groups.xml with cpassword)"

	# --- AS-REP roasting setup -------------------------------------------
	# AS-REP roasting (GetNPUsers) needs the KDC to answer AS-REQs carrying
	# no pre-authentication. Samba's embedded Heimdal KDC gates that on
	# THREE switches, not one — third_party/heimdal/kdc/kerberos5.c
	# require_preauth_p() = config->require_preauth ||
	# client->flags.require_preauth || server->flags.require_preauth:
	#  1. config->require_preauth defaults TRUE (kdc/default_config.c) and
	#     is only overridable via [kdc] require-preauth in the krb5.conf
	#     the KDC itself loads — lpcfg_config_path("krb5.conf") =
	#     /etc/samba/krb5.conf, which does not exist by default (the
	#     generated private/krb5.conf is NOT what the KDC reads). Written
	#     below; /etc/samba is a volume, so it persists.
	#  2. client flag: UF_DONT_REQ_PREAUTH (userAccountControl 0x400000)
	#     on the roast target (alice).
	#  3. server flag: the AS-REQ's server principal is krbtgt, and Samba
	#     builds krbtgt's hdb entry with require_preauth=1 (stock UAC
	#     512/514), which alone forces preauth for EVERY AS-REQ. So the
	#     flag must also be set on krbtgt — lab-only (krbtgt is never an
	#     AS client and its ticket keys are unaffected). Side effect:
	#     krbtgt appears in DONT_REQ_PREAUTH scans; its AS-REP fails with
	#     KDC_ERR_CLIENT_NOTYET (krbtgt has AES keys only, the probe
	#     offers rc4-hmac only) — a benign warning.
	# A Windows DC needs only #2; #1 and #3 are Samba-lab concessions,
	# verified empirically against bookworm's samba 4.17.12-Debian (A/B:
	# removing either one brings back KDC_ERR_PREAUTH_REQUIRED), and the
	# resulting AS-REP decrypts with alice's NT hash.
	#
	# No ldb-tools in the image (ldbmodify/ldbsearch absent) and a raw
	# python-ldb open of sam.ldb aborts (TDB mutex requirement), so the
	# modify goes through SamDB, which loads the proper module stack.
	cat >/etc/samba/krb5.conf <<'KRB5EOF'
[libdefaults]
	default_realm = LAB.LOCAL
	dns_lookup_realm = false
	dns_lookup_kdc = false

[kdc]
	require-preauth = no
KRB5EOF
	echo "[provision] wrote /etc/samba/krb5.conf ([kdc] require-preauth = no)"

	python3 - <<'PYEOF'
from samba.samdb import SamDB
from samba.auth import system_session
from samba.param import LoadParm
import ldb
import sys

UF_DONT_REQ_PREAUTH = 0x400000
lp = LoadParm()
lp.load("/etc/samba/smb.conf")
samdb = SamDB(url="/var/lib/samba/private/sam.ldb",
              session_info=system_session(), lp=lp)

def read_uac(dn):
    res = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                       attrs=["userAccountControl"])
    return int(str(res[0]["userAccountControl"]))

def set_dont_req_preauth(dn):
    uac = read_uac(dn)
    if uac & UF_DONT_REQ_PREAUTH:
        return uac
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, dn)
    m["userAccountControl"] = ldb.MessageElement(
        str(uac | UF_DONT_REQ_PREAUTH), ldb.FLAG_MOD_REPLACE,
        "userAccountControl")
    samdb.modify(m)
    return read_uac(dn)

ok = True
for name in ("alice", "krbtgt"):
    uac = set_dont_req_preauth("CN=%s,CN=Users,DC=lab,DC=local" % name)
    stuck = bool(uac & UF_DONT_REQ_PREAUTH)
    ok = ok and stuck
    print("[provision] %s userAccountControl = %d (UF_DONT_REQ_PREAUTH %s)"
          % (name, uac, "set" if stuck else "MISSING"))
sys.exit(0 if ok else 1)
PYEOF
	echo "[provision] DONT_REQ_PREAUTH verified on alice + krbtgt (AS-REP roasting enabled)"

	# Domain SID = krbtgt's SID minus its RID (-502): pdbedit -Lv krbtgt →
	# "User SID: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-502" (space-padded)
	KRBTGT_SID=$(pdbedit -Lv krbtgt | awk '/User SID:/ {print $NF}')
	DOMAIN_SID=${KRBTGT_SID%-*}
	if [[ ! "$DOMAIN_SID" =~ ^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$ ]]; then
		echo "[provision] ERROR: bad domain SID '$DOMAIN_SID' (from '$KRBTGT_SID')" >&2
		exit 1
	fi
	echo "$DOMAIN_SID" > "$STATE_DIR/domain.sid"
	echo "[provision] domain SID recorded to /state/domain.sid ($DOMAIN_SID)"

	cat >>"$SMB_CONF" <<EOF

[$SHARE_NAME]
   path = $SHARE_PATH
   read only = no
   guest ok = no
EOF
	echo "[provision] appended [$SHARE_NAME] to $SMB_CONF"

	mkdir -p "$SHARE_PATH/docs"
	cp /seed/hello.txt "$SHARE_PATH/hello.txt"
	cp /seed/note.txt "$SHARE_PATH/docs/note.txt"
	dd if=/dev/urandom of="$SHARE_PATH/blob.bin" bs=1024 count=256 status=none
	# lab-only: domain users get write access at the POSIX level too
	# (otherwise SMB write fails with ACCESS_DENIED despite "read only = no")
	chmod -R 0777 "$SHARE_PATH"
	(
		cd "$SHARE_PATH"
		sha256sum hello.txt docs/note.txt blob.bin
	) >"$STATE_DIR/seed.sha256"
	echo "[provision] seeded $SHARE_PATH"
else
	echo "[provision] existing sam.ldb found — skipping provision"
fi

echo "[provision] starting samba"
exec samba -i
