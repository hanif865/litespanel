#!/usr/bin/env bash
#
# LitesPanel mail stack — Postfix (SMTP) + Dovecot (IMAP) + Roundcube (webmail).
#
# Run as root AFTER install.sh:
#     sudo bash setup-mail.sh
#
# Wires into the panel's email accounts: mailboxes created in the panel become
# real IMAP mailboxes you can log into via Roundcube at /webmail.
#
# NOTE: Sending to the wider internet (Gmail, etc.) also needs correct DNS
# (MX, SPF, DKIM, PTR) and an unblocked port 25 — those are outside this script.
#
set -euo pipefail

PHP_VER="${PANEL_PHP_FPM_VERSION:-8.3}"
RC_VERSION="1.6.9"
RC_DIR="/usr/share/roundcube"
ENV_FILE="/etc/litespanel.env"
MYHOST="$(hostname -f 2>/dev/null || hostname)"

# Read a KEY=value from the panel env file (relay creds can live there so the
# admin just edits the file and re-runs — sudo won't pass them via environment).
env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }

BOLD="\033[1m"; GREEN="\033[32m"; BLUE="\033[34m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
step() { echo -e "\n${BLUE}${BOLD}==>${RESET} ${BOLD}$1${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}!${RESET} $1"; }
die()  { echo -e "${RED}${BOLD}✗ $1${RESET}"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash setup-mail.sh"
export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
step "Installing Postfix, Dovecot, Roundcube dependencies"
debconf-set-selections <<< "postfix postfix/mailname string ${MYHOST}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt-get update -qq
apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    ssl-cert \
    "php${PHP_VER}-imap" "php${PHP_VER}-mbstring" "php${PHP_VER}-xml" \
    "php${PHP_VER}-intl" "php${PHP_VER}-zip" "php${PHP_VER}-gd" "php${PHP_VER}-mysql" \
    wget tar >/dev/null
ok "packages installed"

# --------------------------------------------------------------------------
step "Creating the vmail user and mailbox store"
groupadd -g 5000 vmail 2>/dev/null || true
id vmail >/dev/null 2>&1 || useradd -r -g vmail -u 5000 -d /var/mail -s /usr/sbin/nologin vmail
mkdir -p /var/mail/vhosts
chown -R vmail:vmail /var/mail/vhosts
touch /etc/dovecot/users
chown root:dovecot /etc/dovecot/users 2>/dev/null || true
chmod 640 /etc/dovecot/users
ok "/var/mail/vhosts ready"

# --------------------------------------------------------------------------
step "Setting up the TLS certificate for mail clients"
# External mail clients (Thunderbird, phone, Outlook) connect over TLS, so
# Dovecot (993/995) and Postfix (465/587) both need a certificate + key. We use
# Debian's ssl-cert "snakeoil" self-signed pair: it exists on every box (the
# ssl-cert package regenerates it), and the `ssl-cert` group model lets the
# postfix daemon read the private key without loosening its permissions.
#
# Caveat: one cert can't match every mail.<domain> a multi-tenant box serves, so
# clients see a name-mismatch warning and accept once. A real per-domain cert
# (Let's Encrypt) would remove it, but that's out of scope for this one-shot.
SSL_CERT=/etc/ssl/certs/ssl-cert-snakeoil.pem
SSL_KEY=/etc/ssl/private/ssl-cert-snakeoil.key
[ -f "$SSL_CERT" ] || make-ssl-cert generate-default-snakeoil --force-overwrite >/dev/null 2>&1 || true
# Postfix's smtpd runs as the postfix user; add it to ssl-cert so it can read the
# key. (Dovecot reads the key as root at startup, so it needs no extra group.)
adduser postfix ssl-cert >/dev/null 2>&1 || true
ok "TLS cert ready (${SSL_CERT})"

# --------------------------------------------------------------------------
step "Preparing webmail single sign-on (Dovecot master user)"
# The panel's "Check Email" button opens a mailbox in Roundcube already logged
# in. The panel never stores the mailbox password, so it can't hand one over.
# Instead we create ONE privileged Dovecot "master" account: the panel signs a
# short-lived token naming the mailbox, and Roundcube's panel_sso plugin logs in
# as "<address>*panelsso" with the master password. Dovecot's master passdb
# authorizes that as the target user without their password.
SSO_MASTER_USER="panelsso"
# Fresh secret + master password each run; both sides (Dovecot, Roundcube plugin,
# panel env) are rewritten together below, so they always stay in lock-step.
SSO_MASTER_PASS="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
SSO_SECRET="$(openssl rand -hex 32)"
umask 077
printf '%s:%s\n' "$SSO_MASTER_USER" "$(doveadm pw -s SHA512-CRYPT -p "$SSO_MASTER_PASS")" \
    > /etc/dovecot/master-users
chown root:dovecot /etc/dovecot/master-users 2>/dev/null || true
chmod 640 /etc/dovecot/master-users
ok "master user '${SSO_MASTER_USER}' created"

# --------------------------------------------------------------------------
step "Configuring Dovecot (IMAP + POP3 + LMTP, TLS, passwd-file auth)"
[ -f /etc/dovecot/dovecot.conf.orig ] || cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig 2>/dev/null || true
cat > /etc/dovecot/dovecot.conf <<'EOF'
# Managed by LitesPanel setup-mail.sh
protocols = imap pop3 lmtp
# Listen on all interfaces so phones and desktop clients can connect over TLS.
listen = *, ::
log_path = /var/log/dovecot.log
auth_mechanisms = plain login
# Only accept plaintext logins over an encrypted (TLS) or loopback connection.
# Loopback counts as secured, so Roundcube on localhost still authenticates.
disable_plaintext_auth = yes

# TLS for the imaps/pop3s ports and STARTTLS on 143/110. Snakeoil self-signed —
# clients get a one-time name-mismatch prompt (see the cert note above).
ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2

mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000

namespace inbox {
  inbox = yes
}

passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}
# Master user for webmail single sign-on: a login of "user@domain*panelsso" with
# the master password authenticates as user@domain. Used only by the panel's
# Check Email button (panel_sso plugin) — normal logins never touch this.
auth_master_user_separator = *
passdb {
  driver = passwd-file
  args = /etc/dovecot/master-users
  master = yes
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}

# IMAP: 143 (STARTTLS) + 993 (implicit SSL/TLS).
service imap-login {
  inet_listener imap  { port = 143 }
  inet_listener imaps { port = 993
    ssl = yes
  }
}
# POP3: 110 (STARTTLS) + 995 (implicit SSL/TLS).
service pop3-login {
  inet_listener pop3  { port = 110 }
  inet_listener pop3s { port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
systemctl restart dovecot
ok "Dovecot configured (IMAP 143/993, POP3 110/995, TLS on)"

# --------------------------------------------------------------------------
step "Configuring Postfix (virtual mailbox delivery via Dovecot LMTP)"
touch /etc/postfix/vhost_domains        # panel appends hosted domains here
postconf -e "myhostname = ${MYHOST}"
postconf -e "virtual_mailbox_domains = /etc/postfix/vhost_domains"
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "virtual_mailbox_base = /var/mail/vhosts"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
# TLS: present the same snakeoil cert to clients so submission (587 STARTTLS)
# and smtps (465 implicit TLS) can encrypt. `may` = opportunistic on port 25.
postconf -e "smtpd_tls_cert_file = ${SSL_CERT}"
postconf -e "smtpd_tls_key_file = ${SSL_KEY}"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"
# Enable the submission port (587) for authenticated sending from webmail/clients.
if ! postconf -M submission/inet >/dev/null 2>&1; then
    postconf -M "submission/inet=submission inet n - y - - smtpd"
    postconf -P "submission/inet/syslog_name=postfix/submission"
    postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
    postconf -P "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
fi
# Enable smtps (465) — implicit-TLS submission that phone/desktop clients default
# to. wrappermode wraps the whole connection in TLS from the first byte.
if ! postconf -M smtps/inet >/dev/null 2>&1; then
    postconf -M "smtps/inet=smtps inet n - y - - smtpd"
    postconf -P "smtps/inet/syslog_name=postfix/smtps"
    postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
    postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
    postconf -P "smtps/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
fi
# Optional SMTP relay (smarthost) for outbound mail. When these env vars are
# set, Postfix sends outbound mail through the relay (e.g. Zoho, SendGrid,
# Mailgun, SES) instead of directly to the recipient's MX. Solves the "port 25
# blocked by VPS provider" + "no IP reputation" problem — relay uses 587/465
# (never blocked) and its own established reputation. If unset, direct delivery.
RELAY_HOST="${PANEL_SMTP_RELAY_HOST:-$(env_get PANEL_SMTP_RELAY_HOST)}"
RELAY_USER="${PANEL_SMTP_RELAY_USER:-$(env_get PANEL_SMTP_RELAY_USER)}"
RELAY_PASS="${PANEL_SMTP_RELAY_PASS:-$(env_get PANEL_SMTP_RELAY_PASS)}"
if [ -n "$RELAY_HOST" ] && [ -n "$RELAY_USER" ] && [ -n "$RELAY_PASS" ]; then
    postconf -e "relayhost = ${RELAY_HOST}"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_tls_security_level = encrypt"
    # Write credentials to the sasl_passwd map (hashed, postfix-only readable).
    echo "${RELAY_HOST} ${RELAY_USER}:${RELAY_PASS}" > /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    rm -f /etc/postfix/sasl_passwd  # keep only the .db
    ok "SMTP relay configured (${RELAY_HOST})"
else
    # No relay configured — direct delivery to recipient MX (needs open port 25).
    postconf -e "relayhost ="
    ok "Direct mail delivery (no relay)"
fi
systemctl restart postfix
ok "Postfix configured (submission 587 + smtps 465, TLS on)"

# --------------------------------------------------------------------------
step "Installing OpenDKIM (signs outgoing mail)"
# OpenDKIM signs every outbound message with the per-domain key the panel
# generates in Email Deliverability. Without it the published DKIM DNS record
# is inert and Gmail/Outlook mark the mail unsigned. The panel appends each
# domain to KeyTable/SigningTable when its DKIM record is created; here we lay
# down the daemon, its tables and the Postfix milter wiring once.
apt-get install -y -qq opendkim opendkim-tools >/dev/null
mkdir -p /etc/opendkim/keys
# The keys the panel writes live under /etc/opendkim/keys/<domain>/ — opendkim
# runs as its own user, so it must own that tree to read the private keys.
chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || true
chmod 750 /etc/opendkim /etc/opendkim/keys 2>/dev/null || true

# TrustedHosts: hosts opendkim signs *for* (and won't verify). Localhost only —
# this box relays its own domains' mail, nothing external.
[ -f /etc/opendkim/TrustedHosts ] || cat > /etc/opendkim/TrustedHosts <<'EOF'
127.0.0.1
localhost
::1
EOF
# KeyTable / SigningTable start empty; the panel appends one line per domain.
touch /etc/opendkim/KeyTable /etc/opendkim/SigningTable
chown opendkim:opendkim /etc/opendkim/TrustedHosts /etc/opendkim/KeyTable /etc/opendkim/SigningTable 2>/dev/null || true

cat > /etc/opendkim.conf <<'EOF'
# Managed by LitesPanel setup-mail.sh
Syslog                  yes
UMask                   007
Mode                    sv
Canonicalization        relaxed/simple
SubDomains              no
OversignHeaders         From
AutoRestart             yes
AutoRestartRate         10/1M
Socket                  inet:8891@localhost
PidFile                 /run/opendkim/opendkim.pid
UserID                  opendkim
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
EOF

systemctl enable opendkim >/dev/null 2>&1 || true
systemctl restart opendkim || warn "opendkim did not start — check 'journalctl -u opendkim'"

# Wire OpenDKIM into Postfix as a milter (both SMTP and internal/submission).
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:8891"
postconf -e "non_smtpd_milters = inet:localhost:8891"
systemctl restart postfix
ok "OpenDKIM signing enabled"

# --------------------------------------------------------------------------
step "Installing Rspamd (spam filtering)"
# Rspamd scans inbound mail and tags spam. It runs as a SECOND Postfix milter,
# chained AFTER OpenDKIM (inet:localhost:8891) so DKIM signing is untouched — we
# only append Rspamd's milter (inet:localhost:11332) to smtpd_milters. v1 is
# tag-only: reject is disabled, so spam is only headered/subject-tagged and never
# bounced (there's no Junk folder yet). The panel's Spam Filters page tunes
# per-domain thresholds and allow/block lists under /etc/rspamd/litespanel/.
if apt-get install -y -qq rspamd >/dev/null 2>&1; then
    mkdir -p /etc/rspamd/local.d /etc/rspamd/litespanel

    # tag-only: reject disabled -> spam is never rejected at SMTP, only tagged.
    cat > /etc/rspamd/local.d/actions.conf <<'EOF'
# Managed by LitesPanel setup-mail.sh - tag-only spam filtering.
# reject is disabled so spam is NEVER rejected at SMTP; it is only tagged.
reject = null;
add_header = 6;
rewrite_subject = 6;
greylist = null;
EOF

    # Emit X-Spam* headers on scanned mail so clients/webmail can sort on them.
    cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
# Managed by LitesPanel setup-mail.sh - add X-Spam* headers to scanned mail.
extended_spam_headers = true;
use = ["x-spamd-bar", "x-spam-level", "spam-header", "authentication-results"];
EOF

    # Make the proxy worker (port 11332) scan mail itself and act as a milter.
    cat > /etc/rspamd/local.d/worker-proxy.inc <<'EOF'
# Managed by LitesPanel setup-mail.sh
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
EOF

    systemctl enable --now rspamd >/dev/null 2>&1 || warn "rspamd did not start — check 'journalctl -u rspamd'"

    # Chain Rspamd after OpenDKIM for inbound SMTP. Leave non_smtpd_milters as
    # OpenDKIM-only so locally-generated mail isn't spam-scanned (just signed).
    postconf -e "smtpd_milters = inet:localhost:8891, inet:localhost:11332"
    systemctl restart postfix
    ok "Rspamd spam filtering enabled (tag-only)"
else
    warn "Rspamd install failed — spam filtering not enabled (install later from the panel)"
fi

# --------------------------------------------------------------------------
step "Installing Roundcube ${RC_VERSION}"
if [ ! -f "$RC_DIR/index.php" ]; then
    tmp="$(mktemp -d)"
    wget -q "https://github.com/roundcube/roundcubemail/releases/download/${RC_VERSION}/roundcubemail-${RC_VERSION}-complete.tar.gz" -O "$tmp/rc.tgz" \
        || die "Failed to download Roundcube."
    mkdir -p "$RC_DIR"
    tar xzf "$tmp/rc.tgz" -C "$RC_DIR" --strip-components=1
    rm -rf "$tmp"
fi
mkdir -p "$RC_DIR/temp" "$RC_DIR/logs"
chown -R www-data:www-data "$RC_DIR/temp" "$RC_DIR/logs"

# Roundcube's own MySQL database
RC_DB_PASS="$(openssl rand -base64 18)"
mysql -e "CREATE DATABASE IF NOT EXISTS roundcube CHARACTER SET utf8mb4;"
mysql -e "CREATE USER IF NOT EXISTS 'roundcube'@'localhost' IDENTIFIED BY '${RC_DB_PASS}';"
mysql -e "ALTER USER 'roundcube'@'localhost' IDENTIFIED BY '${RC_DB_PASS}';"
mysql -e "GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost'; FLUSH PRIVILEGES;"
# Import schema on first run (harmless if already present).
mysql roundcube < "$RC_DIR/SQL/mysql.initial.sql" 2>/dev/null || true

DES_KEY="$(openssl rand -base64 24 | cut -c1-24)"
cat > "$RC_DIR/config/config.inc.php" <<EOF
<?php
\$config = [];
\$config['db_dsnw'] = 'mysql://roundcube:${RC_DB_PASS}@localhost/roundcube';
\$config['imap_host'] = 'ssl://localhost:993';
\$config['smtp_host'] = 'ssl://localhost:465';
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['support_url'] = '';
\$config['product_name'] = 'Webmail';
\$config['des_key'] = '${DES_KEY}';
\$config['plugins'] = ['archive', 'zipdownload', 'panel_sso'];
\$config['skin'] = 'elastic';
# Snakeoil is self-signed, so Roundcube (connecting to localhost over TLS) must
# not verify the peer certificate — the hostname won't match and it's local.
\$config['imap_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
\$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
EOF
chown -R www-data:www-data "$RC_DIR/config"
ok "Roundcube installed"

# --------------------------------------------------------------------------
step "Installing the panel_sso Roundcube plugin (Check Email single sign-on)"
# The panel's "Check Email" button redirects to /webmail/?_sso=<token>. This
# plugin verifies the signed token (HMAC with the shared secret) and logs the
# user in as "<address>*panelsso" via the Dovecot master password — so the
# mailbox opens without the panel ever knowing the real password. Modelled on
# Roundcube's bundled `autologon` example. Secret + master creds go in the
# plugin's own config below, in lock-step with Dovecot + the panel env.
PLUGIN_DIR="$RC_DIR/plugins/panel_sso"
mkdir -p "$PLUGIN_DIR"
cat > "$PLUGIN_DIR/panel_sso.php" <<'EOF'
<?php
/**
 * panel_sso — single sign-on for LitesPanel's "Check Email" button.
 *
 * Token: base64url(payload).hmac_sha256_hex, payload = "<address>|<expiry>".
 * Verifies the HMAC, checks expiry, rejects a replayed token, then logs in as
 * "<address>*panelsso" with the Dovecot master password.
 */
class panel_sso extends rcube_plugin
{
    public $noajax = true;

    function init()
    {
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('authenticate', array($this, 'authenticate'));
    }

    function startup($args)
    {
        $token = rcube_utils::get_input_value('_sso', rcube_utils::INPUT_GET);
        if (empty($_SESSION['user_id']) && !empty($token) && $this->verify($token)) {
            $args['action'] = 'login';
        }
        return $args;
    }

    function authenticate($args)
    {
        $token = rcube_utils::get_input_value('_sso', rcube_utils::INPUT_GET);
        if (!empty($token) && ($addr = $this->verify($token))) {
            $rcmail = rcmail::get_instance();
            $args['user'] = $addr . '*' . $rcmail->config->get('panel_sso_master_user');
            $args['pass'] = $rcmail->config->get('panel_sso_master_pass');
            $args['cookiecheck'] = false;
            $args['valid'] = true;
        }
        return $args;
    }

    private function verify($token)
    {
        $this->load_config();
        $secret = rcmail::get_instance()->config->get('panel_sso_secret');
        if (empty($secret)) return false;

        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) return false;
        list($b64, $sig) = $parts;

        $b64 = strtr($b64, '-_', '+/');
        if ($pad = strlen($b64) % 4) $b64 .= str_repeat('=', 4 - $pad);
        $payload = base64_decode($b64, true);
        if ($payload === false) return false;

        $expected = hash_hmac('sha256', $payload, $secret);
        if (!hash_equals($expected, $sig)) return false;

        $bits = explode('|', $payload);
        if (count($bits) !== 2) return false;
        list($addr, $exp) = $bits;
        if (intval($exp) < time()) return false;
        if ($this->seen($sig)) return false;
        return $addr;
    }

    // One-time use: reject a signature already accepted. Nonces live in the RC
    // temp dir with expiry stamps and are pruned on each check.
    private function seen($sig)
    {
        $rcmail = rcmail::get_instance();
        $dir = $rcmail->config->get('temp_dir') ?: sys_get_temp_dir();
        $file = $dir . '/panel_sso_nonces';
        $now = time();
        $keep = array();
        if (is_readable($file)) {
            foreach (explode("\n", (string) file_get_contents($file)) as $line) {
                $row = explode(' ', trim($line), 2);
                if (count($row) === 2 && intval($row[0]) > $now) $keep[$row[1]] = intval($row[0]);
            }
        }
        if (isset($keep[$sig])) return true;
        $keep[$sig] = $now + 120;
        $out = '';
        foreach ($keep as $s => $t) $out .= $t . ' ' . $s . "\n";
        @file_put_contents($file, $out, LOCK_EX);
        return false;
    }
}
EOF
cat > "$PLUGIN_DIR/config.inc.php" <<EOF
<?php
// Managed by LitesPanel setup-mail.sh — SSO shared secret + Dovecot master creds.
\$config['panel_sso_secret'] = '${SSO_SECRET}';
\$config['panel_sso_master_user'] = '${SSO_MASTER_USER}';
\$config['panel_sso_master_pass'] = '${SSO_MASTER_PASS}';
EOF
chown -R www-data:www-data "$PLUGIN_DIR"
chmod 640 "$PLUGIN_DIR/config.inc.php"
ok "panel_sso plugin installed"

# --------------------------------------------------------------------------
step "Adding /webmail to nginx"
# Insert a /webmail location into the panel server block (idempotent).
NGINX_SITE=/etc/nginx/sites-available/litespanel
if ! grep -q "location /webmail" "$NGINX_SITE"; then
    python3 - "$NGINX_SITE" "$PHP_VER" <<'PY'
import sys
site, php = sys.argv[1], sys.argv[2]
block = (
    "    location /webmail {\n"
    "        root /usr/share/;\n"
    "        index index.php;\n"
    "        location ~ ^/webmail/(.+\\.php)$ {\n"
    "            root /usr/share/;\n"
    "            fastcgi_pass unix:/run/php/php%s-fpm.sock;\n"
    "            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n"
    "            include fastcgi_params;\n"
    "        }\n"
    "        location ~ ^/webmail/(config|temp|logs)/ { deny all; }\n"
    "    }\n\n"
) % php
# roundcube dir is /usr/share/roundcube; expose it as /webmail via a symlink.
import os
if not os.path.islink("/usr/share/webmail"):
    try: os.symlink("/usr/share/roundcube", "/usr/share/webmail")
    except FileExistsError: pass
text = open(site).read()
text = text.replace("    location / {", block + "    location / {", 1)
open(site, "w").write(text)
print("patched")
PY
fi
nginx -t >/dev/null 2>&1 && systemctl reload nginx || die "nginx config test failed"
ok "Webmail served at /webmail"

# --------------------------------------------------------------------------
step "Telling the panel about Webmail + SSO"
if ! grep -q '^PANEL_WEBMAIL_URL=' "$ENV_FILE" 2>/dev/null; then
    echo "PANEL_WEBMAIL_URL=/webmail" >> "$ENV_FILE"
fi
# Write (or overwrite) the SSO secret so the panel and Roundcube stay in lock-step.
sed -i '/^PANEL_WEBMAIL_SSO_SECRET=/d' "$ENV_FILE" 2>/dev/null || true
echo "PANEL_WEBMAIL_SSO_SECRET=${SSO_SECRET}" >> "$ENV_FILE"
systemctl restart litespanel
ok "Panel updated"

echo -e "\n${GREEN}${BOLD}  ✓ Mail stack installed.${RESET}"
echo -e "  Webmail:  http(s)://<your-panel>/webmail"
echo -e "  Create mailboxes in the panel (Email Accounts), then log into webmail"
echo -e "  with the full address + password.\n"
echo -e "  ${BOLD}Mail clients${RESET} (Thunderbird / phone / Outlook) — full address + password:"
echo -e "    IMAP  ${BOLD}993${RESET} SSL/TLS   ·   POP3  ${BOLD}995${RESET} SSL/TLS   ·   SMTP  ${BOLD}465${RESET} SSL/TLS"
echo -e "    server ${BOLD}mail.<domain>${RESET} (self-signed cert → accept the one-time warning)"
echo -e "    See each account's ${BOLD}Connect Devices${RESET} page in the panel for exact settings.\n"
if [ -n "$RELAY_HOST" ]; then
    echo -e "  ${GREEN}Outbound mail relays through ${BOLD}${RELAY_HOST}${RESET}${GREEN} — port 25 blocks don't matter.${RESET}"
    echo -e "  ${YELLOW}The relay may require the From domain to be verified on your relay account.${RESET}\n"
else
    echo -e "  ${YELLOW}For internet delivery (Gmail etc.): point the domain's MX here, add SPF/DKIM,${RESET}"
    echo -e "  ${YELLOW}and confirm your host doesn't block outbound port 25.${RESET}"
    echo -e "  ${YELLOW}If port 25 is blocked, use a relay — set these in ${ENV_FILE} and re-run:${RESET}"
    echo -e "    PANEL_SMTP_RELAY_HOST=[smtp.zoho.com]:587"
    echo -e "    PANEL_SMTP_RELAY_USER=you@yourdomain.com   PANEL_SMTP_RELAY_PASS=<app-password>"
    echo -e "  ${YELLOW}(works with Zoho, SendGrid, Mailgun, Amazon SES — any authenticated submission host.)${RESET}\n"
fi
