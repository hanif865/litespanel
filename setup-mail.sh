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
apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-lmtpd \
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
step "Configuring Dovecot (IMAP + LMTP, passwd-file auth)"
[ -f /etc/dovecot/dovecot.conf.orig ] || cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig 2>/dev/null || true
cat > /etc/dovecot/dovecot.conf <<'EOF'
# Managed by LitesPanel setup-mail.sh
protocols = imap lmtp
listen = 127.0.0.1
log_path = /var/log/dovecot.log
auth_mechanisms = plain login
disable_plaintext_auth = no
ssl = no

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
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
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
ok "Dovecot configured"

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
# Enable the submission port (587) for authenticated sending from webmail/clients.
if ! postconf -M submission/inet >/dev/null 2>&1; then
    postconf -M "submission/inet=submission inet n - y - - smtpd"
    postconf -P "submission/inet/syslog_name=postfix/submission"
    postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
    postconf -P "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
fi
systemctl restart postfix
ok "Postfix configured"

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
\$config['imap_host'] = 'localhost:143';
\$config['smtp_host'] = 'localhost:587';
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['support_url'] = '';
\$config['product_name'] = 'Webmail';
\$config['des_key'] = '${DES_KEY}';
\$config['plugins'] = ['archive', 'zipdownload'];
\$config['skin'] = 'elastic';
\$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
EOF
chown -R www-data:www-data "$RC_DIR/config"
ok "Roundcube installed"

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
step "Telling the panel about Webmail"
if ! grep -q '^PANEL_WEBMAIL_URL=' "$ENV_FILE" 2>/dev/null; then
    echo "PANEL_WEBMAIL_URL=/webmail" >> "$ENV_FILE"
fi
systemctl restart litespanel
ok "Panel updated"

echo -e "\n${GREEN}${BOLD}  ✓ Mail stack installed.${RESET}"
echo -e "  Webmail:  http(s)://<your-panel>/webmail"
echo -e "  Create mailboxes in the panel (Email Accounts), then log into webmail"
echo -e "  with the full address + password.\n"
echo -e "  ${YELLOW}For internet delivery: point the domain's MX at this server, add SPF/DKIM,${RESET}"
echo -e "  ${YELLOW}and confirm your host doesn't block port 25.${RESET}\n"
