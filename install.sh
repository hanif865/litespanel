#!/usr/bin/env bash
#
# LitesPanel one-command installer.
#
# Run as root on a FRESH Ubuntu 22.04 / 24.04 server:
#
#     sudo bash install.sh                       # serve over HTTP on the server IP
#     sudo bash install.sh panel.example.com     # + auto Let's Encrypt SSL for that domain
#
# It installs and wires up everything a control panel needs:
#   nginx · MySQL · PHP-FPM · certbot · phpMyAdmin · the panel · a systemd service.
#
set -euo pipefail

# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
PANEL_DIR="/opt/litespanel"
DATA_DIR="/var/lib/litespanel"
ENV_FILE="/etc/litespanel.env"
SERVICE="/etc/systemd/system/litespanel.service"
PHP_VER="8.3"
PMA_VERSION="5.2.2"
PMA_DIR="/usr/share/phpmyadmin"
DOMAIN="${1:-}"
REPO="hanif865/litespanel"     # GitHub repo the one-line installer pulls from
BRANCH="main"
# Works whether run from a file or piped via `curl ... | bash` (set -u safe).
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

# --------------------------------------------------------------------------
# Pretty output
# --------------------------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[32m"; BLUE="\033[34m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
step() { echo -e "\n${BLUE}${BOLD}==>${RESET} ${BOLD}$1${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}!${RESET} $1"; }
die()  { echo -e "${RED}${BOLD}✗ $1${RESET}"; exit 1; }

echo -e "${BOLD}${BLUE}"
echo "  ┌─────────────────────────────────────────┐"
echo "  │        LitesPanel  ·  installer         │"
echo "  └─────────────────────────────────────────┘"
echo -e "${RESET}"

# --------------------------------------------------------------------------
# Pre-flight checks
# --------------------------------------------------------------------------
step "Checking environment"
[ "$(id -u)" -eq 0 ] || die "Please run as root:  sudo bash install.sh"

# If the source isn't next to this script (e.g. piped via `curl | bash`),
# fetch it from GitHub so the one-line install works.
if [ ! -d "$SRC_DIR/app" ]; then
    command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl; }
    command -v tar  >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq tar; }
    tmp="$(mktemp -d)"
    echo -e "  downloading source from github.com/${REPO} (${BRANCH})..."
    curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$tmp/src.tgz" \
        || die "Could not download source from GitHub (${REPO})."
    mkdir -p "$tmp/src"
    tar xzf "$tmp/src.tgz" -C "$tmp/src" --strip-components=1
    SRC_DIR="$tmp/src"
fi
[ -d "$SRC_DIR/app" ] || die "Panel source (app/) not found."

if [ -r /etc/os-release ]; then . /etc/os-release; fi
[ "${ID:-}" = "ubuntu" ] || warn "Tested on Ubuntu 22.04/24.04; '${ID:-unknown}' may need tweaks."
SERVER_IP="$(hostname -I | awk '{print $1}')"
ok "OS: ${PRETTY_NAME:-unknown}  ·  IP: ${SERVER_IP}"
[ -n "$DOMAIN" ] && ok "Domain: ${DOMAIN} (SSL will be requested)" || warn "No domain given — HTTP only (add one later for SSL)."

export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# 1. System packages
# --------------------------------------------------------------------------
step "Installing system packages (this takes a few minutes)"
apt-get update -qq
apt-get install -y -qq \
    nginx mysql-server certbot python3-certbot-nginx \
    python3-venv python3-pip \
    "php${PHP_VER}-fpm" "php${PHP_VER}-mysql" "php${PHP_VER}-cli" "php${PHP_VER}-curl" \
    "php${PHP_VER}-gd" "php${PHP_VER}-mbstring" "php${PHP_VER}-xml" "php${PHP_VER}-zip" "php${PHP_VER}-intl" \
    wget curl unzip ufw fail2ban >/dev/null
ok "nginx, MySQL, PHP ${PHP_VER}, certbot, ufw, fail2ban installed"

# Common PHP extensions the PHP Selector enables by default, so a fresh box
# has the usual WordPress/Laravel stack working out of the box. Installed
# best-effort: any package missing from the distro repos is skipped, not fatal.
# The panel's PHP Selector can install more on demand later (admin only).
step "Installing common PHP extensions"
PHP_EXT_PKGS=(
    "php${PHP_VER}-bcmath" "php${PHP_VER}-bz2" "php${PHP_VER}-gmp"
    "php${PHP_VER}-imagick" "php${PHP_VER}-soap" "php${PHP_VER}-xsl"
    "php${PHP_VER}-sqlite3" "php${PHP_VER}-redis" "php${PHP_VER}-igbinary"
    "php${PHP_VER}-opcache" "php${PHP_VER}-readline" "php${PHP_VER}-gettext"
    "php${PHP_VER}-ldap" "php${PHP_VER}-tidy" "php${PHP_VER}-ssh2"
)
for pkg in "${PHP_EXT_PKGS[@]}"; do
    apt-get install -y -qq "$pkg" >/dev/null 2>&1 && echo -e "  ${GREEN}✓${RESET} $pkg" || warn "$pkg not available — skipped"
done
systemctl reload "php${PHP_VER}-fpm" >/dev/null 2>&1 || true
ok "Common PHP extensions installed"


# --------------------------------------------------------------------------
# 2. Panel code + Python environment
# --------------------------------------------------------------------------
step "Installing the panel into ${PANEL_DIR}"
mkdir -p "$PANEL_DIR" "$DATA_DIR"
cp -r "$SRC_DIR/app" "$SRC_DIR/migrations" "$SRC_DIR/alembic.ini" "$SRC_DIR/requirements.txt" "$PANEL_DIR/"
if [ ! -d "$PANEL_DIR/.venv" ]; then
    python3 -m venv "$PANEL_DIR/.venv"
fi
"$PANEL_DIR/.venv/bin/pip" install --upgrade pip -q
"$PANEL_DIR/.venv/bin/pip" install -q -r "$PANEL_DIR/requirements.txt"
ok "Python virtualenv ready"

# --------------------------------------------------------------------------
# 3. phpMyAdmin
# --------------------------------------------------------------------------
step "Installing phpMyAdmin ${PMA_VERSION}"
if [ ! -f "$PMA_DIR/index.php" ]; then
    tmp="$(mktemp -d)"
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz" -O "$tmp/pma.tgz"
    mkdir -p "$PMA_DIR"
    tar xzf "$tmp/pma.tgz" -C "$PMA_DIR" --strip-components=1
    rm -rf "$tmp"
fi
mkdir -p "$PMA_DIR/tmp"
chown -R www-data:www-data "$PMA_DIR/tmp"
if [ ! -f "$PMA_DIR/config.inc.php" ]; then
    cp "$PMA_DIR/config.sample.inc.php" "$PMA_DIR/config.inc.php"
    BF="$(openssl rand -base64 32)"
    sed -i "s#\$cfg\['blowfish_secret'\] = '';#\$cfg['blowfish_secret'] = '${BF}';#" "$PMA_DIR/config.inc.php"
    sed -i '/^?>/d' "$PMA_DIR/config.inc.php"
    printf "\$cfg['TempDir'] = '%s/tmp';\n\$cfg['AllowThirdPartyFraming'] = 'sameorigin';\n" "$PMA_DIR" >> "$PMA_DIR/config.inc.php"
fi
ok "phpMyAdmin ready at /phpmyadmin"

# --------------------------------------------------------------------------
# 4. Secrets + configuration
# --------------------------------------------------------------------------
step "Generating configuration & secrets"
ADMIN_USER="${PANEL_ADMIN_USER:-admin}"
# Reuse an existing admin password if re-installing; otherwise generate one.
if [ -f "$ENV_FILE" ] && grep -q '^PANEL_ADMIN_PASSWORD=' "$ENV_FILE"; then
    ADMIN_PASS="$(grep '^PANEL_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
    SECRET="$(grep '^PANEL_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2-)"
    warn "Reusing existing admin password from ${ENV_FILE}"
else
    ADMIN_PASS="${PANEL_ADMIN_PASSWORD:-$(openssl rand -base64 12)}"
    SECRET="$(openssl rand -hex 32)"
fi
cat > "$ENV_FILE" <<EOF
PANEL_PROVIDER=linux
PANEL_SECRET_KEY=${SECRET}
PANEL_ADMIN_USER=${ADMIN_USER}
PANEL_ADMIN_PASSWORD=${ADMIN_PASS}
PANEL_DATA_DIR=${DATA_DIR}
PANEL_PHPMYADMIN_URL=/phpmyadmin
PANEL_SERVER_IP=${SERVER_IP}
PANEL_HOST=${DOMAIN:-${SERVER_IP}}
EOF
chmod 600 "$ENV_FILE"
ok "Config written to ${ENV_FILE}"

# --------------------------------------------------------------------------
# 4b. Database schema (Alembic migrations)
# --------------------------------------------------------------------------
# Apply migrations explicitly here — up front and loudly — instead of relying
# only on the app's startup hook. A reinstall re-copies migrations/ (above), so
# this brings the live DB to the newest revision (e.g. node_apps) and, crucially,
# aborts the install if a migration fails rather than booting a half-migrated app.
step "Applying database migrations"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
if (cd "$PANEL_DIR" && "$PANEL_DIR/.venv/bin/python" -c "from app.db import init_db; init_db()"); then
    ok "Database schema is up to date"
else
    die "Database migration failed — aborting so the panel is not left half-migrated"
fi

# --------------------------------------------------------------------------
# 5. systemd service
# --------------------------------------------------------------------------
step "Creating the systemd service"
cat > "$SERVICE" <<EOF
[Unit]
Description=LitesPanel control panel
After=network.target mysql.service

[Service]
User=root
WorkingDirectory=${PANEL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${PANEL_DIR}/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable litespanel >/dev/null 2>&1
systemctl restart litespanel
ok "Service enabled and started"

# --------------------------------------------------------------------------
# 6. nginx reverse proxy (+ phpMyAdmin)
# --------------------------------------------------------------------------
step "Configuring nginx"
SERVER_NAME="${DOMAIN:-_}"
cat > /etc/nginx/sites-available/litespanel <<EOF
server {
    listen 80;
    server_name ${SERVER_NAME};
    client_max_body_size 100M;

    location /phpmyadmin {
        root /usr/share/;
        index index.php;
        location ~ ^/phpmyadmin/(.+\.php)\$ {
            root /usr/share/;
            fastcgi_pass unix:/run/php/php${PHP_VER}-fpm.sock;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # Long-running admin actions (Node.js runtime install via apt, SSL
        # issuance) can take minutes; don't let nginx 502 them at 60s.
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }
}
EOF
ln -sf /etc/nginx/sites-available/litespanel /etc/nginx/sites-enabled/litespanel
rm -f /etc/nginx/sites-enabled/default

# HTTPS catch-all: reject HTTPS to any domain that has no certificate yet, so
# such requests are closed (444) instead of falling through to the panel (they
# would otherwise hit the only :443 server and show the control panel). Each
# hosted site gets its own :443 block once SSL is issued for it.
if [ ! -f /etc/nginx/litespanel-selfsigned.crt ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /etc/nginx/litespanel-selfsigned.key \
        -out /etc/nginx/litespanel-selfsigned.crt \
        -subj "/CN=litespanel-default" >/dev/null 2>&1 || true
fi
cat > /etc/nginx/conf.d/00-litespanel-https-default.conf <<'EOF'
server {
    listen 443 ssl default_server;
    server_name _;
    ssl_certificate     /etc/nginx/litespanel-selfsigned.crt;
    ssl_certificate_key /etc/nginx/litespanel-selfsigned.key;
    ssl_reject_handshake off;
    return 444;
}
EOF

nginx -t >/dev/null 2>&1 || die "nginx config test failed — check /etc/nginx/sites-available/litespanel"
systemctl reload nginx
ok "nginx serving the panel"

# --------------------------------------------------------------------------
# 7. Firewall (ufw) + intrusion prevention (fail2ban)
# --------------------------------------------------------------------------
# The panel's Firewall & Security page manages ufw rules and fail2ban bans at
# runtime, but the host needs both installed, configured and ENABLED first so
# that page shows an active firewall out of the box. SSH is allowed *before*
# enabling ufw so this can never lock out the current session.
step "Enabling the firewall (OpenSSH, HTTP, HTTPS)"
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 'Nginx Full' >/dev/null 2>&1 || true
# --force skips the interactive "proceed?" prompt; SSH is already allowed above.
ufw --force enable >/dev/null 2>&1 && ok "ufw enabled (OpenSSH, Nginx Full allowed)" \
    || warn "Could not enable ufw automatically — run 'ufw --force enable' manually"

step "Configuring fail2ban (sshd jail)"
# A minimal local jail so fail2ban actively protects SSH and the panel's
# Firewall page has a live jail to manage. jail.local overrides the package
# default without being clobbered on upgrades.
if [ ! -f /etc/fail2ban/jail.local ]; then
    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
EOF
fi
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 \
    && ok "fail2ban running with the sshd jail" \
    || warn "fail2ban did not start — check 'systemctl status fail2ban'"

# --------------------------------------------------------------------------
# 8. SSL (optional, needs a domain pointing at this server)
# --------------------------------------------------------------------------
if [ -n "$DOMAIN" ]; then
    step "Requesting a Let's Encrypt certificate for ${DOMAIN}"
    if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@${DOMAIN}" --redirect >/dev/null 2>&1; then
        ok "HTTPS enabled for ${DOMAIN}"
        # Now that we're on HTTPS, turn on Secure session cookies.
        if ! grep -q '^PANEL_HTTPS=' "$ENV_FILE"; then echo "PANEL_HTTPS=true" >> "$ENV_FILE"; fi
        systemctl restart litespanel
        URL="https://${DOMAIN}"
    else
        warn "SSL request failed — is ${DOMAIN}'s DNS pointing to ${SERVER_IP}? You can retry later:"
        warn "  sudo certbot --nginx -d ${DOMAIN}"
        URL="http://${DOMAIN}"
    fi
else
    URL="http://${SERVER_IP}"
fi

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------
sleep 1
HEALTH="$(curl -s http://127.0.0.1:8000/healthz || true)"
echo -e "\n${GREEN}${BOLD}  ✓ LitesPanel is installed and running.${RESET}"
echo -e "  health: ${HEALTH:-<no response>}\n"
echo -e "  ${BOLD}Panel URL:${RESET}  ${URL}"
echo -e "  ${BOLD}Username: ${RESET}  ${ADMIN_USER}"
echo -e "  ${BOLD}Password: ${RESET}  ${ADMIN_PASS}"
echo -e "\n  ${YELLOW}Log in and change the admin password. Keep ${ENV_FILE} private.${RESET}\n"
