"""Central configuration.

Everything a deploy might change lives here and can be overridden with
environment variables, so the same code runs on a Windows dev box (demo
provider) and a Linux VPS (linux provider) without edits.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --- Paths -----------------------------------------------------------------
# Project root = the folder containing this "app" package.
BASE_DIR = Path(__file__).resolve().parent.parent

# All mutable panel state (db, hosted sites, nginx configs, certs) lives under
# DATA_DIR. On a real VPS you'd point this at /var/www + /etc, but keeping it
# together makes the demo self-contained and easy to inspect.
DATA_DIR = Path(_env("PANEL_DATA_DIR", str(BASE_DIR / "data")))
SITES_DIR = DATA_DIR / "sites"          # per-domain webroots
NGINX_DIR = DATA_DIR / "nginx"          # generated vhost configs
CERTS_DIR = DATA_DIR / "certs"          # SSL certificates
DB_SANDBOX_DIR = DATA_DIR / "databases"  # demo "MySQL" storage
PG_DIR = DATA_DIR / "postgres"          # demo "PostgreSQL" storage

DB_URL = _env("PANEL_DB_URL", f"sqlite:///{(DATA_DIR / 'panel.db').as_posix()}")

# --- Provider --------------------------------------------------------------
# "demo"  -> simulate system operations on the local filesystem (Windows-safe)
# "linux" -> run real nginx/certbot/mysql commands (VPS)
PROVIDER = _env("PANEL_PROVIDER", "demo")

# --- Security --------------------------------------------------------------
# Session signing key. Generated per-process if unset — fine for dev, but set
# PANEL_SECRET_KEY in production so sessions survive restarts.
SECRET_KEY = _env("PANEL_SECRET_KEY", secrets.token_hex(32))
SESSION_COOKIE = "panel_session"

# Default admin bootstrapped on first run (change the password after login).
DEFAULT_ADMIN_USER = _env("PANEL_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASSWORD = _env("PANEL_ADMIN_PASSWORD", "admin")

# --- App -------------------------------------------------------------------
APP_NAME = _env("PANEL_APP_NAME", "LitesPanel")

# Set PANEL_HTTPS=true once the panel is served over HTTPS so the session cookie
# gets the Secure flag (don't enable while still on plain HTTP or logins break).
HTTPS_ONLY = _env("PANEL_HTTPS", "false").lower() in ("1", "true", "yes")
# Base domain used to build demo URLs and default nginx server_name hints.
PANEL_HOST = _env("PANEL_HOST", "localhost")

# The panel's own public base URL. Every hosted site gets a `/lpanel` location
# (like cPanel's /cpanel) that 301-redirects here to the panel login. Defaults
# from PANEL_HOST + scheme, but set PANEL_URL explicitly in production.
PANEL_URL = _env("PANEL_URL", ("https://" if HTTPS_ONLY else "http://") + PANEL_HOST).rstrip("/")

# If set (e.g. https://server/phpmyadmin), the Database Manager embeds the real
# phpMyAdmin in an iframe. If empty, the built-in SQLite-backed SQL console is
# used — which actually works in the demo without a MySQL server.
PHPMYADMIN_URL = _env("PANEL_PHPMYADMIN_URL", "")

# If set (e.g. /webmail), the panel shows a Webmail tool linking to Roundcube.
WEBMAIL_URL = _env("PANEL_WEBMAIL_URL", "")

# Shared secret for single sign-on to webmail (the Check Email button). The panel
# signs a short-lived token naming the mailbox; Roundcube's panel_sso plugin verifies
# the signature with this same secret and logs the user in via a Dovecot master user.
# Unset (mail stack not installed) → Check Email falls back to the plain login page.
WEBMAIL_SSO_SECRET = _env("PANEL_WEBMAIL_SSO_SECRET", "")

# WordPress 1-click installer sources.
WORDPRESS_URL = _env("PANEL_WORDPRESS_URL", "https://wordpress.org/latest.zip")
WP_CLI_URL = _env("PANEL_WP_CLI_URL",
                  "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar")

# Public IP of this hosting node — used to seed default DNS A records.
SERVER_IP = _env("PANEL_SERVER_IP", "203.0.113.10")

# Additional data directories.
DNS_DIR = DATA_DIR / "dns"          # generated zone files
MAIL_DIR = DATA_DIR / "mail"        # virtual mailbox store
DKIM_DIR = DATA_DIR / "dkim"        # per-domain DKIM private keys (0600)
BACKUPS_DIR = DATA_DIR / "backups"  # account backup archives
PHP_DIR = DATA_DIR / "php"          # generated php.ini / pool overrides
NODE_DIR = DATA_DIR / "node"        # generated systemd units + reverse-proxy conf
FIREWALL_DIR = DATA_DIR / "firewall"  # demo firewall/fail2ban state files
LOG_DIR = DATA_DIR / "logs"           # demo synthetic access/error logs
FTP_DIR = DATA_DIR / "ftp"            # demo virtual-FTP user store (passwd files)
WEBDISK_DIR = DATA_DIR / "webdisk"    # demo WebDAV credential store (htpasswd files)
# Per-account home directories (system-user isolation). The demo provider
# simulates these under DATA_DIR; the linux provider uses real /home.
HOME_DIR = DATA_DIR / "home"

# PHP-FPM version used for per-account pools (linux provider).
PHP_FPM_VERSION = _env("PANEL_PHP_FPM_VERSION", "8.3")

# Max upload size for hosted sites. cPanel-style: large enough for WordPress
# theme/plugin zips and media. Applied at BOTH layers that can reject a big
# body — nginx (client_max_body_size) and PHP-FPM (upload_max_filesize /
# post_max_size). Keep them in lock-step so neither becomes the silent 413/error.
MAX_UPLOAD_MB = int(_env("PANEL_MAX_UPLOAD_MB", "128"))

# --- Panel self-update (admin-only) ----------------------------------------
# Where the panel is installed on the VPS (the git working tree the updater
# pulls into) and how to reach it. BASE_DIR is the real runtime directory, so
# it works regardless of where the code was copied. Overridable for odd layouts.
PANEL_INSTALL_DIR = _env("PANEL_INSTALL_DIR", str(BASE_DIR))
PANEL_SERVICE_NAME = _env("PANEL_SERVICE_NAME", "litespanel")
PANEL_REPO_URL = _env("PANEL_REPO_URL", "https://github.com/hanif865/litespanel.git")
PANEL_REPO_BRANCH = _env("PANEL_REPO_BRANCH", "main")
# The self-updater writes its progress here so the WHM page can tail it.
PANEL_UPDATE_LOG = _env("PANEL_UPDATE_LOG", str(DATA_DIR / "panel-update.log"))

# Node.js support (admin-only). Major versions the panel can install via
# NodeSource, and the local port range reverse-proxied apps are assigned from.
NODE_VERSIONS = ("22", "20", "18")
NODE_PORT_BASE = int(_env("PANEL_NODE_PORT_BASE", "3100"))

# Service Manager (admin-only). The core system services WHM can start/stop/
# restart, as (key, label) pairs. `key` is the opaque catalog id the router and
# templates use — the provider maps it to the real systemd unit, so a client can
# never target an arbitrary unit. Shared here so the demo and linux providers
# stay in lock-step on keys/labels/order.
MANAGED_SERVICES = (
    ("nginx",      "Nginx — web server"),
    ("php-fpm",    "PHP-FPM"),
    ("mysql",      "MySQL / MariaDB"),
    ("postgresql", "PostgreSQL"),
    ("postfix",    "Postfix — SMTP"),
    ("dovecot",    "Dovecot — IMAP/POP3"),
)


def ensure_dirs() -> None:
    """Create the data directories on startup (idempotent)."""
    for d in (DATA_DIR, SITES_DIR, NGINX_DIR, CERTS_DIR, DB_SANDBOX_DIR, PG_DIR, DNS_DIR,
              MAIL_DIR, DKIM_DIR, BACKUPS_DIR, HOME_DIR, PHP_DIR, NODE_DIR, FIREWALL_DIR, LOG_DIR,
              FTP_DIR, WEBDISK_DIR):
        d.mkdir(parents=True, exist_ok=True)
