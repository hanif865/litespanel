# LitesPanel — a lightweight hosting control panel

A cPanel alternative built on **FastAPI**, designed to stay small enough for a
1 CPU / 4 GB VPS while still hosting real websites. The panel itself is just a
manager — nginx, PHP-FPM and MySQL do the heavy lifting.

## 🚀 One-command install

On a **fresh Ubuntu 22.04 / 24.04** server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/install.sh | sudo bash
```

…or with a domain, to also get a free Let's Encrypt certificate (point the
domain's DNS at the server first):

```bash
curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/install.sh | sudo bash -s -- panel.example.com
```

The installer sets up **nginx, MySQL, PHP-FPM, certbot, phpMyAdmin**, the panel
itself, and a **systemd service** — then prints your panel URL and admin login.

📖 **Full step-by-step guide** (fresh server → secured → domain → SSL → mail →
updating): see **[DEPLOY.md](DEPLOY.md)**.

## Features

### User Panel (cPanel-style)

- 🌐 **Domains / website hosting** — provisions an nginx vhost + document root
- 🔗 **Subdomains** — `blog.example.com`, docroot nested in the parent's public_html
- 🧭 **DNS Zone Editor** — add / **edit** / delete A/AAAA/CNAME/MX/TXT/NS records,
  synced to a zone file; new domains auto-seed sensible defaults (A, www, MX, SPF)
- 📧 **Email accounts** — per-domain mailboxes with quota; Maildir + Dovecot-style
  virtual users file (password stored hashed, never plaintext). Change password & quota
  post-creation. **Webmail SSO** — one-click login to Roundcube via short-lived signed token.
- 📬 **Connect Email** — per-mailbox IMAP/SMTP config guide (server, ports, SSL settings)
  for desktop/mobile clients
- 📤 **Email forwarders** — forward an address to another (or `*` catch-all),
  synced to a Postfix-style virtual alias file
- 🤖 **Autoresponders** — automatic replies (out-of-office) with enable/disable
- 🔐 **Email Deliverability** — generate DKIM keypair (2048-bit RSA), auto-register with
  OpenDKIM, display public key + DNS TXT records chunked to fit 255-char limits. SPF/DMARC
  guides for one-click copy.
- 📁 **File manager** — browse, upload, edit, download, delete (sandboxed per site)
- 🗄️ **MySQL / MariaDB databases** — create with a scoped user
- 🐘 **PostgreSQL databases** — create with a scoped user (full parity with MySQL manager)
- 🐬 **Database Manager (phpMyAdmin-style)** — SQL console + table browser. In demo
  mode each database is a real SQLite file so queries actually run; set
  `PANEL_PHPMYADMIN_URL` to embed real phpMyAdmin in production.
- 🧙 **Database Wizard** — guided create-database-and-user flow with a chosen
  username and password (vs. the one-click auto-generated Databases page)
- 🐘 **PHP version selector** — set the PHP-FPM version per domain (rewrites vhost)
- 🟢 **Node.js app hosting** — deploy from Git URL or upload a tarball; set npm install
  options, environment variables, custom start command; live streaming logs; start/stop/restart
- 📂 **FTP Accounts** — create per-domain FTP users (ProFTPd virtual users file), each
  jailed to their docroot
- 🔨 **WordPress 1-Click Installer** — fully installs WordPress (database, files, admin
  account) on a **domain or subdomain** with HMAC-signed auto-login. No browser setup wizard.
  Subdomain installs serve over HTTP; domain installs use HTTPS when a certificate exists.
- ⏰ **Cron jobs** — schedule commands, synced to the system crontab
- 🔒 **SSL** — issue/revoke Let's Encrypt certificates per domain
- 💾 **Backups** — full-account zip (sites + databases + DNS + email); download & restore
- 📊 **Dashboard** — cPanel Jupiter-style home with **real** CPU / memory / disk
  stats (stdlib + ctypes sampler on Windows, /proc on Linux — no psutil)
- 🌙 **Dark mode** — persistent theme toggle (applied before paint, no flash)

### WHM (Admin / Reseller)

- 👥 **User Manager** — create/edit accounts with roles (admin / reseller / user),
  per-account limits (domains, databases, email, disk), suspend/reactivate, full resource
  isolation per account (dedicated Linux system user + PHP-FPM pool)
- 📋 **Account Details** — per-account deep view: resource usage, owned domains, databases,
  email accounts, FTP users, limits, package assignment
- 📦 **Packages** — reusable hosting plans (named limit bundles). Assign to accounts;
  editing a package updates every account on it. Effective limits = package if
  assigned, else the account's inline limits
- 💿 **Server Software** — install PHP versions, Node.js, PostgreSQL, mail stack
  (Postfix/Dovecot/OpenDKIM/Roundcube) host-wide (admin-only, one-click via background shell)
- ⚙️ **Service Manager** — start/stop/restart core services (Nginx, PHP-FPM, MySQL, PostgreSQL,
  Postfix, Dovecot) with live status. Admin-only, runs `systemctl` via the provider.
- 🛡️ **ModSecurity WAF** — admin-only on/off toggle for the OWASP Core Rule Set
- 🚫 **IP Blocker** — block IPs host-wide (nginx `deny`), review auto-bans (e.g. from
  fail2ban), unblock with one click

## Security

Built-in protections:

- **CSRF** — SameSite=Lax session cookies + same-origin (Origin/Referer) checks
  on every state-changing request.
- **Session cookies** — HttpOnly, SameSite=Lax, and Secure once `PANEL_HTTPS=true`;
  the session id is rotated on login (anti session-fixation).
- **Login throttling** — 5 failed attempts per IP triggers a 5-minute lockout.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options: SAMEORIGIN`,
  `Referrer-Policy`, `Permissions-Policy`.
- **SQL safety** — database/user names are validated to plain identifiers and
  passwords are escaped before hitting MySQL (no string-built injection).
- **Path safety** — the file manager confines every path to the site root, and
  backup restore rejects Zip-Slip paths that escape the target directory.
- **Passwords** — PBKDF2-HMAC-SHA256 (200k iterations), constant-time compare.
- **Per-account system-user isolation** (shared hosting) — every hosting account
  gets its own Linux user, a dedicated PHP-FPM pool, and a `/home/<user>` tree it
  owns. A site's PHP runs **as that user**, so one account can't read or write
  another's files. Files created via the File Manager are chowned to the account.
  On a group-name collision (e.g. Ubuntu's reserved `admin` group) the account gets
  a panel-namespaced primary group rather than reusing a group it doesn't own.
- **Admin-only server operations** — Service Manager, Server Software, ModSecurity and
  IP Blocker are gated by `require_admin` and, where a client sends a target, use a
  fixed server-side allowlist (a `key` catalog, never a raw unit/path) so a request can
  never target an arbitrary systemd unit or file.
- **Mail stack TLS** — Postfix/Dovecot serve over STARTTLS/SSL for external clients so
  mailbox credentials aren't sent in the clear; DKIM signs outbound mail via OpenDKIM.
- **Signed auto-login tokens** — WordPress and Webmail one-click logins use short-lived
  (300s) HMAC-SHA256 tokens, never a stored session or plaintext credential in the URL.

Remaining hardening:

- The panel process runs as **root** (the linux provider expects it, like cPanel/WHM).
  A more locked-down setup would drop to a service user with scoped `sudo` rules.
- Disk **quotas** per account are tracked in the DB but not yet enforced at the
  filesystem level (would use `setquota`).

## Roles

| Role | Can do |
|------|--------|
| **admin** | Everything; manage all accounts; create resellers or users; unlimited |
| **reseller** | Manage only the users they created; limited by their own allocation |
| **user** | Manage only their own sites/dbs/email/etc.; no access to User Manager |

## Database migrations (Alembic)

Alembic is the single source of truth for the schema. On startup the app runs
`alembic upgrade head` automatically — a fresh DB gets every table, an existing
one gets only new migrations. **No more deleting the DB after a model change.**

After editing `app/models.py`:

```bash
.venv/Scripts/alembic revision --autogenerate -m "describe the change"
.venv/Scripts/alembic upgrade head   # (also runs automatically on next app start)
```

SQLite batch mode (`render_as_batch=True`) is enabled so add/drop/alter-column
migrations work on SQLite too.

## Architecture: the provider layer

Every OS-level action goes through a **provider** (`app/providers/`):

| Provider | When | What it does |
|----------|------|--------------|
| `demo`   | Windows dev box | Simulates operations on the local filesystem — real files, no real services. Runs anywhere. |
| `linux`  | Production VPS  | Runs the real `nginx`, `certbot`, `mysql` commands. |

Switch between them with one env var — the routers and UI never change:

```bash
PANEL_PROVIDER=demo    # default, for development
PANEL_PROVIDER=linux   # on the server
```

## Run it (development, Windows)

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 and log in with **admin / admin**.

## Run it (production, Linux VPS)

```bash
pip install -r requirements.txt
export PANEL_PROVIDER=linux
export PANEL_SECRET_KEY="$(openssl rand -hex 32)"
export PANEL_ADMIN_PASSWORD="a-strong-password"
# single worker keeps the footprint ~80-120 MB
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Put nginx in front as a reverse proxy for the panel itself, and give the panel
process narrowly-scoped `sudo` rules for exactly the commands in
`app/providers/linux.py` — never blanket root.

## Configuration (env vars)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PANEL_PROVIDER` | `demo` | `demo` or `linux` |
| `PANEL_DATA_DIR` | `./data` | Where sites, configs, certs, db live |
| `PANEL_DB_URL` | `sqlite:///.../panel.db` | Panel's own metadata store |
| `PANEL_SECRET_KEY` | random per run | Session signing key — **set in prod** |
| `PANEL_ADMIN_USER` / `PANEL_ADMIN_PASSWORD` | `admin` / `admin` | Bootstrapped on first run |

## Project layout

```
app/
  main.py            # app assembly, startup, admin bootstrap
  config.py          # env-driven settings
  db.py / models.py  # SQLite via SQLAlchemy
  security.py        # pbkdf2 password hashing, session auth
  providers/         # demo.py + linux.py behind base.py
  routers/           # dashboard, domains, files, databases, ssl, auth
  templates/         # Jinja UI
  static/app.css
```

## Roadmap (next)

- Filesystem-level disk quotas (`setquota`) — currently tracked in the DB but not enforced
- Drop the panel from root to a scoped-`sudo` service user
- Scheduled / automatic backups (manual full-account backup already ships)
- Let's Encrypt for subdomains (subdomain WordPress installs are HTTP-only today)
- Per-service uptime / memory metrics in the Service Manager
