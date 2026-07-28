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

## Features

- 🌐 **Domains / website hosting** — provisions an nginx vhost + document root
- 🔗 **Subdomains** — `blog.example.com`, docroot nested in the parent's public_html
- 🧭 **DNS Zone Editor** — add / **edit** / delete A/AAAA/CNAME/MX/TXT/NS records,
  synced to a zone file; new domains auto-seed sensible defaults (A, www, MX, SPF)
- 📧 **Email accounts** — per-domain mailboxes with quota; Maildir + Dovecot-style
  virtual users file (password stored hashed, never plaintext)
- 📤 **Email forwarders** — forward an address to another (or `*` catch-all),
  synced to a Postfix-style virtual alias file
- 🤖 **Autoresponders** — automatic replies (out-of-office) with enable/disable
- 📁 **File manager** — browse, upload, edit, download, delete (sandboxed per site)
- 🗄️ **Database management** — create MySQL/MariaDB databases with a scoped user
- 🐬 **Database Manager (phpMyAdmin-style)** — SQL console + table browser. In demo
  mode each database is a real SQLite file so queries actually run; set
  `PANEL_PHPMYADMIN_URL` to embed real phpMyAdmin in production.
- 🧙 **Database Wizard** — guided create-database-and-user flow with a chosen
  username and password (vs. the one-click auto-generated Databases page)
- 🐘 **PHP version selector** — set the PHP-FPM version per domain (rewrites vhost)
- ⏰ **Cron jobs** — schedule commands, synced to the system crontab
- 🔒 **SSL** — issue/revoke Let's Encrypt certificates per domain
- 💾 **Backups** — full-account zip (sites + databases + DNS + email); download & restore
- 👥 **Multi-user / Reseller** — WHM-style User Manager with roles (admin / reseller /
  user), per-account limits (domains, databases, email, disk) enforced on creation,
  suspend/reactivate, and full resource isolation per account
- 📦 **Packages** — reusable hosting plans (named limit bundles). Assign to accounts;
  editing a package updates every account on it. Effective limits = package if
  assigned, else the account's inline limits
- 📊 **Dashboard** — cPanel Jupiter-style home with **real** CPU / memory / disk
  stats (stdlib + ctypes sampler on Windows, /proc on Linux — no psutil)
- 🌙 **Dark mode** — persistent theme toggle (applied before paint, no flash)

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

- DNS record management
- Email accounts
- Cron jobs & scheduled backups
- Multi-user / reseller packages
- Real CPU metric via a tiny sampler (avoid psutil to stay light)
