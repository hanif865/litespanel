"""Demo provider — simulates a hosting node on the local filesystem.

Runs anywhere Python runs (Windows included). It writes real files where it
makes the demo tangible (docroots, nginx config text, self-signed-ish certs)
so the UI shows genuine results, but never touches the real OS services.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import config
from .base import CertInfo, DbCredentials, Provider, node_env_lines, node_exec_start

_NGINX_TEMPLATE = """# Managed by {app} — do not edit by hand.
server {{
    listen 80;
    server_name {domain} www.{domain};
    root {docroot};
    index index.html index.php;

    location /lpanel {{
        return 301 {panel_url}/login;
    }}

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        fastcgi_pass unix:/run/php/php{php}-fpm.sock;
        include fastcgi_params;
    }}
}}
"""

_WELCOME_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{domain}</title>
<style>body{{font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem}}
h1{{color:#2563eb}}</style></head>
<body><h1>{domain} is live 🎉</h1>
<p>This site was provisioned by {app}. Replace this file in
<code>public_html/</code> with your own site.</p></body></html>
"""


# Sample log content the demo seeds under LOG_DIR so the Log Viewer has
# something realistic to show on a machine with no real /var/log.
_SAMPLE_LOGS = {
    "access.log": (
        '203.0.113.24 - - [31/Jul/2026:09:14:02 +0000] "GET / HTTP/1.1" 200 1043 "-" "Mozilla/5.0"\n'
        '198.51.100.7 - - [31/Jul/2026:09:14:05 +0000] "GET /wp-login.php HTTP/1.1" 404 564 "-" "curl/8.4.0"\n'
        '203.0.113.24 - - [31/Jul/2026:09:14:11 +0000] "POST /login HTTP/1.1" 303 0 "https://panel.example.com/login" "Mozilla/5.0"\n'
        '192.0.2.55 - - [31/Jul/2026:09:15:40 +0000] "GET /static/app.css HTTP/1.1" 200 8210 "-" "Mozilla/5.0"\n'
        '198.51.100.7 - - [31/Jul/2026:09:16:22 +0000] "GET /.env HTTP/1.1" 404 564 "-" "python-requests/2.31"\n'
    ),
    "error.log": (
        "2026/07/31 09:14:05 [error] 812#812: *1024 open() \"/var/www/html/.env\" failed (2: No such file or directory), client: 198.51.100.7, server: panel.example.com\n"
        "2026/07/31 09:16:22 [error] 812#812: *1031 open() \"/var/www/html/wp-login.php\" failed (2: No such file or directory), client: 198.51.100.7\n"
        "2026/07/31 09:20:01 [warn] 812#812: *1044 upstream server temporarily disabled while connecting to upstream\n"
    ),
    "auth.log": (
        "Jul 31 09:10:44 vps sshd[2201]: Accepted publickey for root from 203.0.113.24 port 51234 ssh2\n"
        "Jul 31 09:12:03 vps sudo:     root : TTY=pts/0 ; PWD=/opt/litespanel ; USER=root ; COMMAND=/bin/systemctl restart litespanel\n"
        "Jul 31 09:13:19 vps sshd[2260]: Failed password for invalid user admin from 198.51.100.7 port 40122 ssh2\n"
        "Jul 31 09:13:22 vps sshd[2260]: Failed password for invalid user admin from 198.51.100.7 port 40122 ssh2\n"
        "Jul 31 09:13:26 vps sshd[2260]: Disconnected from invalid user admin 198.51.100.7 port 40122 [preauth]\n"
    ),
    "fail2ban.log": (
        "2026-07-31 09:13:26,441 fail2ban.filter [1123]: INFO [sshd] Found 198.51.100.7 - 2026-07-31 09:13:26\n"
        "2026-07-31 09:13:30,502 fail2ban.actions [1123]: NOTICE [sshd] Ban 198.51.100.7\n"
        "2026-07-31 10:13:30,512 fail2ban.actions [1123]: NOTICE [sshd] Unban 198.51.100.7\n"
    ),
    "litespanel.log": (
        "2026-07-31T09:12:03+0000 INFO uvicorn.error: Application startup complete.\n"
        "2026-07-31T09:14:11+0000 INFO litespanel.audit: login ok user=admin ip=203.0.113.24\n"
        "2026-07-31T09:13:19+0000 WARNING litespanel.security: login failed user=admin ip=198.51.100.7\n"
        "2026-07-31T09:20:44+0000 INFO litespanel.audit: firewall rule added 8443/tcp by admin\n"
    ),
}


def _cell(value):
    """Render a SQLite cell value as a display string for the results table."""
    if value is None:
        return "NULL"
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return str(value)


class DemoProvider(Provider):
    name = "demo"

    # --- Accounts ---------------------------------------------------------
    def ensure_account(self, username: str) -> Path:
        # Simulate a system user by creating its home directory.
        home = config.HOME_DIR / username
        home.mkdir(parents=True, exist_ok=True)
        return home

    def remove_account(self, username: str) -> None:
        import shutil

        shutil.rmtree(config.HOME_DIR / username, ignore_errors=True)

    # --- Web hosting ------------------------------------------------------
    def create_site(self, domain: str, docroot: Path, php_version: str, system_user: str) -> Path:
        docroot.mkdir(parents=True, exist_ok=True)

        # A landing page so the site "works" immediately.
        index = docroot / "index.html"
        if not index.exists():
            index.write_text(
                _WELCOME_HTML.format(domain=domain, app=config.APP_NAME), encoding="utf-8"
            )

        # Write the vhost config as real text so users can inspect it.
        self._write_vhost(domain, docroot, php_version, system_user)
        # Seed synthetic per-domain logs so the Metrics page shows real numbers.
        self._seed_domain_logs(domain)
        return docroot

    def _write_vhost(self, domain: str, docroot: Path, php_version: str, system_user: str) -> None:
        # In the demo the PHP socket name shows the per-user pool for clarity.
        vhost = config.NGINX_DIR / f"{domain}.conf"
        text = _NGINX_TEMPLATE.format(
            app=config.APP_NAME, domain=domain, docroot=Path(docroot).as_posix(),
            php=php_version, panel_url=config.PANEL_URL,
        )
        text = f"# account: {system_user}\n" + text
        vhost.write_text(text, encoding="utf-8")

    def remove_site(self, domain: str) -> None:
        vhost = config.NGINX_DIR / f"{domain}.conf"
        vhost.unlink(missing_ok=True)
        # Docroot removal is left to the caller (data safety).

    def reload_web(self) -> None:
        # No-op in demo; on Linux this reloads nginx.
        return None

    def set_php_version(self, domain: str, docroot: str, php_version: str, system_user: str) -> None:
        self._write_vhost(domain, Path(docroot), php_version, system_user)

    def apply_php_config(self, system_user: str, php_version: str,
                         extensions: dict[str, bool], directives: dict[str, str],
                         domain: str | None = None) -> None:
        # Write a real, inspectable php.ini so the effect is visible in the demo.
        scope = domain or system_user
        target = config.PHP_DIR / f"{scope}.ini"
        lines = [
            f"; PHP {php_version} config for {scope}",
            f"; scope: {'domain ' + domain if domain else 'account global (' + system_user + ')'}",
            "",
            "[PHP]",
        ]
        for key in sorted(directives):
            lines.append(f"{key} = {directives[key]}")
        lines.append("")
        lines.append("; extensions")
        for name in sorted(extensions):
            prefix = "" if extensions[name] else ";"
            lines.append(f"{prefix}extension={name}")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- PHP extension packages (simulated) -------------------------------
    def _installed_ext_file(self) -> Path:
        return config.PHP_DIR / "installed_extensions.txt"

    def list_installed_extensions(self, php_version: str) -> set[str]:
        from .. import php_catalog

        # Built-ins are always present; plus whatever the demo has "installed".
        installed = set(php_catalog.BUILTIN_EXTENSIONS)
        installed |= {n for n, on in php_catalog.default_extensions().items() if on}
        f = self._installed_ext_file()
        if f.exists():
            installed |= {ln.strip() for ln in f.read_text().splitlines() if ln.strip()}
        return installed

    def install_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        f = self._installed_ext_file()
        current = set(f.read_text().splitlines()) if f.exists() else set()
        current.add(extension)
        f.write_text("\n".join(sorted(c for c in current if c)) + "\n", encoding="utf-8")
        return True, f"(demo) installed php{php_version}-{extension}"

    def uninstall_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        f = self._installed_ext_file()
        if f.exists():
            current = {ln for ln in f.read_text().splitlines() if ln.strip() and ln.strip() != extension}
            f.write_text("\n".join(sorted(current)) + "\n", encoding="utf-8")
        return True, f"(demo) removed php{php_version}-{extension}"

    def set_https_redirect(self, domain: str, docroot: str, php_version: str,
                           system_user: str, enabled: bool, has_ssl: bool) -> None:
        vhost = config.NGINX_DIR / f"{domain}.conf"
        body = _NGINX_TEMPLATE.format(
            app=config.APP_NAME, domain=domain, docroot=Path(docroot).as_posix(),
            php=php_version, panel_url=config.PANEL_URL,
        )
        header = f"# account: {system_user}\n"
        if enabled:
            header += (f"server {{ listen 80; server_name {domain} www.{domain}; "
                       f"return 301 https://$host$request_uri; }}\n")
        vhost.write_text(header + body, encoding="utf-8")

    # --- Subdomains -------------------------------------------------------
    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str, system_user: str) -> Path:
        docroot.mkdir(parents=True, exist_ok=True)
        index = docroot / "index.html"
        if not index.exists():
            index.write_text(
                _WELCOME_HTML.format(domain=fqdn, app=config.APP_NAME), encoding="utf-8"
            )
        self._write_vhost(fqdn, docroot, php_version, system_user)
        return docroot

    def remove_subdomain(self, fqdn: str) -> None:
        (config.NGINX_DIR / f"{fqdn}.conf").unlink(missing_ok=True)

    # --- Node.js (admin-only, simulated) ----------------------------------
    def _node_state_file(self) -> Path:
        return config.NODE_DIR / "installed_node.txt"

    def _node_status_file(self, name: str) -> Path:
        return config.NODE_DIR / f"{name}.status"

    def install_node(self, version: str) -> tuple[bool, str]:
        self._node_state_file().write_text(f"{version}.0.0\n", encoding="utf-8")
        return True, f"(demo) installed Node.js {version}.x via NodeSource"

    def node_installed_version(self) -> str | None:
        f = self._node_state_file()
        return f.read_text(encoding="utf-8").strip() if f.exists() else None

    def _node_work_dir(self, app_dir: Path, app_root: str) -> Path:
        app_dir = Path(app_dir).resolve()
        root = (app_root or "").strip().strip("/")
        if not root:
            return app_dir
        target = (app_dir / root).resolve()
        if target == app_dir or app_dir in target.parents:
            return target
        return app_dir

    def deploy_node_app(self, name: str, domain: str, app_dir: Path, port: int,
                        entrypoint: str, system_user: str, node_version: str,
                        start_command: str = "", env_vars: str = "",
                        app_root: str = "") -> tuple[bool, str]:
        app_dir = Path(app_dir)
        app_dir.mkdir(parents=True, exist_ok=True)
        work_dir = self._node_work_dir(app_dir, app_root)
        work_dir.mkdir(parents=True, exist_ok=True)
        env_block = "".join(line + "\n" for line in node_env_lines(env_vars))
        exec_start = node_exec_start("/usr/bin/node", entrypoint, start_command)
        # Write an inspectable systemd unit so the demo shows what Linux would do.
        unit = config.NODE_DIR / f"litespanel-node-{name}.service"
        unit.write_text(
            "[Unit]\n"
            f"Description=LitesPanel Node app {name} ({domain})\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={system_user}\n"
            f"WorkingDirectory={work_dir.as_posix()}\n"
            "Environment=NODE_ENV=production\n"
            f"Environment=PORT={port}\n"
            f"{env_block}"
            f"ExecStart={exec_start}\n"
            "Restart=on-failure\nRestartSec=5\n\n"
            "[Install]\nWantedBy=multi-user.target\n",
            encoding="utf-8",
        )
        # Seed a couple of log lines so the demo log viewer has something to show.
        (config.NODE_DIR / f"{name}.log").write_text(
            f"[demo] deployed litespanel-node-{name} serving {domain} on port {port}\n"
            f"[demo] ExecStart={exec_start}\n"
            "[demo] Listening — (simulated runtime, no real process)\n",
            encoding="utf-8",
        )
        # And the reverse-proxy vhost that replaces the domain's PHP vhost.
        vhost = config.NGINX_DIR / f"{domain}.conf"
        vhost.write_text(
            f"# account: {system_user} — Node.js reverse proxy\n"
            f"server {{\n    listen 80;\n    server_name {domain} www.{domain};\n"
            f"    location / {{\n        proxy_pass http://127.0.0.1:{port};\n"
            f"        proxy_set_header Host $host;\n"
            f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            f"    }}\n}}\n",
            encoding="utf-8",
        )
        self._node_status_file(name).write_text("running\n", encoding="utf-8")
        return True, f"(demo) Node app '{name}' running on port {port}, serving {domain}."

    def control_node_app(self, name: str, action: str) -> tuple[bool, str]:
        if action not in ("start", "stop", "restart"):
            return False, f"Unknown action: {action}"
        state = "stopped" if action == "stop" else "running"
        self._node_status_file(name).write_text(state + "\n", encoding="utf-8")
        past = {"start": "started", "stop": "stopped", "restart": "restarted"}[action]
        return True, f"(demo) {past} '{name}'."

    def remove_node_app(self, name: str, domain: str) -> None:
        (config.NODE_DIR / f"litespanel-node-{name}.service").unlink(missing_ok=True)
        self._node_status_file(name).unlink(missing_ok=True)
        (config.NODE_DIR / f"{name}.log").unlink(missing_ok=True)
        (config.NGINX_DIR / f"{domain}.conf").unlink(missing_ok=True)

    def node_app_status(self, name: str) -> str:
        f = self._node_status_file(name)
        return f.read_text(encoding="utf-8").strip() if f.exists() else "unknown"

    def npm_install(self, app, system_user: str) -> tuple[bool, str]:
        work_dir = self._node_work_dir(Path(app.app_dir), app.app_root or "")
        work_dir.mkdir(parents=True, exist_ok=True)
        (config.NODE_DIR / f"{app.name}.npm-install").write_text(
            f"(demo) npm install in {work_dir.as_posix()} as {system_user}\n",
            encoding="utf-8",
        )
        log = config.NODE_DIR / f"{app.name}.log"
        with log.open("a", encoding="utf-8") as fh:
            fh.write("[demo] npm install --no-fund --no-audit → up to date\n")
        return True, f"(demo) npm install completed in {work_dir.as_posix()}"

    def node_app_logs(self, name: str, lines: int = 200) -> str:
        f = config.NODE_DIR / f"{name}.log"
        if not f.exists():
            return "(demo) no logs"
        tail = f.read_text(encoding="utf-8").splitlines()[-max(1, int(lines)):]
        return "\n".join(tail)

    def set_owner(self, path: Path, system_user: str) -> None:
        # No POSIX ownership on the Windows demo box — nothing to do.
        return None

    def run_wp_cli(self, docroot: Path, system_user: str, args: list[str]) -> tuple[bool, str]:
        # No PHP/WordPress runtime in the demo — pretend it worked.
        return True, "demo: wp-cli not run"

    # --- Cron -------------------------------------------------------------
    def sync_cron(self, lines: list[str]) -> None:
        crontab = config.DATA_DIR / "cron" / "crontab"
        crontab.parent.mkdir(parents=True, exist_ok=True)
        header = f"# Managed by {config.APP_NAME}. Do not edit by hand.\n"
        crontab.write_text(header + "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    # --- Databases --------------------------------------------------------
    def _db_path(self, name: str):
        # Each "database" is a real SQLite file, so the SQL console truly works.
        return config.DB_SANDBOX_DIR / f"{name}.sqlite"

    def create_database(self, name: str, user: str, password: str) -> DbCredentials:
        import sqlite3

        # Touch the SQLite file so it exists and is browsable immediately.
        conn = sqlite3.connect(self._db_path(name))
        conn.close()
        return DbCredentials(name=name, user=user, password=password)

    def drop_database(self, name: str, user: str) -> None:
        self._db_path(name).unlink(missing_ok=True)

    def reset_db_password(self, name: str, user: str, password: str) -> None:
        # Demo databases are SQLite files with no user auth — nothing to change.
        return None

    def db_tables(self, name: str) -> list[str]:
        import sqlite3

        path = self._db_path(name)
        if not path.exists():
            return []
        conn = sqlite3.connect(path)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            return [r[0] for r in rows]
        finally:
            conn.close()

    def db_execute(self, name: str, sql: str) -> dict:
        import sqlite3

        result = {"columns": [], "rows": [], "message": "", "error": ""}
        path = self._db_path(name)
        if not path.exists():
            result["error"] = f"Database '{name}' not found."
            return result
        conn = sqlite3.connect(path)
        try:
            cur = conn.execute(sql)
            if cur.description:  # a SELECT-like statement
                result["columns"] = [c[0] for c in cur.description]
                result["rows"] = [list(map(_cell, r)) for r in cur.fetchmany(500)]
                result["message"] = f"{len(result['rows'])} row(s) returned."
            else:
                conn.commit()
                result["message"] = f"OK — {cur.rowcount} row(s) affected."
        except sqlite3.Error as exc:
            result["error"] = str(exc)
        finally:
            conn.close()
        return result

    # --- PostgreSQL databases ---------------------------------------------
    # The demo has no real Postgres server; it records each database as a real
    # SQLite file (so the row is inspectable) and reports a plausible 5432
    # connection. Kept in its own PG_DIR so it never collides with MySQL demo
    # files above.
    def _pg_path(self, name: str) -> Path:
        return config.PG_DIR / f"{name}.sqlite"

    def create_pg_database(self, name: str, user: str, password: str) -> DbCredentials:
        import sqlite3

        config.PG_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._pg_path(name))
        conn.close()
        return DbCredentials(name=name, user=user, password=password,
                             host="localhost", port=5432)

    def drop_pg_database(self, name: str, user: str) -> None:
        self._pg_path(name).unlink(missing_ok=True)

    def pg_available(self) -> bool:
        return True

    # --- SSL --------------------------------------------------------------
    def issue_certificate(self, domain: str) -> CertInfo:
        now = datetime.now(timezone.utc)
        cert_path = config.CERTS_DIR / f"{domain}.pem"
        # A placeholder PEM-looking file — enough to demonstrate the flow.
        cert_path.write_text(
            f"-----BEGIN CERTIFICATE-----\n"
            f"# DEMO certificate for {domain}\n"
            f"# serial {secrets.token_hex(8)}\n"
            f"-----END CERTIFICATE-----\n",
            encoding="utf-8",
        )
        return CertInfo(
            issuer="Let's Encrypt (demo)",
            issued_at=now,
            expires_at=now + timedelta(days=90),
            cert_path=cert_path.as_posix(),
        )

    def revoke_certificate(self, domain: str) -> None:
        (config.CERTS_DIR / f"{domain}.pem").unlink(missing_ok=True)

    # --- DNS --------------------------------------------------------------
    def sync_zone(self, domain: str, records: list[dict]) -> None:
        lines = [
            f"; Zone file for {domain} — managed by {config.APP_NAME}.",
            "$TTL 14400",
            f"@\tIN\tSOA\tns1.{domain}. admin.{domain}. (1 3600 900 604800 86400)",
        ]
        for r in records:
            name = r.get("name") or "@"
            ttl = r.get("ttl") or 14400
            if r["type"] == "MX":
                prio = r.get("priority") or 10
                lines.append(f"{name}\t{ttl}\tIN\tMX\t{prio} {r['value']}")
            elif r["type"] == "TXT":
                lines.append(f'{name}\t{ttl}\tIN\tTXT\t"{r["value"]}"')
            else:
                lines.append(f"{name}\t{ttl}\tIN\t{r['type']}\t{r['value']}")
        (config.DNS_DIR / f"{domain}.zone").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- Email ------------------------------------------------------------
    def create_mailbox(self, address: str, password: str, quota_mb: int) -> None:
        local, _, domain = address.partition("@")
        maildir = config.MAIL_DIR / domain / local / "Maildir"
        for sub in ("cur", "new", "tmp"):
            (maildir / sub).mkdir(parents=True, exist_ok=True)
        # Dovecot-style virtual users file (store a hash, never plaintext).
        pwhash = hashlib.sha256(password.encode()).hexdigest()
        passwd = config.MAIL_DIR / domain / "passwd"
        entries = {}
        if passwd.exists():
            for line in passwd.read_text(encoding="utf-8").splitlines():
                if ":" in line:
                    entries[line.split(":", 1)[0]] = line
        entries[address] = f"{address}:{{SHA256}}{pwhash}:quota={quota_mb}M"
        passwd.write_text("\n".join(entries.values()) + "\n", encoding="utf-8")

    def delete_mailbox(self, address: str) -> None:
        import shutil

        local, _, domain = address.partition("@")
        shutil.rmtree(config.MAIL_DIR / domain / local, ignore_errors=True)
        passwd = config.MAIL_DIR / domain / "passwd"
        if passwd.exists():
            kept = [
                ln for ln in passwd.read_text(encoding="utf-8").splitlines()
                if ln and not ln.startswith(f"{address}:")
            ]
            passwd.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

    def sync_forwarders(self, domain: str, pairs: list[tuple[str, str]]) -> None:
        # Postfix-style virtual alias lines: "source@domain  destination".
        maildir = config.MAIL_DIR / domain
        maildir.mkdir(parents=True, exist_ok=True)
        lines = [f"# Forwarders for {domain} — managed by {config.APP_NAME}."]
        for source, dest in pairs:
            lines.append(f"{source}@{domain}\t{dest}")
        (maildir / "forwarders").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def set_autoresponder(self, address: str, subject: str, body: str, enabled: bool) -> None:
        local, _, domain = address.partition("@")
        ar_dir = config.MAIL_DIR / domain / "autoresponders"
        ar_dir.mkdir(parents=True, exist_ok=True)
        status = "on" if enabled else "off"
        (ar_dir / f"{local}.txt").write_text(
            f"status: {status}\nsubject: {subject}\n\n{body}\n", encoding="utf-8"
        )

    def remove_autoresponder(self, address: str) -> None:
        local, _, domain = address.partition("@")
        (config.MAIL_DIR / domain / "autoresponders" / f"{local}.txt").unlink(missing_ok=True)

    # --- FTP accounts -----------------------------------------------------
    def _ftp_passwd(self) -> Path:
        # Single pure-ftpd-style virtual-users file, one tab-delimited line per
        # login:  "<login>\t{SHA256}<hash>\t<home_dir>\t<quota_mb>". Tab-delimited
        # (not ':') because a Windows demo home path contains a drive-letter colon.
        return config.FTP_DIR / "passwd"

    def _ftp_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        passwd = self._ftp_passwd()
        if passwd.exists():
            for line in passwd.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "\t" in line:
                    entries[line.split("\t", 1)[0]] = line
        return entries

    def _ftp_write(self, entries: dict[str, str]) -> None:
        header = f"# Virtual FTP users — managed by {config.APP_NAME}."
        body = "\n".join([header, *entries.values()])
        self._ftp_passwd().write_text(body + "\n", encoding="utf-8")

    def create_ftp_account(self, username: str, password: str, home_dir: Path,
                           quota_mb: int = 0) -> None:
        home = Path(home_dir)
        home.mkdir(parents=True, exist_ok=True)
        pwhash = hashlib.sha256(password.encode()).hexdigest()
        entries = self._ftp_entries()
        entries[username] = f"{username}\t{{SHA256}}{pwhash}\t{home.as_posix()}\t{int(quota_mb)}"
        self._ftp_write(entries)

    def set_ftp_password(self, username: str, password: str) -> None:
        entries = self._ftp_entries()
        existing = entries.get(username)
        if existing is None:
            return
        parts = existing.split("\t")
        # parts = [login, "{SHA256}hash", home, quota]
        home = parts[2] if len(parts) > 2 else ""
        quota = parts[3] if len(parts) > 3 else "0"
        pwhash = hashlib.sha256(password.encode()).hexdigest()
        entries[username] = f"{username}\t{{SHA256}}{pwhash}\t{home}\t{quota}"
        self._ftp_write(entries)

    def delete_ftp_account(self, username: str) -> None:
        entries = self._ftp_entries()
        if entries.pop(username, None) is not None:
            self._ftp_write(entries)

    # --- Web Disk (WebDAV) ------------------------------------------------
    def _webdisk_passwd(self) -> Path:
        # Tab-delimited htpasswd-style store, one line per login:
        #   "<login>\t{SHA256}<hash>\t<home_dir>\t<ro|rw>"
        return config.WEBDISK_DIR / "passwd"

    def _webdisk_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        passwd = self._webdisk_passwd()
        if passwd.exists():
            for line in passwd.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "\t" in line:
                    entries[line.split("\t", 1)[0]] = line
        return entries

    def _webdisk_write(self, entries: dict[str, str]) -> None:
        header = f"# Web Disk (WebDAV) users — managed by {config.APP_NAME}."
        body = "\n".join([header, *entries.values()])
        self._webdisk_passwd().write_text(body + "\n", encoding="utf-8")

    def create_webdisk_account(self, username: str, password: str, home_dir: Path,
                               read_only: bool = False) -> None:
        home = Path(home_dir)
        home.mkdir(parents=True, exist_ok=True)
        pwhash = hashlib.sha256(password.encode()).hexdigest()
        mode = "ro" if read_only else "rw"
        entries = self._webdisk_entries()
        entries[username] = f"{username}\t{{SHA256}}{pwhash}\t{home.as_posix()}\t{mode}"
        self._webdisk_write(entries)

    def set_webdisk_password(self, username: str, password: str) -> None:
        entries = self._webdisk_entries()
        existing = entries.get(username)
        if existing is None:
            return
        parts = existing.split("\t")
        home = parts[2] if len(parts) > 2 else ""
        mode = parts[3] if len(parts) > 3 else "rw"
        pwhash = hashlib.sha256(password.encode()).hexdigest()
        entries[username] = f"{username}\t{{SHA256}}{pwhash}\t{home}\t{mode}"
        self._webdisk_write(entries)

    def delete_webdisk_account(self, username: str) -> None:
        entries = self._webdisk_entries()
        if entries.pop(username, None) is not None:
            self._webdisk_write(entries)

    # --- Git version control ----------------------------------------------
    def create_git_repo(self, path: Path, owner: str | None,
                        clone_url: str | None = None) -> None:
        # Simulate a repo on the local filesystem — no git binary required, so
        # the demo works identically on Windows. We lay down a minimal .git
        # marker so the tree is recognizable and records the remote.
        repo = Path(path)
        repo.mkdir(parents=True, exist_ok=True)
        git_dir = repo / ".git"
        git_dir.mkdir(exist_ok=True)
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        remote = f'[remote "origin"]\n\turl = {clone_url}\n' if clone_url else ""
        (git_dir / "config").write_text(
            f"# Simulated repo — managed by {config.APP_NAME}.\n{remote}",
            encoding="utf-8",
        )
        if clone_url:
            (repo / "README.md").write_text(
                f"# Cloned from {clone_url}\n\n(demo provider simulation)\n",
                encoding="utf-8",
            )

    def git_pull(self, path: Path) -> str:
        repo = Path(path)
        if not (repo / ".git").exists():
            return "Not a git repository."
        stamp = datetime.now(timezone.utc).isoformat()
        (repo / ".git" / "FETCH_HEAD").write_text(stamp + "\n", encoding="utf-8")
        return f"Already up to date. (demo pull at {stamp})"

    def delete_git_repo(self, path: Path) -> None:
        import shutil
        shutil.rmtree(Path(path), ignore_errors=True)

    # --- Backups ----------------------------------------------------------
    def create_backup(self, dest_zip: Path, sites: list[tuple[str, str]], databases: list[str]) -> dict:
        import json
        import zipfile

        items = []
        with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest = {"domains": [n for n, _ in sites], "databases": databases,
                        "created": datetime.now(timezone.utc).isoformat()}
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            for name, site_dir in sites:
                site = Path(site_dir)
                if site.exists():
                    for f in site.rglob("*"):
                        if f.is_file():
                            zf.write(f, f"homedir/{name}/{f.relative_to(site).as_posix()}")
                    items.append(f"site:{name}")
                zone = config.DNS_DIR / f"{name}.zone"
                if zone.exists():
                    zf.write(zone, f"dns/{name}.zone")
                    items.append(f"dns:{name}")
                maild = config.MAIL_DIR / name
                if maild.exists():
                    for f in maild.rglob("*"):
                        if f.is_file():
                            zf.write(f, f"mail/{name}/{f.relative_to(maild).as_posix()}")
                    items.append(f"mail:{name}")

            for name in databases:
                dbf = self._db_path(name)
                if dbf.exists():
                    zf.write(dbf, f"databases/{name}.sqlite")
                    items.append(f"db:{name}")

        return {"size_bytes": dest_zip.stat().st_size, "items": items}

    def restore_backup(self, zip_path: Path) -> dict:
        import zipfile

        from .base import safe_extract_path

        # Map each archive prefix to the base dir it may write into.
        bases = {
            "homedir/": config.SITES_DIR,
            "dns/": config.DNS_DIR,
            "mail/": config.MAIL_DIR,
            "databases/": config.DB_SANDBOX_DIR,
        }
        items = []
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue  # directory entry
                base = next((b for p, b in bases.items() if member.startswith(p)), None)
                if base is None:
                    continue  # skip manifest.json and anything unexpected
                rel = member.split("/", 1)[1]
                target = safe_extract_path(base, rel)
                if target is None:
                    continue  # Zip Slip attempt — refuse to write outside base
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as out:
                    out.write(src.read())
                items.append(member)
        return {"items": items}

    # --- Health -----------------------------------------------------------
    def system_stats(self) -> dict:
        # Real numbers via the stdlib metrics sampler (works on Windows dev too).
        import shutil

        from .. import metrics

        try:
            usage = shutil.disk_usage(config.DATA_DIR)
            disk = {
                "total_gb": round(usage.total / 1e9, 1),
                "used_gb": round(usage.used / 1e9, 1),
                "percent": round(usage.used / usage.total * 100, 1),
            }
        except OSError:
            disk = {"total_gb": 0, "used_gb": 0, "percent": 0}

        return {
            "provider": self.name,
            "cpu_percent": metrics.cpu_percent(),
            "mem_percent": metrics.mem_percent(),
            "disk": disk,
        }

    # --- Firewall / security (admin-only) ---------------------------------
    # State lives in two inspectable JSON files under FIREWALL_DIR so the demo
    # shows genuine, persistent results without touching the real OS.
    def _fw_file(self) -> Path:
        return config.FIREWALL_DIR / "firewall.json"

    def _fw_load(self) -> dict:
        import json

        try:
            return json.loads(self._fw_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Seed a sensible default: firewall off, a couple of common rules.
            return {
                "enabled": False,
                "default_incoming": "deny",
                "default_outgoing": "allow",
                "rules": [
                    {"num": 1, "to": "22/tcp", "action": "allow", "source": "Anywhere"},
                    {"num": 2, "to": "80/tcp", "action": "allow", "source": "Anywhere"},
                    {"num": 3, "to": "443/tcp", "action": "allow", "source": "Anywhere"},
                ],
            }

    def _fw_save(self, state: dict) -> None:
        import json

        config.FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
        self._fw_file().write_text(json.dumps(state, indent=2), encoding="utf-8")

    def firewall_status(self) -> dict:
        state = self._fw_load()
        return {
            "backend": "ufw",
            "available": True,
            "active": bool(state.get("enabled")),
            "default_incoming": state.get("default_incoming", "deny"),
            "default_outgoing": state.get("default_outgoing", "allow"),
        }

    def list_firewall_rules(self) -> list[dict]:
        state = self._fw_load()
        if not state.get("enabled"):
            return []
        return state.get("rules", [])

    def set_firewall_enabled(self, enabled: bool) -> tuple[bool, str]:
        state = self._fw_load()
        state["enabled"] = bool(enabled)
        self._fw_save(state)
        return True, f"(demo) firewall {'enabled' if enabled else 'disabled'}"

    def add_firewall_rule(self, port: int, proto: str, action: str,
                          source: str | None = None) -> tuple[bool, str]:
        state = self._fw_load()
        rules = state.setdefault("rules", [])
        next_num = max((r.get("num", 0) for r in rules), default=0) + 1
        rules.append({
            "num": next_num,
            "to": f"{port}/{proto}",
            "action": action,
            "source": source or "Anywhere",
        })
        self._fw_save(state)
        return True, f"(demo) {action} {port}/{proto}"

    def delete_firewall_rule(self, num: int) -> tuple[bool, str]:
        state = self._fw_load()
        rules = state.get("rules", [])
        kept = [r for r in rules if r.get("num") != num]
        if len(kept) == len(rules):
            return False, f"(demo) no rule with index {num}"
        # Renumber so indices stay contiguous, like ufw does.
        for i, r in enumerate(kept, start=1):
            r["num"] = i
        state["rules"] = kept
        self._fw_save(state)
        return True, f"(demo) deleted rule {num}"

    def _f2b_file(self) -> Path:
        return config.FIREWALL_DIR / "fail2ban.json"

    def _f2b_load(self) -> dict:
        import json

        try:
            return json.loads(self._f2b_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"jails": {"sshd": []}}

    def _f2b_save(self, state: dict) -> None:
        import json

        config.FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
        self._f2b_file().write_text(json.dumps(state, indent=2), encoding="utf-8")

    def fail2ban_status(self) -> dict:
        state = self._f2b_load()
        return {
            "available": True,
            "active": True,
            "jails": list(state.get("jails", {}).keys()),
        }

    def list_banned_ips(self, jail: str) -> list[str]:
        state = self._f2b_load()
        return list(state.get("jails", {}).get(jail, []))

    def ban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        state = self._f2b_load()
        jails = state.setdefault("jails", {})
        banned = jails.setdefault(jail, [])
        if ip not in banned:
            banned.append(ip)
        self._f2b_save(state)
        return True, f"(demo) banned {ip} in {jail}"

    def unban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        state = self._f2b_load()
        banned = state.get("jails", {}).get(jail, [])
        if ip in banned:
            banned.remove(ip)
            self._f2b_save(state)
            return True, f"(demo) unbanned {ip} from {jail}"
        return False, f"(demo) {ip} not banned in {jail}"

    # --- IP Blocker -------------------------------------------------------
    # Manual, permanent blocklist. Kept in its own JSON file so it's separate
    # from the fail2ban auto-bans above; the router shows both on one page.
    def _blocked_file(self) -> Path:
        return config.FIREWALL_DIR / "blocked_ips.json"

    def _blocked_load(self) -> dict:
        import json

        try:
            return json.loads(self._blocked_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"blocked": []}

    def _blocked_save(self, state: dict) -> None:
        import json

        config.FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
        self._blocked_file().write_text(json.dumps(state, indent=2), encoding="utf-8")

    def list_blocked_ips(self) -> list[dict]:
        state = self._blocked_load()
        return [
            {"ip": e["ip"], "comment": e.get("comment", ""), "num": i + 1}
            for i, e in enumerate(state.get("blocked", []))
        ]

    def block_ip(self, ip: str, comment: str | None = None) -> tuple[bool, str]:
        from datetime import datetime, timezone

        state = self._blocked_load()
        blocked = state.setdefault("blocked", [])
        if any(e["ip"] == ip for e in blocked):
            return False, f"(demo) {ip} is already blocked"
        blocked.append(
            {"ip": ip, "comment": comment or "",
             "created_at": datetime.now(timezone.utc).isoformat()}
        )
        self._blocked_save(state)
        return True, f"(demo) blocked {ip}"

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        state = self._blocked_load()
        blocked = state.get("blocked", [])
        for i, e in enumerate(blocked):
            if e["ip"] == ip:
                del blocked[i]
                self._blocked_save(state)
                return True, f"(demo) unblocked {ip}"
        return False, f"(demo) {ip} is not blocked"

    # --- ModSecurity WAF --------------------------------------------------
    # A single on/off (+ mode) toggle, kept in its own JSON file so the demo
    # state is inspectable and survives a restart, like the firewall toggle.
    def _modsec_file(self) -> Path:
        return config.FIREWALL_DIR / "modsecurity.json"

    def _modsec_load(self) -> dict:
        import json

        try:
            return json.loads(self._modsec_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"enabled": False, "mode": "On"}

    def _modsec_save(self, state: dict) -> None:
        import json

        config.FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
        self._modsec_file().write_text(json.dumps(state, indent=2), encoding="utf-8")

    def modsecurity_status(self) -> dict:
        state = self._modsec_load()
        return {
            "available": True,
            "enabled": bool(state.get("enabled", False)),
            "mode": state.get("mode", "On"),
            "engine": "ModSecurity 3.x (demo)",
            "ruleset": "OWASP CRS 4.x",
        }

    def set_modsecurity(self, enabled: bool, mode: str = "On") -> tuple[bool, str]:
        if mode not in ("On", "DetectionOnly"):
            return False, f"(demo) invalid mode {mode!r}"
        self._modsec_save({"enabled": bool(enabled), "mode": mode})
        if not enabled:
            return True, "(demo) ModSecurity turned off"
        return True, f"(demo) ModSecurity turned on ({mode})"

    # --- Logs -------------------------------------------------------------
    # The demo has no real /var/log, so it writes small, realistic sample logs
    # under LOG_DIR the first time each is requested. The viewer still only
    # accepts a `key` from this map — never a path.
    _LOG_FILES: dict[str, tuple[str, str, str]] = {
        # key: (label, category, filename under LOG_DIR)
        "nginx-access": ("Nginx — Access", "Web", "access.log"),
        "nginx-error": ("Nginx — Error", "Web", "error.log"),
        "auth": ("System — Auth (SSH/sudo)", "System", "auth.log"),
        "fail2ban": ("Security — fail2ban", "Security", "fail2ban.log"),
        "panel": ("LitesPanel — App", "Panel", "litespanel.log"),
    }

    def _seed_log(self, filename: str) -> Path:
        """Create a sample log file on first use (demo only)."""
        path = config.LOG_DIR / filename
        if path.exists():
            return path
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(_SAMPLE_LOGS.get(filename, "(no sample data)\n"), encoding="utf-8")
        return path

    # --- Per-domain web logs (Metrics) ------------------------------------
    def _domain_log_dir(self) -> Path:
        d = config.LOG_DIR / "domains"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _domain_access_path(self, domain: str) -> Path:
        return self._domain_log_dir() / f"{domain}.access.log"

    def _domain_error_path(self, domain: str) -> Path:
        return self._domain_log_dir() / f"{domain}.error.log"

    def _seed_domain_logs(self, domain: str) -> None:
        """Generate a realistic week of synthetic traffic for a new site.

        Demo-only: real hosts get genuine nginx logs. Deterministic per domain
        so the numbers are stable across page loads.
        """
        access = self._domain_access_path(domain)
        if access.exists():
            return
        import random

        rnd = random.Random(hashlib.sha256(domain.encode()).hexdigest())
        ips = [f"203.0.113.{n}" for n in range(2, 60)] + \
              [f"198.51.100.{n}" for n in range(2, 40)] + \
              [f"192.0.2.{n}" for n in range(2, 30)]
        paths = [
            ("GET", "/", 0.34), ("GET", "/about", 0.10), ("GET", "/blog", 0.12),
            ("GET", "/blog/hello-world", 0.08), ("GET", "/contact", 0.06),
            ("GET", "/static/app.css", 0.09), ("GET", "/static/app.js", 0.08),
            ("GET", "/favicon.ico", 0.05), ("POST", "/contact", 0.03),
            ("GET", "/wp-login.php", 0.02), ("GET", "/.env", 0.015),
            ("GET", "/pricing", 0.045),
        ]
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1 Safari/605.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile/15E148",
            "curl/8.4.0", "python-requests/2.31", "Googlebot/2.1",
        ]
        referers = ["-", f"https://{domain}/", "https://www.google.com/",
                    "https://t.co/abc", "https://news.ycombinator.com/"]
        weighted = [(m, p) for (m, p, _) in paths]
        weights = [w for (_, _, w) in paths]
        lines: list[str] = []
        now = datetime.now(timezone.utc)
        for day_ago in range(6, -1, -1):
            hits = rnd.randint(180, 420)
            for _ in range(hits):
                method, path = rnd.choices(weighted, weights=weights, k=1)[0]
                ts = now - timedelta(days=day_ago, hours=rnd.randint(0, 23),
                                     minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59))
                if path in ("/wp-login.php", "/.env"):
                    status, size = 404, rnd.randint(500, 600)
                elif method == "POST":
                    status, size = 303, 0
                elif rnd.random() < 0.04:
                    status, size = 500, rnd.randint(500, 900)
                else:
                    status, size = 200, rnd.randint(400, 20000)
                stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
                lines.append(
                    f'{rnd.choice(ips)} - - [{stamp}] "{method} {path} HTTP/1.1" '
                    f'{status} {size} "{rnd.choice(referers)}" "{rnd.choice(agents)}"'
                )
        lines.sort(key=lambda ln: datetime.strptime(
            ln.split("[", 1)[1].split("]", 1)[0].split()[0], "%d/%b/%Y:%H:%M:%S"))
        access.write_text("\n".join(lines) + "\n", encoding="utf-8")

        errs = []
        for day_ago in range(3, -1, -1):
            ts = now - timedelta(days=day_ago, hours=rnd.randint(0, 23))
            errs.append(
                f'{ts.strftime("%Y/%m/%d %H:%M:%S")} [error] 812#812: *{rnd.randint(1000, 9999)} '
                f'open() "/home/site/{domain}/public_html/.env" failed (2: No such file '
                f'or directory), client: {rnd.choice(ips)}, server: {domain}'
            )
        self._domain_error_path(domain).write_text("\n".join(errs) + "\n", encoding="utf-8")

    def read_access_log(self, domain: str, max_lines: int = 20000) -> list[str]:
        self._seed_domain_logs(domain)
        path = self._domain_access_path(domain)
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()[-max_lines:]

    def read_error_log(self, domain: str, max_lines: int = 200) -> list[str]:
        self._seed_domain_logs(domain)
        path = self._domain_error_path(domain)
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()[-max_lines:]

    def log_sources(self) -> list[dict]:
        sources = []
        for key, (label, category, filename) in self._LOG_FILES.items():
            self._seed_log(filename)
            sources.append({"key": key, "label": label, "category": category})
        return sources

    def read_log(self, key: str, lines: int = 200, grep: str | None = None) -> tuple[bool, str]:
        entry = self._LOG_FILES.get(key)
        if entry is None:
            return False, "unknown log source"
        from .base import tail_file

        path = self._seed_log(entry[2])
        return True, tail_file(path, lines=lines, grep=grep)
