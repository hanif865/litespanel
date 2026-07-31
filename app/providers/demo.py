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
from .base import CertInfo, DbCredentials, Provider

_NGINX_TEMPLATE = """# Managed by {app} — do not edit by hand.
server {{
    listen 80;
    server_name {domain} www.{domain};
    root {docroot};
    index index.html index.php;

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
        return docroot

    def _write_vhost(self, domain: str, docroot: Path, php_version: str, system_user: str) -> None:
        # In the demo the PHP socket name shows the per-user pool for clarity.
        vhost = config.NGINX_DIR / f"{domain}.conf"
        text = _NGINX_TEMPLATE.format(
            app=config.APP_NAME, domain=domain, docroot=Path(docroot).as_posix(), php=php_version
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
            app=config.APP_NAME, domain=domain, docroot=Path(docroot).as_posix(), php=php_version
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

    def deploy_node_app(self, name: str, domain: str, app_dir: Path, port: int,
                        entrypoint: str, system_user: str, node_version: str) -> tuple[bool, str]:
        app_dir = Path(app_dir)
        app_dir.mkdir(parents=True, exist_ok=True)
        # Write an inspectable systemd unit so the demo shows what Linux would do.
        unit = config.NODE_DIR / f"litespanel-node-{name}.service"
        unit.write_text(
            "[Unit]\n"
            f"Description=LitesPanel Node app {name} ({domain})\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={system_user}\n"
            f"WorkingDirectory={app_dir.as_posix()}\n"
            "Environment=NODE_ENV=production\n"
            f"Environment=PORT={port}\n"
            f"ExecStart=/usr/bin/node {entrypoint}\n"
            "Restart=on-failure\nRestartSec=5\n\n"
            "[Install]\nWantedBy=multi-user.target\n",
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
        (config.NGINX_DIR / f"{domain}.conf").unlink(missing_ok=True)

    def node_app_status(self, name: str) -> str:
        f = self._node_status_file(name)
        return f.read_text(encoding="utf-8").strip() if f.exists() else "unknown"

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
