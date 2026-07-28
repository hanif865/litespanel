"""Linux provider — runs the real system tools on a VPS.

This is the production implementation. It is intentionally a thin, auditable
skeleton: each method maps to the exact shell command a sysadmin would run.
Enable it with PANEL_PROVIDER=linux. Requires the panel process to have the
right privileges (typically via sudo rules scoped to these specific commands,
NOT blanket root).

Left as documented stubs where a step needs host-specific decisions (PHP-FPM
socket paths, MySQL admin auth). Fill these in for your distro before use.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from .base import CertInfo, DbCredentials, Provider

# On Debian/Ubuntu these are the conventional locations.
NGINX_SITES = Path("/etc/nginx/sites-enabled")
WEB_ROOT = Path("/var/www")


def _run(cmd: list[str]) -> str:
    """Run a command, raising with captured output on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return result.stdout


class LinuxProvider(Provider):
    name = "linux"

    def create_site(self, domain: str, php_version: str) -> Path:
        docroot = WEB_ROOT / domain / "public_html"
        docroot.mkdir(parents=True, exist_ok=True)
        vhost = NGINX_SITES / f"{domain}.conf"
        vhost.write_text(
            f"server {{\n    listen 80;\n    server_name {domain} www.{domain};\n"
            f"    root {docroot};\n    index index.php index.html;\n"
            f"    location ~ \\.php$ {{ fastcgi_pass unix:/run/php/php{php_version}-fpm.sock;"
            f" include fastcgi_params; }}\n}}\n"
        )
        self.reload_web()
        return docroot

    def remove_site(self, domain: str) -> None:
        (NGINX_SITES / f"{domain}.conf").unlink(missing_ok=True)
        self.reload_web()

    def reload_web(self) -> None:
        _run(["nginx", "-t"])          # validate before applying
        _run(["systemctl", "reload", "nginx"])

    def set_php_version(self, domain: str, docroot: str, php_version: str) -> None:
        vhost = NGINX_SITES / f"{domain}.conf"
        text = vhost.read_text() if vhost.exists() else ""
        import re

        text = re.sub(r"php\d+\.\d+-fpm\.sock", f"php{php_version}-fpm.sock", text)
        vhost.write_text(text)
        self.reload_web()

    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str) -> Path:
        docroot.mkdir(parents=True, exist_ok=True)
        vhost = NGINX_SITES / f"{fqdn}.conf"
        vhost.write_text(
            f"server {{\n    listen 80;\n    server_name {fqdn};\n    root {docroot};\n"
            f"    index index.php index.html;\n"
            f"    location ~ \\.php$ {{ fastcgi_pass unix:/run/php/php{php_version}-fpm.sock;"
            f" include fastcgi_params; }}\n}}\n"
        )
        self.reload_web()
        return docroot

    def remove_subdomain(self, fqdn: str) -> None:
        (NGINX_SITES / f"{fqdn}.conf").unlink(missing_ok=True)
        self.reload_web()

    def sync_cron(self, lines: list[str]) -> None:
        # Pipe the full crontab to `crontab -` (replaces the user's crontab).
        text = "# Managed by panel\n" + "\n".join(lines) + "\n"
        result = subprocess.run(["crontab", "-"], input=text, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"crontab update failed: {result.stderr.strip()}")

    def db_tables(self, name: str) -> list[str]:
        out = _run(["mysql", "-N", "-e", f"SHOW TABLES FROM `{name}`;"])
        return [line.strip() for line in out.splitlines() if line.strip()]

    def db_execute(self, name: str, sql: str) -> dict:
        # For production, prefer embedding real phpMyAdmin (set PANEL_PHPMYADMIN_URL)
        # over this raw passthrough. Kept minimal and tab-delimited.
        result = {"columns": [], "rows": [], "message": "", "error": ""}
        proc = subprocess.run(
            ["mysql", "--batch", name, "-e", sql], capture_output=True, text=True
        )
        if proc.returncode != 0:
            result["error"] = proc.stderr.strip()
            return result
        out_lines = proc.stdout.splitlines()
        if out_lines:
            result["columns"] = out_lines[0].split("\t")
            result["rows"] = [ln.split("\t") for ln in out_lines[1:]]
            result["message"] = f"{len(result['rows'])} row(s) returned."
        else:
            result["message"] = "OK."
        return result

    def create_database(self, name: str, user: str, password: str) -> DbCredentials:
        # NOTE: supply MySQL admin auth via ~/.my.cnf or a socket, never inline.
        sql = (
            f"CREATE DATABASE `{name}`; "
            f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{password}'; "
            f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; "
            f"FLUSH PRIVILEGES;"
        )
        _run(["mysql", "-e", sql])
        return DbCredentials(name=name, user=user, password=password)

    def drop_database(self, name: str, user: str) -> None:
        _run(["mysql", "-e", f"DROP DATABASE IF EXISTS `{name}`; DROP USER IF EXISTS '{user}'@'localhost';"])

    def issue_certificate(self, domain: str) -> CertInfo:
        _run([
            "certbot", "--nginx", "-d", domain, "-d", f"www.{domain}",
            "--non-interactive", "--agree-tos", "-m", f"admin@{domain}",
        ])
        now = datetime.now(timezone.utc)
        from datetime import timedelta

        return CertInfo(
            issuer="Let's Encrypt",
            issued_at=now,
            expires_at=now + timedelta(days=90),
            cert_path=f"/etc/letsencrypt/live/{domain}/fullchain.pem",
        )

    def revoke_certificate(self, domain: str) -> None:
        _run(["certbot", "revoke", "--cert-name", domain, "--non-interactive"])

    def sync_zone(self, domain: str, records: list[dict]) -> None:
        # Write a BIND zone file, then reload. Path/reload command vary by distro
        # and DNS server (BIND vs PowerDNS) — adjust for your setup.
        zone_path = Path(f"/etc/bind/zones/db.{domain}")
        lines = [f"$TTL 14400", f"@ IN SOA ns1.{domain}. admin.{domain}. (1 3600 900 604800 86400)"]
        for r in records:
            name = r.get("name") or "@"
            if r["type"] == "MX":
                lines.append(f"{name} IN MX {r.get('priority', 10)} {r['value']}")
            elif r["type"] == "TXT":
                lines.append(f'{name} IN TXT "{r["value"]}"')
            else:
                lines.append(f"{name} IN {r['type']} {r['value']}")
        zone_path.write_text("\n".join(lines) + "\n")
        _run(["rndc", "reload", domain])

    def create_mailbox(self, address: str, password: str, quota_mb: int) -> None:
        # Typical Postfix/Dovecot virtual-mailbox setup: append to the virtual
        # users DB and create the Maildir. Exact mechanism depends on your MTA.
        local, _, domain = address.partition("@")
        maildir = Path(f"/var/mail/vhosts/{domain}/{local}")
        maildir.mkdir(parents=True, exist_ok=True)
        # doveadm computes the password hash for the Dovecot passdb.
        hashed = _run(["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password]).strip()
        with open("/etc/dovecot/users", "a") as f:
            f.write(f"{address}:{hashed}::::::userdb_quota_rule=*:storage={quota_mb}M\n")

    def delete_mailbox(self, address: str) -> None:
        import shutil

        local, _, domain = address.partition("@")
        shutil.rmtree(f"/var/mail/vhosts/{domain}/{local}", ignore_errors=True)
        users = Path("/etc/dovecot/users")
        if users.exists():
            kept = [ln for ln in users.read_text().splitlines() if not ln.startswith(f"{address}:")]
            users.write_text("\n".join(kept) + "\n")

    def sync_forwarders(self, domain: str, pairs: list[tuple[str, str]]) -> None:
        # Append/refresh this domain's block in Postfix's virtual alias map,
        # then rebuild the hashed map. (A per-domain include file is cleaner in
        # production; kept simple here.)
        vmap = Path("/etc/postfix/virtual")
        lines = vmap.read_text().splitlines() if vmap.exists() else []
        kept = [ln for ln in lines if not ln.strip().endswith(f"@{domain}") and f"@{domain}\t" not in ln]
        for source, dest in pairs:
            kept.append(f"{source}@{domain}\t{dest}")
        vmap.write_text("\n".join(kept) + "\n")
        _run(["postmap", str(vmap)])

    def set_autoresponder(self, address: str, subject: str, body: str, enabled: bool) -> None:
        # Production would install a Sieve vacation script for the mailbox.
        local, _, domain = address.partition("@")
        sieve = Path(f"/var/mail/vhosts/{domain}/{local}/.dovecot.sieve")
        if not enabled:
            sieve.unlink(missing_ok=True)
            return
        sieve.parent.mkdir(parents=True, exist_ok=True)
        sieve.write_text(
            'require ["vacation"];\n'
            f'vacation :days 1 :subject "{subject}" "{body}";\n'
        )

    def remove_autoresponder(self, address: str) -> None:
        local, _, domain = address.partition("@")
        Path(f"/var/mail/vhosts/{domain}/{local}/.dovecot.sieve").unlink(missing_ok=True)

    def create_backup(self, dest_zip: Path, domains: list[str], databases: list[str]) -> dict:
        import zipfile

        items = []
        with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for d in domains:
                site = WEB_ROOT / d
                if site.exists():
                    for f in site.rglob("*"):
                        if f.is_file():
                            zf.write(f, f"homedir/{d}/{f.relative_to(site).as_posix()}")
                    items.append(f"site:{d}")
            for name in databases:
                # mysqldump each database into the archive.
                dump = subprocess.run(["mysqldump", name], capture_output=True, text=True)
                if dump.returncode == 0:
                    zf.writestr(f"databases/{name}.sql", dump.stdout)
                    items.append(f"db:{name}")
        return {"size_bytes": dest_zip.stat().st_size, "items": items}

    def restore_backup(self, zip_path: Path) -> dict:
        import zipfile

        items = []
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                if member.startswith("homedir/"):
                    target = WEB_ROOT / member[len("homedir/"):]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as out:
                        out.write(src.read())
                    items.append(member)
                elif member.startswith("databases/") and member.endswith(".sql"):
                    name = Path(member).stem
                    sql = zf.read(member).decode()
                    subprocess.run(["mysql", name], input=sql, text=True)
                    items.append(member)
        return {"items": items}

    def system_stats(self) -> dict:
        # Zero-dependency metrics via the shared /proc-based sampler.
        import shutil

        from .. import metrics

        stats = {
            "provider": self.name,
            "cpu_percent": metrics.cpu_percent(),
            "mem_percent": metrics.mem_percent(),
            "disk": {},
        }
        try:
            u = shutil.disk_usage("/")
            stats["disk"] = {
                "total_gb": round(u.total / 1e9, 1),
                "used_gb": round(u.used / 1e9, 1),
                "percent": round(u.used / u.total * 100, 1),
            }
        except OSError:
            pass
        return stats
