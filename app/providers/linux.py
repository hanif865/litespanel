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

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from .base import CertInfo, DbCredentials, Provider

# On Debian/Ubuntu these are the conventional locations.
NGINX_SITES = Path("/etc/nginx/sites-enabled")
WEB_ROOT = Path("/var/www")

# Database/user names must be plain identifiers — validated here as defense in
# depth so a bad name can never be interpolated into SQL, even if a caller
# forgets to check.
_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _ident(value: str, what: str) -> str:
    if not _IDENT_RE.match(value):
        raise ValueError(f"Unsafe {what}: {value!r}")
    return value


def _mysql_str(value: str) -> str:
    """Escape a value for use inside a single-quoted MySQL string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _run(cmd: list[str]) -> str:
    """Run a command, raising with captured output on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return result.stdout


class LinuxProvider(Provider):
    name = "linux"

    # --- Accounts (system-user isolation) ---------------------------------
    def ensure_account(self, username: str) -> Path:
        _ident(username, "account username")
        home = Path("/home") / username
        # Create the system user if it doesn't exist (no shell login).
        if subprocess.run(["id", username], capture_output=True).returncode != 0:
            _run(["useradd", "--create-home", "--home-dir", str(home),
                  "--shell", "/usr/sbin/nologin", username])
        # A dedicated PHP-FPM pool makes this account's PHP run AS this user,
        # so its sites can't read another account's files.
        self._write_php_pool(username)
        # Let nginx (www-data) traverse into the account to reach public_html.
        _run(["chmod", "751", str(home)])
        return home

    def remove_account(self, username: str) -> None:
        _ident(username, "account username")
        pool = Path(f"/etc/php/{config.PHP_FPM_VERSION}/fpm/pool.d/{username}.conf")
        pool.unlink(missing_ok=True)
        self._reload_php()
        # Only delete real per-account homes, never a pre-existing system user.
        if (Path("/home") / username).is_dir():
            subprocess.run(["userdel", "--remove", username], capture_output=True)

    def _php_sock(self, username: str) -> str:
        return f"/run/php/{username}.sock"

    def _write_php_pool(self, username: str) -> None:
        pool = Path(f"/etc/php/{config.PHP_FPM_VERSION}/fpm/pool.d/{username}.conf")
        pool.write_text(
            f"[{username}]\n"
            f"user = {username}\n"
            f"group = {username}\n"
            f"listen = {self._php_sock(username)}\n"
            f"listen.owner = www-data\n"
            f"listen.group = www-data\n"
            f"pm = ondemand\n"
            f"pm.max_children = 5\n"
            f"pm.process_idle_timeout = 10s\n"
            f"pm.max_requests = 500\n"
            f"chdir = /\n"
        )
        self._reload_php()

    def _reload_php(self) -> None:
        _run(["systemctl", "reload", f"php{config.PHP_FPM_VERSION}-fpm"])

    def _vhost(self, server_name: str, extra_names: str, docroot: Path, username: str) -> str:
        return (
            f"server {{\n    listen 80;\n    server_name {server_name}{extra_names};\n"
            f"    root {docroot};\n    index index.php index.html;\n"
            f"    location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(username)};"
            f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}\n}}\n"
        )

    # --- Web hosting ------------------------------------------------------
    def create_site(self, domain: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        docroot.mkdir(parents=True, exist_ok=True)
        # Hand ownership of the whole site tree to the account.
        _run(["chown", "-R", f"{system_user}:{system_user}", str(Path(docroot).parent)])
        (NGINX_SITES / f"{domain}.conf").write_text(
            self._vhost(domain, f" www.{domain}", docroot, system_user)
        )
        self.reload_web()
        return docroot

    def remove_site(self, domain: str) -> None:
        (NGINX_SITES / f"{domain}.conf").unlink(missing_ok=True)
        self.reload_web()

    def reload_web(self) -> None:
        _run(["nginx", "-t"])          # validate before applying
        _run(["systemctl", "reload", "nginx"])

    def set_php_version(self, domain: str, docroot: str, php_version: str, system_user: str) -> None:
        # The socket is per-account (not per-version); rewrite the whole vhost.
        (NGINX_SITES / f"{domain}.conf").write_text(
            self._vhost(domain, f" www.{domain}", Path(docroot), system_user)
        )
        self.reload_web()

    def set_https_redirect(self, domain: str, docroot: str, php_version: str,
                           system_user: str, enabled: bool, has_ssl: bool) -> None:
        _ident(system_user, "account username")
        docroot = Path(docroot)
        names = f"{domain} www.{domain}"
        php = (f"location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(system_user)};"
               f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}")
        blocks = []
        if has_ssl:
            cert = f"/etc/letsencrypt/live/{domain}"
            if enabled:
                blocks.append(f"server {{ listen 80; server_name {names};"
                              f" return 301 https://$host$request_uri; }}")
            else:
                blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                              f" index index.php index.html; {php} }}")
            blocks.append(f"server {{ listen 443 ssl; server_name {names};"
                          f" ssl_certificate {cert}/fullchain.pem; ssl_certificate_key {cert}/privkey.pem;"
                          f" root {docroot}; index index.php index.html; {php} }}")
        else:
            blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                          f" index index.php index.html; {php} }}")
        (NGINX_SITES / f"{domain}.conf").write_text("\n".join(blocks) + "\n")
        self.reload_web()

    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        docroot.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", f"{system_user}:{system_user}", str(docroot)])
        (NGINX_SITES / f"{fqdn}.conf").write_text(self._vhost(fqdn, "", docroot, system_user))
        self.reload_web()
        return docroot

    def remove_subdomain(self, fqdn: str) -> None:
        (NGINX_SITES / f"{fqdn}.conf").unlink(missing_ok=True)
        self.reload_web()

    def set_owner(self, path: Path, system_user: str) -> None:
        _ident(system_user, "account username")
        if Path(path).exists():
            _run(["chown", "-R", f"{system_user}:{system_user}", str(path)])

    def run_wp_cli(self, docroot: Path, system_user: str, args: list[str]) -> tuple[bool, str]:
        _ident(system_user, "account username")
        wp = Path("/usr/local/bin/wp")
        if not wp.exists():
            subprocess.run(["curl", "-fsSL", config.WP_CLI_URL, "-o", str(wp)], capture_output=True)
            wp.chmod(0o755)
        # Run as the account user so files stay owned by them.
        cmd = ["runuser", "-u", system_user, "--", str(wp), f"--path={docroot}"] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0, (result.stdout + result.stderr).strip()

    def sync_cron(self, lines: list[str]) -> None:
        # Pipe the full crontab to `crontab -` (replaces the user's crontab).
        text = "# Managed by panel\n" + "\n".join(lines) + "\n"
        result = subprocess.run(["crontab", "-"], input=text, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"crontab update failed: {result.stderr.strip()}")

    def db_tables(self, name: str) -> list[str]:
        _ident(name, "database name")
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
        # Names are validated to plain identifiers; the password is escaped for
        # the SQL string literal so it can't break out or inject.
        _ident(name, "database name")
        _ident(user, "database user")
        pw = _mysql_str(password)
        sql = (
            f"CREATE DATABASE `{name}`; "
            f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{pw}'; "
            f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; "
            f"FLUSH PRIVILEGES;"
        )
        _run(["mysql", "-e", sql])
        return DbCredentials(name=name, user=user, password=password)

    def drop_database(self, name: str, user: str) -> None:
        _ident(name, "database name")
        _ident(user, "database user")
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
        # Postfix/Dovecot virtual-mailbox setup (see setup-mail.sh):
        #   - Maildir under /var/mail/vhosts, owned by the vmail user
        #   - a Dovecot passwd-file entry (SHA512-CRYPT hash)
        #   - the domain registered as a Postfix virtual mailbox domain
        local, _, domain = address.partition("@")
        maildir = Path(f"/var/mail/vhosts/{domain}/{local}/Maildir")
        for sub in ("cur", "new", "tmp"):
            (maildir / sub).mkdir(parents=True, exist_ok=True)
        if subprocess.run(["id", "vmail"], capture_output=True).returncode == 0:
            _run(["chown", "-R", "vmail:vmail", f"/var/mail/vhosts/{domain}"])

        hashed = _run(["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password]).strip()
        users = Path("/etc/dovecot/users")
        lines = [l for l in (users.read_text().splitlines() if users.exists() else [])
                 if not l.startswith(f"{address}:")]
        lines.append(f"{address}:{hashed}::::::userdb_quota_rule=*:storage={quota_mb}M")
        users.write_text("\n".join(lines) + "\n")

        self._register_mail_domain(domain)

    def delete_mailbox(self, address: str) -> None:
        import shutil

        local, _, domain = address.partition("@")
        shutil.rmtree(f"/var/mail/vhosts/{domain}/{local}", ignore_errors=True)
        users = Path("/etc/dovecot/users")
        if users.exists():
            kept = [ln for ln in users.read_text().splitlines() if not ln.startswith(f"{address}:")]
            users.write_text("\n".join(kept) + "\n")

    def _register_mail_domain(self, domain: str) -> None:
        """Add the domain to Postfix's virtual-mailbox domain list and reload."""
        vdomains = Path("/etc/postfix/vhost_domains")
        if not vdomains.exists():
            return  # mail stack not installed (setup-mail.sh); nothing to do
        existing = vdomains.read_text().split()
        if domain not in existing:
            existing.append(domain)
            vdomains.write_text("\n".join(existing) + "\n")
            subprocess.run(["systemctl", "reload", "postfix"], capture_output=True)

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

    def create_backup(self, dest_zip: Path, sites: list[tuple[str, str]], databases: list[str]) -> dict:
        import zipfile

        items = []
        with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, site_dir in sites:
                site = Path(site_dir)
                if site.exists():
                    for f in site.rglob("*"):
                        if f.is_file():
                            zf.write(f, f"homedir/{name}/{f.relative_to(site).as_posix()}")
                    items.append(f"site:{name}")
            for name in databases:
                # mysqldump each database into the archive.
                dump = subprocess.run(["mysqldump", name], capture_output=True, text=True)
                if dump.returncode == 0:
                    zf.writestr(f"databases/{name}.sql", dump.stdout)
                    items.append(f"db:{name}")
        return {"size_bytes": dest_zip.stat().st_size, "items": items}

    def restore_backup(self, zip_path: Path) -> dict:
        import zipfile

        from .base import safe_extract_path

        items = []
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                if member.startswith("homedir/"):
                    target = safe_extract_path(WEB_ROOT, member[len("homedir/"):])
                    if target is None:
                        continue  # Zip Slip attempt
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as out:
                        out.write(src.read())
                    items.append(member)
                elif member.startswith("databases/") and member.endswith(".sql"):
                    name = Path(member).stem
                    _ident(name, "database name")
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
