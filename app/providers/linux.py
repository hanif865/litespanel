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
# Web Disk (WebDAV) artifacts: a shared htpasswd credential store plus a
# per-login nginx dav location snippet an admin includes into a WebDAV server
# block. Kept out of sites-enabled so it never disturbs a real vhost.
WEBDAV_DIR = Path("/etc/litespanel/webdav")
# Per-domain nginx access/error logs (Metrics). nginx (running as root at
# master, workers as www-data) opens these for writing, so the directory must
# exist before a vhost referencing it is loaded.
WEBLOG_DIR = Path("/var/log/litespanel")

# Database/user names must be plain identifiers — validated here as defense in
# depth so a bad name can never be interpolated into SQL, even if a caller
# forgets to check.
_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
# Node app slug (systemd unit name) and entrypoint file — kept strict so they
# can never inject extra directives into the generated unit file.
_NODE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_ENTRY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/ -]{0,254}$")
# Firewall inputs — validated before ever reaching ufw/fail2ban-client argv so a
# crafted port/source can't turn into an extra argument.
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"            # IPv4 or IPv4/CIDR
    r"|^([0-9a-fA-F:]+)(/\d{1,3})?$"                  # IPv6 or IPv6/CIDR
)


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

    def _write_php_pool(self, username: str,
                        directives: dict[str, str] | None = None,
                        reload: bool = True) -> None:
        pool = Path(f"/etc/php/{config.PHP_FPM_VERSION}/fpm/pool.d/{username}.conf")
        lines = [
            f"[{username}]",
            f"user = {username}",
            f"group = {username}",
            f"listen = {self._php_sock(username)}",
            "listen.owner = www-data",
            "listen.group = www-data",
            "pm = ondemand",
            "pm.max_children = 5",
            "pm.process_idle_timeout = 10s",
            "pm.max_requests = 500",
            "chdir = /",
        ]
        # Per-account php.ini overrides live in the pool as php_admin_value /
        # php_admin_flag — this is the only place PHP-FPM honours that syntax.
        # (A conf.d .ini file is plain php.ini and ignores it entirely.)
        for key in sorted(directives or {}):
            value = str(directives[key]).replace("\n", " ").strip()
            if value in ("On", "Off", "on", "off", "1", "0"):
                lines.append(f"php_admin_flag[{key}] = {value}")
            else:
                lines.append(f"php_admin_value[{key}] = {value}")
        pool.write_text("\n".join(lines) + "\n")
        if reload:
            self._reload_php()

    def _reload_php(self) -> None:
        _run(["systemctl", "reload", f"php{config.PHP_FPM_VERSION}-fpm"])

    def _ensure_weblog_dir(self) -> None:
        """Make sure /var/log/litespanel exists before nginx opens a log there."""
        WEBLOG_DIR.mkdir(parents=True, exist_ok=True)

    def _vhost(self, server_name: str, extra_names: str, docroot: Path, username: str) -> str:
        return (
            f"server {{\n    listen 80;\n    server_name {server_name}{extra_names};\n"
            f"    root {docroot};\n    index index.php index.html;\n"
            f"    access_log /var/log/litespanel/{server_name}.access.log;\n"
            f"    error_log /var/log/litespanel/{server_name}.error.log;\n"
            f"    location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(username)};"
            f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}\n}}\n"
        )

    # --- Web hosting ------------------------------------------------------
    def create_site(self, domain: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        self._ensure_weblog_dir()
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

    def apply_php_config(self, system_user: str, php_version: str,
                         extensions: dict[str, bool], directives: dict[str, str],
                         domain: str | None = None) -> None:
        _ident(system_user, "account username")
        from .. import php_catalog

        # php.ini directives are enforced through the account's PHP-FPM pool
        # (php_admin_value / php_admin_flag). Rewrite the pool with them baked
        # in; a single reload at the end applies both directives and extensions.
        self._write_php_pool(system_user, directives=directives, reload=False)

        # Remove the stale override file written by an earlier buggy version:
        # it lived in conf.d as pool syntax, which php.ini silently ignored.
        old = Path(f"/etc/php/{config.PHP_FPM_VERSION}/fpm/conf.d/zz-panel-{system_user}.ini")
        old.unlink(missing_ok=True)

        # Extensions are enabled/disabled with Debian's phpenmod/phpdismod,
        # the supported way to toggle apt-provided modules per SAPI. Built-in
        # and non-apt extensions are skipped (nothing to toggle).
        loaded = self.list_installed_extensions(php_version)
        for name in sorted(extensions):
            if php_catalog.apt_package(name, php_version) is None:
                continue
            want = extensions[name]
            action = None
            if want and name not in loaded:
                action = "phpenmod"
            elif not want and name in loaded:
                action = "phpdismod"
            if action:
                # Best-effort: a missing mods-available entry (extension not
                # actually installed yet) must not abort saving the directives.
                try:
                    _run([action, "-v", php_version, "-s", "fpm", name])
                except RuntimeError:
                    pass

        self._reload_php()

    # --- PHP extension packages -------------------------------------------
    _EXT_NAME_RE = re.compile(r"^[a-z0-9_]{1,40}$")

    def list_installed_extensions(self, php_version: str) -> set[str]:
        # `php -m` lists the modules loaded for the CLI SAPI; close enough to
        # what FPM loads for the UI's "installed?" indicator. Names are
        # lowercased to match the catalog.
        proc = subprocess.run(
            [f"php{php_version}", "-m"], capture_output=True, text=True
        )
        if proc.returncode != 0:
            return set()
        return {
            line.strip().lower()
            for line in proc.stdout.splitlines()
            if line.strip() and not line.startswith("[")
        }

    def _ext_package(self, extension: str, php_version: str) -> str:
        from .. import php_catalog

        if not self._EXT_NAME_RE.match(extension):
            raise ValueError(f"Unsafe extension name: {extension!r}")
        if not re.match(r"^\d+\.\d+$", php_version):
            raise ValueError(f"Unsafe PHP version: {php_version!r}")
        pkg = php_catalog.apt_package(extension, php_version)
        if pkg is None:
            raise ValueError(f"No installable apt package for {extension!r}")
        return pkg

    def _apt(self, action: str, extension: str, php_version: str) -> tuple[bool, str]:
        import os

        try:
            pkg = self._ext_package(extension, php_version)
        except ValueError as exc:
            return False, str(exc)
        proc = subprocess.run(
            ["apt-get", action, "-y", pkg],
            capture_output=True, text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            timeout=300,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        self._reload_php()
        verb = "Installed" if action == "install" else "Removed"
        return True, f"{verb} {pkg}."

    def install_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        return self._apt("install", extension, php_version)

    def uninstall_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        return self._apt("remove", extension, php_version)

    def set_https_redirect(self, domain: str, docroot: str, php_version: str,
                           system_user: str, enabled: bool, has_ssl: bool) -> None:
        _ident(system_user, "account username")
        self._ensure_weblog_dir()
        docroot = Path(docroot)
        names = f"{domain} www.{domain}"
        logs = (f" access_log /var/log/litespanel/{domain}.access.log;"
                f" error_log /var/log/litespanel/{domain}.error.log;")
        php = (f"location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(system_user)};"
               f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}")
        blocks = []
        if has_ssl:
            cert = f"/etc/letsencrypt/live/{domain}"
            if enabled:
                blocks.append(f"server {{ listen 80; server_name {names};"
                              f"{logs} return 301 https://$host$request_uri; }}")
            else:
                blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                              f" index index.php index.html;{logs} {php} }}")
            blocks.append(f"server {{ listen 443 ssl; server_name {names};"
                          f" ssl_certificate {cert}/fullchain.pem; ssl_certificate_key {cert}/privkey.pem;"
                          f" root {docroot}; index index.php index.html;{logs} {php} }}")
        else:
            blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                          f" index index.php index.html;{logs} {php} }}")
        (NGINX_SITES / f"{domain}.conf").write_text("\n".join(blocks) + "\n")
        self.reload_web()

    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        self._ensure_weblog_dir()
        docroot.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", f"{system_user}:{system_user}", str(docroot)])
        (NGINX_SITES / f"{fqdn}.conf").write_text(self._vhost(fqdn, "", docroot, system_user))
        self.reload_web()
        return docroot

    # --- Node.js (admin-only) ---------------------------------------------
    def _node_unit_path(self, name: str) -> Path:
        if not _NODE_NAME_RE.match(name):
            raise ValueError(f"Unsafe node app name: {name!r}")
        return Path(f"/etc/systemd/system/litespanel-node-{name}.service")

    def install_node(self, version: str) -> tuple[bool, str]:
        import os

        if not re.match(r"^\d{1,2}$", version):
            return False, f"Unsafe Node version: {version!r}"
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        # NodeSource: fetch the setup script for this major, run it (adds the
        # apt repo + key), then install the nodejs package.
        setup = Path("/tmp/nodesource_setup.sh")
        try:
            _run(["curl", "-fsSL", f"https://deb.nodesource.com/setup_{version}.x",
                  "-o", str(setup)])
        except RuntimeError as exc:
            return False, f"Could not fetch NodeSource setup: {exc}"
        proc = subprocess.run(["bash", str(setup)], capture_output=True, text=True,
                              env=env, timeout=300)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        proc = subprocess.run(["apt-get", "install", "-y", "nodejs"],
                              capture_output=True, text=True, env=env, timeout=600)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        installed = self.node_installed_version() or f"{version}.x"
        return True, f"Installed Node.js {installed}."

    def node_installed_version(self) -> str | None:
        # `node` is only present once the admin installs the runtime, so a fresh
        # box legitimately has no binary. subprocess.run raises FileNotFoundError
        # (not a non-zero return) when the command is missing — catch it so the
        # Node page renders "not installed" instead of 500ing.
        try:
            proc = subprocess.run(["node", "--version"], capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.strip().lstrip("v") or None

    def _node_proxy_vhost(self, domain: str, port: int) -> str:
        names = f"{domain} www.{domain}"
        return (
            f"server {{\n    listen 80;\n    server_name {names};\n"
            f"    location / {{\n"
            f"        proxy_pass http://127.0.0.1:{port};\n"
            f"        proxy_http_version 1.1;\n"
            f"        proxy_set_header Upgrade $http_upgrade;\n"
            f"        proxy_set_header Connection \"upgrade\";\n"
            f"        proxy_set_header Host $host;\n"
            f"        proxy_set_header X-Real-IP $remote_addr;\n"
            f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
            f"    }}\n}}\n"
        )

    def deploy_node_app(self, name: str, domain: str, app_dir: Path, port: int,
                        entrypoint: str, system_user: str, node_version: str) -> tuple[bool, str]:
        _ident(system_user, "account username")
        try:
            unit = self._node_unit_path(name)
        except ValueError as exc:
            return False, str(exc)
        if not _ENTRY_RE.match(entrypoint):
            return False, f"Unsafe entrypoint: {entrypoint!r}"
        if not (1024 <= int(port) <= 65535):
            return False, f"Port out of range: {port}"
        node_bin = "/usr/bin/node"
        if not Path(node_bin).exists():
            node_bin = "/usr/bin/env node"

        app_dir = Path(app_dir)
        app_dir.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", f"{system_user}:{system_user}", str(app_dir)])

        unit.write_text(
            "[Unit]\n"
            f"Description=LitesPanel Node app {name} ({domain})\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={system_user}\n"
            f"WorkingDirectory={app_dir}\n"
            "Environment=NODE_ENV=production\n"
            f"Environment=PORT={int(port)}\n"
            f"ExecStart={node_bin} {entrypoint}\n"
            "Restart=on-failure\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        # Point the domain's vhost at the Node process.
        (NGINX_SITES / f"{domain}.conf").write_text(self._node_proxy_vhost(domain, int(port)))

        _run(["systemctl", "daemon-reload"])
        try:
            _run(["systemctl", "enable", "--now", unit.name])
        except RuntimeError as exc:
            # The unit is installed and nginx is pointed at it, but the app
            # failed to start (missing deps, bad entrypoint). Surface it rather
            # than pretend success — admin can fix and hit Restart.
            self.reload_web()
            return False, f"Deployed, but the service failed to start: {exc}"
        self.reload_web()
        return True, f"Node app '{name}' is running on port {port}, serving {domain}."

    def control_node_app(self, name: str, action: str) -> tuple[bool, str]:
        if action not in ("start", "stop", "restart"):
            return False, f"Unknown action: {action}"
        try:
            unit = self._node_unit_path(name)
        except ValueError as exc:
            return False, str(exc)
        try:
            _run(["systemctl", action, unit.name])
        except RuntimeError as exc:
            return False, str(exc)
        past = {"start": "started", "stop": "stopped", "restart": "restarted"}[action]
        return True, f"{past.capitalize()} '{name}'."

    def remove_node_app(self, name: str, domain: str) -> None:
        try:
            unit = self._node_unit_path(name)
        except ValueError:
            return
        # Best-effort: a not-yet-started / already-removed unit must not raise.
        for cmd in (["systemctl", "stop", unit.name],
                    ["systemctl", "disable", unit.name]):
            try:
                _run(cmd)
            except RuntimeError:
                pass
        unit.unlink(missing_ok=True)
        try:
            _run(["systemctl", "daemon-reload"])
        except RuntimeError:
            pass
        # Drop the reverse-proxy vhost; the router restores the PHP vhost after.
        (NGINX_SITES / f"{domain}.conf").unlink(missing_ok=True)

    def node_app_status(self, name: str) -> str:
        try:
            unit = self._node_unit_path(name)
        except ValueError:
            return "unknown"
        try:
            proc = subprocess.run(["systemctl", "is-active", unit.name],
                                  capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return "unknown"
        state = proc.stdout.strip()
        if state == "active":
            return "running"
        if state in ("inactive", "failed", "deactivating"):
            return "stopped"
        return "unknown"

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

    def reset_db_password(self, name: str, user: str, password: str) -> None:
        _ident(user, "database user")
        pw = _mysql_str(password)
        _run(["mysql", "-e",
              f"ALTER USER '{user}'@'localhost' IDENTIFIED BY '{pw}'; FLUSH PRIVILEGES;"])

    def issue_certificate(self, domain: str) -> CertInfo:
        base = ["certbot", "--nginx", "--non-interactive", "--agree-tos",
                "--redirect", "-m", f"admin@{domain}"]
        try:
            # Prefer covering both the apex and the www host.
            _run(base + ["-d", domain, "-d", f"www.{domain}"])
        except Exception:  # noqa: BLE001 — www may not resolve; retry apex only.
            _run(base + ["-d", domain])
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
        # DNS is only served locally when BIND is installed on this host. Many
        # setups use the registrar's or an external nameserver and have no local
        # BIND — there the panel DB stays the source of truth and we skip writing
        # a zone file rather than failing the operation that triggered the sync.
        bind_dir = Path("/etc/bind")
        if not bind_dir.is_dir():
            return
        zones_dir = bind_dir / "zones"
        zones_dir.mkdir(parents=True, exist_ok=True)
        zone_path = zones_dir / f"db.{domain}"
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
        # Best-effort reload: a missing rndc or a zone not yet declared in
        # named.conf must not break the panel action that triggered this sync.
        try:
            _run(["rndc", "reload", domain])
        except (RuntimeError, FileNotFoundError, OSError):
            pass

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

    # --- FTP accounts -----------------------------------------------------
    # Virtual FTP users via pure-ftpd's pure-pw (no system account per login).
    # The login name is validated so it can never inject extra pure-pw argv, and
    # the password is passed on stdin (twice) rather than on the command line.
    _FTP_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._@-]{0,126}[A-Za-z0-9])?$")

    def _ftp_login(self, username: str) -> str:
        if not self._FTP_LOGIN_RE.match(username):
            raise ValueError(f"Unsafe FTP login: {username!r}")
        return username

    def _pure_pw(self, args: list[str], password: str | None = None) -> None:
        # pure-pw prompts for the password twice on stdin when creating/updating.
        stdin = f"{password}\n{password}\n" if password is not None else None
        result = subprocess.run(["pure-pw", *args], input=stdin,
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"pure-pw {args[0]} failed: {result.stderr.strip()}")
        # Rebuild the hashed database pure-ftpd actually reads.
        subprocess.run(["pure-pw", "mkdb"], capture_output=True, text=True)

    def create_ftp_account(self, username: str, password: str, home_dir: Path,
                           quota_mb: int = 0) -> None:
        login = self._ftp_login(username)
        home = Path(home_dir)
        home.mkdir(parents=True, exist_ok=True)
        # Own the jail as the web user so uploads land with sane ownership.
        _run(["chown", "-R", "www-data:www-data", str(home)])
        args = ["useradd", login, "-u", "www-data", "-d", str(home)]
        if quota_mb and int(quota_mb) > 0:
            args += ["-N", str(int(quota_mb))]  # quota in MB
        self._pure_pw(args, password=password)

    def set_ftp_password(self, username: str, password: str) -> None:
        login = self._ftp_login(username)
        self._pure_pw(["passwd", login], password=password)

    def delete_ftp_account(self, username: str) -> None:
        try:
            login = self._ftp_login(username)
        except ValueError:
            return
        # -m keeps the home directory; only the login is removed.
        subprocess.run(["pure-pw", "userdel", login, "-m"], capture_output=True, text=True)
        subprocess.run(["pure-pw", "mkdb"], capture_output=True, text=True)

    # --- Web Disk (WebDAV) ------------------------------------------------
    # A Web Disk login is an HTTP basic-auth credential the WebDAV server checks.
    # We keep a shared htpasswd store and a per-login nginx `dav` location snippet
    # (write access via PUT/DELETE/MKCOL/COPY/MOVE; read-only omits them). The
    # snippet is included into a WebDAV server block by the host's nginx config.
    _WEBDISK_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._@-]{0,126}[A-Za-z0-9])?$")

    def _webdisk_login(self, username: str) -> str:
        if not self._WEBDISK_LOGIN_RE.match(username):
            raise ValueError(f"Unsafe Web Disk login: {username!r}")
        return username

    def _htpasswd_path(self) -> Path:
        return WEBDAV_DIR / "htpasswd"

    def _apr1(self, password: str) -> str:
        # apr1 (Apache MD5) — supported by nginx's auth_basic module.
        result = subprocess.run(["openssl", "passwd", "-apr1", "-stdin"],
                                input=password, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"openssl passwd failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def _htpasswd_set(self, login: str, password: str) -> None:
        WEBDAV_DIR.mkdir(parents=True, exist_ok=True)
        path = self._htpasswd_path()
        lines = []
        if path.exists():
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines()
                     if ln and not ln.startswith(f"{login}:")]
        lines.append(f"{login}:{self._apr1(password)}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o640)

    def _htpasswd_remove(self, login: str) -> None:
        path = self._htpasswd_path()
        if not path.exists():
            return
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines()
                 if ln and not ln.startswith(f"{login}:")]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def create_webdisk_account(self, username: str, password: str, home_dir: Path,
                               read_only: bool = False) -> None:
        login = self._webdisk_login(username)
        home = Path(home_dir)
        home.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", "www-data:www-data", str(home)])
        self._htpasswd_set(login, password)
        WEBDAV_DIR.mkdir(parents=True, exist_ok=True)
        dav_methods = "" if read_only else "        dav_methods PUT DELETE MKCOL COPY MOVE;\n"
        # A safe location key derived from the login (no slashes / specials).
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", login)
        (WEBDAV_DIR / f"{slug}.conf").write_text(
            f"# Managed by {config.APP_NAME} — WebDAV for {login}\n"
            f"location /webdav/{slug}/ {{\n"
            f"        alias {home.as_posix()}/;\n"
            f"        auth_basic \"Web Disk\";\n"
            f"        auth_basic_user_file {self._htpasswd_path().as_posix()};\n"
            f"{dav_methods}"
            f"        create_full_put_path on;\n"
            f"        dav_access user:rw group:rw all:r;\n"
            f"        autoindex on;\n"
            f"}}\n",
            encoding="utf-8",
        )

    def set_webdisk_password(self, username: str, password: str) -> None:
        login = self._webdisk_login(username)
        self._htpasswd_set(login, password)

    def delete_webdisk_account(self, username: str) -> None:
        try:
            login = self._webdisk_login(username)
        except ValueError:
            return
        self._htpasswd_remove(login)
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", login)
        (WEBDAV_DIR / f"{slug}.conf").unlink(missing_ok=True)

    # --- Git version control ----------------------------------------------
    def create_git_repo(self, path: Path, owner: str | None,
                        clone_url: str | None = None) -> None:
        repo = Path(path)
        repo.mkdir(parents=True, exist_ok=True)
        if owner:
            _ident(owner, "account username")
            _run(["chown", owner, str(repo)])
        # Run git as the account user so the tree stays owned by them.
        prefix = ["runuser", "-u", owner, "--"] if owner else []
        if clone_url:
            cmd = prefix + ["git", "clone", "--", clone_url, str(repo)]
        else:
            cmd = prefix + ["git", "init", "-b", "main", str(repo)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"git failed: {(result.stdout + result.stderr).strip()}")

    def git_pull(self, path: Path) -> str:
        repo = Path(path)
        owner = None
        try:
            owner = repo.owner()  # POSIX: stat owner name
        except (KeyError, OSError, AttributeError):
            owner = None
        prefix = ["runuser", "-u", owner, "--"] if owner else []
        cmd = prefix + ["git", "-C", str(repo), "pull", "--ff-only"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip() or "pull complete"

    def delete_git_repo(self, path: Path) -> None:
        import shutil
        repo = Path(path).resolve()
        # Guard: only ever remove trees under a real account home.
        if repo == Path("/") or "home" not in repo.parts:
            raise ValueError(f"Refusing to delete unexpected path: {repo}")
        shutil.rmtree(repo, ignore_errors=True)


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

    # --- Firewall / security (admin-only) ---------------------------------
    def _ufw(self, args: list[str]) -> str:
        """Run `ufw <args>` non-interactively. Raises like _run on failure."""
        return _run(["ufw"] + args)

    def firewall_status(self) -> dict:
        try:
            out = subprocess.run(["ufw", "status", "verbose"],
                                 capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return {"backend": "none", "available": False, "active": False,
                    "default_incoming": "", "default_outgoing": ""}
        text = out.stdout or ""
        active = "Status: active" in text
        incoming = outgoing = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Default:"):
                # e.g. "Default: deny (incoming), allow (outgoing), disabled (routed)"
                for part in line[len("Default:"):].split(","):
                    part = part.strip()
                    if "(incoming)" in part:
                        incoming = part.split()[0]
                    elif "(outgoing)" in part:
                        outgoing = part.split()[0]
        return {"backend": "ufw", "available": True, "active": active,
                "default_incoming": incoming, "default_outgoing": outgoing}

    def list_firewall_rules(self) -> list[dict]:
        try:
            out = subprocess.run(["ufw", "status", "numbered"],
                                 capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return []
        rules: list[dict] = []
        # Lines look like: "[ 1] 22/tcp                     ALLOW IN    Anywhere"
        for line in (out.stdout or "").splitlines():
            m = re.match(r"\[\s*(\d+)\]\s+(.*)", line)
            if not m:
                continue
            num = int(m.group(1))
            rest = m.group(2)
            # Split on the ALLOW/DENY/REJECT/LIMIT + direction token.
            am = re.search(r"\b(ALLOW|DENY|REJECT|LIMIT)\b(?:\s+(IN|OUT|FWD))?", rest)
            if not am:
                continue
            to = rest[:am.start()].strip()
            action = am.group(1).lower()
            source = rest[am.end():].strip() or "Anywhere"
            rules.append({"num": num, "to": to, "action": action, "source": source})
        return rules

    def set_firewall_enabled(self, enabled: bool) -> tuple[bool, str]:
        try:
            if enabled:
                proc = subprocess.run(["ufw", "--force", "enable"],
                                      capture_output=True, text=True)
            else:
                proc = subprocess.run(["ufw", "disable"],
                                      capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "ufw is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"firewall {'enabled' if enabled else 'disabled'}"

    def add_firewall_rule(self, port: int, proto: str, action: str,
                          source: str | None = None) -> tuple[bool, str]:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return False, "port must be an integer"
        if not (1 <= port <= 65535):
            return False, "port must be between 1 and 65535"
        proto = (proto or "").lower()
        if proto not in ("tcp", "udp"):
            return False, "proto must be tcp or udp"
        action = (action or "").lower()
        if action not in ("allow", "deny"):
            return False, "action must be allow or deny"
        if source:
            source = source.strip()
            if not _IP_RE.match(source):
                return False, "source must be a valid IP or CIDR"
        # ufw allow from <src> to any port <port> proto <proto>
        #   -- or, when no source, the simpler `ufw allow <port>/<proto>`.
        if source:
            cmd = ["ufw", action, "from", source, "to", "any",
                   "port", str(port), "proto", proto]
        else:
            cmd = ["ufw", action, f"{port}/{proto}"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "ufw is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"rule added: {action} {port}/{proto}" + (
            f" from {source}" if source else "")

    def delete_firewall_rule(self, num: int) -> tuple[bool, str]:
        try:
            num = int(num)
        except (TypeError, ValueError):
            return False, "rule number must be an integer"
        if num < 1:
            return False, "rule number must be positive"
        try:
            proc = subprocess.run(["ufw", "--force", "delete", str(num)],
                                  capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "ufw is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"rule {num} deleted"

    def fail2ban_status(self) -> dict:
        try:
            out = subprocess.run(["fail2ban-client", "status"],
                                 capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return {"available": False, "active": False, "jails": []}
        if out.returncode != 0:
            # Binary present but the daemon isn't running.
            return {"available": True, "active": False, "jails": []}
        jails: list[str] = []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("Jail list:"):
                names = line[len("Jail list:"):].strip()
                jails = [j.strip() for j in names.split(",") if j.strip()]
        return {"available": True, "active": True, "jails": jails}

    def list_banned_ips(self, jail: str) -> list[str]:
        try:
            jail = _ident(jail, "jail")
        except ValueError:
            return []
        try:
            out = subprocess.run(["fail2ban-client", "status", jail],
                                 capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return []
        if out.returncode != 0:
            return []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if "Banned IP list:" in line:
                ips = line.split("Banned IP list:", 1)[1].strip()
                return [ip for ip in ips.split() if ip]
        return []

    def ban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        ip = (ip or "").strip()
        if not _IP_RE.match(ip):
            return False, "invalid IP address"
        try:
            jail = _ident(jail, "jail")
        except ValueError as exc:
            return False, str(exc)
        try:
            proc = subprocess.run(["fail2ban-client", "set", jail, "banip", ip],
                                  capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "fail2ban is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"banned {ip} in {jail}"

    def unban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        ip = (ip or "").strip()
        if not _IP_RE.match(ip):
            return False, "invalid IP address"
        try:
            jail = _ident(jail, "jail")
        except ValueError as exc:
            return False, str(exc)
        try:
            proc = subprocess.run(["fail2ban-client", "set", jail, "unbanip", ip],
                                  capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "fail2ban is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"unbanned {ip} from {jail}"

    # --- Logs -------------------------------------------------------------
    # Fixed allowlist of readable logs. The viewer passes back a `key` from this
    # map — never a path — so it can only ever read these specific files.
    _LOG_FILES: dict[str, tuple[str, str, str]] = {
        # key: (label, category, path)
        "nginx-access": ("Nginx — Access", "Web", "/var/log/nginx/access.log"),
        "nginx-error": ("Nginx — Error", "Web", "/var/log/nginx/error.log"),
        "auth": ("System — Auth (SSH/sudo)", "System", "/var/log/auth.log"),
        "syslog": ("System — Syslog", "System", "/var/log/syslog"),
        "fail2ban": ("Security — fail2ban", "Security", "/var/log/fail2ban.log"),
        "mysql-error": ("MySQL — Error", "Database", "/var/log/mysql/error.log"),
        "ufw": ("Security — ufw", "Security", "/var/log/ufw.log"),
    }
    # The panel's own log comes from journald (systemd unit), not a file.
    _PANEL_UNIT = "litespanel"

    def log_sources(self) -> list[dict]:
        sources: list[dict] = []
        for key, (label, category, path) in self._LOG_FILES.items():
            if Path(path).exists():
                sources.append({"key": key, "label": label, "category": category})
        # Panel service log via journalctl (available if the unit exists).
        try:
            proc = subprocess.run(
                ["systemctl", "status", self._PANEL_UNIT],
                capture_output=True, text=True,
            )
            if proc.returncode in (0, 3):  # 0=running, 3=stopped but known
                sources.append({"key": "panel", "label": "LitesPanel — App",
                                "category": "Panel"})
        except (FileNotFoundError, OSError):
            pass
        return sources

    def read_log(self, key: str, lines: int = 200, grep: str | None = None) -> tuple[bool, str]:
        if key == "panel":
            cmd = ["journalctl", "-u", self._PANEL_UNIT, "-n", str(max(1, min(lines, 5000))),
                   "--no-pager", "--output", "short-iso"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            except (FileNotFoundError, OSError):
                return False, "journalctl is not available on this host"
            except subprocess.TimeoutExpired:
                return False, "reading the journal timed out"
            text = proc.stdout
            if grep:
                needle = grep.lower()
                text = "\n".join(ln for ln in text.splitlines() if needle in ln.lower())
            return True, text

        entry = self._LOG_FILES.get(key)
        if entry is None:
            return False, "unknown log source"
        from .base import tail_file

        text = tail_file(Path(entry[2]), lines=lines, grep=grep)
        return True, text

    # --- Per-domain web logs (Metrics) ------------------------------------
    def read_access_log(self, domain: str, max_lines: int = 20000) -> list[str]:
        _ident_ok = True  # domain is not a shell arg; validated by the caller's ownership check
        text = tail_file(WEBLOG_DIR / f"{domain}.access.log", lines=max_lines)
        return text.splitlines() if text else []

    def read_error_log(self, domain: str, max_lines: int = 200) -> list[str]:
        text = tail_file(WEBLOG_DIR / f"{domain}.error.log", lines=max_lines)
        return text.splitlines() if text else []
