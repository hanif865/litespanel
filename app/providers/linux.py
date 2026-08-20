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

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .. import config
from .base import (
    CertInfo, DbCredentials, Provider, SiteVhost, dkim_generate, node_env_lines,
    node_exec_start, tail_file, txt_record_chunks, upload_cap_mb,
    web_fronting_enabled,
)
from .. import db_privileges

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
# Per-account upload cap. client_max_body_size lives in a tiny include, one file
# per account, so the PHP Selector can change an account's upload limit and have
# nginx follow in lock-step: rewrite this one file + reload, and every vhost that
# includes it picks up the new cap — no vhost regeneration, no touching certbot's
# own :443 edits. Kept out of sites-enabled so it's never loaded as a server block.
NGINX_LIMITS = Path("/etc/nginx/litespanel-limits")

# Varnish sandwich artifacts (web-fronting mode). The panel VCL points Varnish
# at the internal nginx backend; the systemd drop-in binds varnishd to
# loopback:VARNISH_PORT (never public) and loads that VCL. Kept off the default
# unit so an apt upgrade of varnish leaves the panel's config intact.
VARNISH_VCL = Path("/etc/varnish/litespanel.vcl")
VARNISH_OVERRIDE = Path("/etc/systemd/system/varnish.service.d/litespanel.conf")

# certbot runs every executable in this dir after a successful renewal. A single
# global deploy hook (written at first issue) reloads nginx/varnish so a silently
# auto-renewed cert is served immediately, no manual reload — the piece that makes
# renewal truly hands-off, cPanel AutoSSL-style.
_RENEW_HOOK_DIR = Path("/etc/letsencrypt/renewal-hooks/deploy")

# Redis daemon tuning artifacts. The systemd drop-in resets ExecStart and
# relaunches redis-server with our memory/eviction flags appended after the
# stock config file (CLI options win over redis.conf, so we never edit the
# distro file). The drop-in PATH is derived per-host from the resolved unit
# (redis-server vs redis differ by distro), so it isn't a fixed constant here.
REDIS_BIN = "/usr/bin/redis-server"
# Plain string, not Path(): this is a fixed POSIX path baked into a systemd
# ExecStart, so it must render with forward slashes even when the module is
# imported on the Windows dev box (a WindowsPath would emit backslashes).
REDIS_CONF = "/etc/redis/redis.conf"

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

# Service Manager: map each catalog key (config.MANAGED_SERVICES) to candidate
# systemd units, most-preferred first. Names differ across distros (MySQL ships
# as either mariadb or mysql), so list every plausible unit and resolve to the
# first one that's actually loaded. The client only ever sends a key from this
# map — never a unit name — so it can't ask systemctl to touch anything else.
_SERVICE_UNITS: dict[str, list[str]] = {
    "nginx": ["nginx"],
    "varnish": ["varnish"],
    "php-fpm": [f"php{config.PHP_FPM_VERSION}-fpm"],
    "redis": ["redis-server", "redis"],
    "mysql": ["mariadb", "mysql"],
    "postgresql": ["postgresql"],
    "named": ["named", "bind9"],
    "ftp": ["pure-ftpd"],
    "sshd": ["sshd", "ssh"],
    "cron": ["crond", "cron"],
    "postfix": ["postfix"],
    "dovecot": ["dovecot"],
    "opendkim": ["opendkim"],
}

# OpenDKIM's config dir (setup-mail.sh lays it down). Overridable so the
# key-registration logic can be exercised against a temp dir in tests.
_OPENDKIM_DIR = Path("/etc/opendkim")


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
            # Each account gets its own primary group so its files stay private.
            # useradd's default same-name group creation fails when a group of
            # that name already exists (e.g. Ubuntu's reserved `admin` group, or
            # an orphan left by an earlier half-finished run). Rather than reuse a
            # group we don't own — which could hand the account another group's
            # members or privileges — create a panel-namespaced group instead.
            group = username
            if self._group_exists(group):
                group = f"{username}_lp"
            if not self._group_exists(group):
                _run(["groupadd", group])
            _run(["useradd", "--create-home", "--home-dir", str(home),
                  "--shell", "/usr/sbin/nologin", "--no-user-group",
                  "--gid", group, username])
        # A dedicated PHP-FPM pool makes this account's PHP run AS this user,
        # so its sites can't read another account's files.
        self._write_php_pool(username)
        # Seed the per-account nginx upload cap so the include target exists
        # before this account's first vhost references it.
        self._ensure_limits(username)
        # Let nginx (www-data) traverse into the account to reach public_html.
        _run(["chmod", "751", str(home)])
        return home

    def _group_exists(self, name: str) -> bool:
        return subprocess.run(["getent", "group", name],
                              capture_output=True).returncode == 0

    def _primary_group(self, username: str) -> str:
        """The account's real primary group. Usually equals the username, but a
        panel-namespaced fallback when that name collided with an existing group."""
        r = subprocess.run(["id", "-gn", username], capture_output=True, text=True)
        name = r.stdout.strip()
        return name if r.returncode == 0 and name else username

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
        group = self._primary_group(username)
        lines = [
            f"[{username}]",
            f"user = {username}",
            f"group = {group}",
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
        #
        # Ship generous upload/runtime defaults so plugin/theme zips and media
        # uploads work out of the box (cPanel-style); nginx allows the body via
        # client_max_body_size, and these let PHP actually accept it. A per-account
        # PHP config (from the PHP page) overrides any of these.
        effective = {
            "upload_max_filesize": f"{config.MAX_UPLOAD_MB}M",
            "post_max_size": f"{config.MAX_UPLOAD_MB}M",
            "memory_limit": "256M",
            "max_execution_time": "300",
            **(directives or {}),
        }
        for key in sorted(effective):
            value = str(effective[key]).replace("\n", " ").strip()
            # An empty value must never be written: `php_admin_value[foo] =` with
            # nothing after it overrides PHP's built-in default with "" and can
            # break the setting (e.g. an empty session.save_path breaks sessions).
            # Skipping it lets a catalog directive default to "" = "leave PHP's
            # default" while a real value still materializes.
            if not value:
                continue
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

    # --- Per-account upload cap (nginx client_max_body_size) --------------
    def _limits_conf(self, username: str) -> Path:
        _ident(username, "account username")
        return NGINX_LIMITS / f"{username}.conf"

    def _write_limits(self, username: str, mb: int) -> None:
        NGINX_LIMITS.mkdir(parents=True, exist_ok=True)
        self._limits_conf(username).write_text(f"client_max_body_size {mb}m;\n")

    def _ensure_limits(self, username: str) -> None:
        """Guarantee the include target exists before any vhost references it, so
        `nginx -t` can never fail on a missing include. Writes the panel default
        only when absent — never clobbers a cap the PHP Selector already set."""
        if not self._limits_conf(username).exists():
            self._write_limits(username, config.MAX_UPLOAD_MB)

    def set_upload_limit(self, username: str, mb: int) -> None:
        """Point nginx's body cap for this account at `mb` MB and reload, so a
        change made on the PHP Selector page takes effect across the account's
        vhosts immediately (they all include this one file)."""
        self._write_limits(username, mb)
        # Sites created before the include existed still carry a hardcoded cap
        # and would ignore the file we just wrote (silent 413). Migrate them to
        # the include first, so this and every future cap change reaches them.
        self._adopt_limits_include(username)
        self.reload_web()

    def _adopt_limits_include(self, username: str) -> None:
        """One-time migration: make every existing vhost of this account use the
        per-account limits include, so a cap change on the PHP page reaches sites
        created before the include mechanism existed.

        Idempotent (skips vhosts already on the include) and surgical: it strips
        any hardcoded `client_max_body_size` and adds the include to each server
        block — never touching certbot's listen/ssl_certificate lines. If the
        rewrite makes `nginx -t` unhappy for any reason, every file touched here
        is restored, so a save can never leave the web server unable to reload.
        """
        _ident(username, "account username")
        if not NGINX_SITES.is_dir():
            return
        include_path = str(self._limits_conf(username))
        marker = f"unix:{self._php_sock(username)}"   # this account's FPM socket
        # Strip the hardcoded directive together with its leading indent/space so
        # neither a blank-but-harmless line (multi-line vhost) nor a token merge
        # like `index.html;access_log` (inline SSL vhost) can result.
        cmb_re = re.compile(r"[ \t]*client_max_body_size[^;\n]*;")
        sn_re = re.compile(r"(server_name[^;\n]*;)")
        changed: dict[Path, str] = {}                 # path -> original, for rollback
        for conf in NGINX_SITES.glob("*.conf"):
            try:
                text = conf.read_text()
            except OSError:
                continue
            # Only this account's PHP vhosts, and only those not already migrated.
            if marker not in text or include_path in text:
                continue
            stripped = cmb_re.sub("", text)
            # Add the include to every server block (each has exactly one
            # server_name), so certbot's :443 block gets the cap too. A lambda
            # replacement avoids backslash/group escaping in the path.
            new = sn_re.sub(
                lambda m: f"{m.group(1)}\n    include {include_path};", stripped
            )
            if new == text:
                continue
            try:
                conf.write_text(new)
                changed[conf] = text
            except OSError:
                pass
        if not changed:
            return
        try:
            subprocess.run(["nginx", "-t"], capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            # Roll back every file we rewrote; leave the server as it was.
            for conf, original in changed.items():
                try:
                    conf.write_text(original)
                except OSError:
                    pass

    # --- Varnish sandwich building blocks (mode-aware vhosts) -------------
    # When web-fronting is ON, every hosted site is generated as a public nginx
    # terminator that proxies to Varnish (127.0.0.1:VARNISH_PORT), which fronts
    # an internal nginx backend (127.0.0.1:NGINX_BACKEND_PORT) that runs PHP-FPM.
    # When OFF, _vhost / set_https_redirect emit exactly today's direct blocks,
    # so the mode flag being unset is fully regression-safe.
    def _php_location(self, username: str) -> str:
        return (f"location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(username)};"
                f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}")

    def _varnish_location(self) -> str:
        return (
            "    location / {\n"
            f"        proxy_pass http://127.0.0.1:{config.VARNISH_PORT};\n"
            "        proxy_set_header Host $host;\n"
            "        proxy_set_header X-Real-IP $remote_addr;\n"
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            "        proxy_set_header X-Forwarded-Proto $scheme;\n"
            "    }\n"
        )

    def _acme_location(self) -> str:
        # Served straight off the :80 terminator (never through Varnish) so
        # certbot certonly --webroot renewals keep working while fronting is on.
        return f"    location /.well-known/acme-challenge/ {{ root {config.ACME_WEBROOT}; }}\n"

    def _lpanel_location(self) -> str:
        return f"    location /lpanel {{ return 301 {config.PANEL_URL}/login; }}\n"

    def _terminator_http(self, primary: str, names: str, username: str, *, redirect_https: bool) -> str:
        if redirect_https:
            # :80 exists only to answer ACME and bounce everything else to https.
            return (
                f"server {{\n    listen 80;\n    server_name {names};\n"
                f"{self._acme_location()}"
                f"    location / {{ return 301 https://$host$request_uri; }}\n}}\n"
            )
        # Plain-HTTP site: :80 is the real traffic path into Varnish.
        return (
            f"server {{\n    listen 80;\n    server_name {names};\n"
            f"    include {self._limits_conf(username)};\n"
            f"    access_log /var/log/litespanel/{primary}.access.log;\n"
            f"    error_log /var/log/litespanel/{primary}.error.log;\n"
            f"{self._acme_location()}"
            f"{self._lpanel_location()}"
            f"{self._varnish_location()}}}\n"
        )

    def _terminator_https(self, primary: str, names: str, username: str, cert: str) -> str:
        return (
            f"server {{\n    listen 443 ssl;\n    server_name {names};\n"
            f"    ssl_certificate {cert}/fullchain.pem;\n"
            f"    ssl_certificate_key {cert}/privkey.pem;\n"
            f"    include {self._limits_conf(username)};\n"
            f"    access_log /var/log/litespanel/{primary}.access.log;\n"
            f"    error_log /var/log/litespanel/{primary}.error.log;\n"
            f"{self._lpanel_location()}"
            f"{self._varnish_location()}}}\n"
        )

    def _backend_block(self, primary: str, names: str, docroot: Path, username: str) -> str:
        # Internal nginx Varnish forwards to: server_name-routed, talks to PHP-FPM.
        # Not publicly reachable (loopback:NGINX_BACKEND_PORT). Carries the body
        # cap too, so a large upload accepted at the edge isn't 413'd here.
        return (
            f"server {{\n    listen 127.0.0.1:{config.NGINX_BACKEND_PORT};\n"
            f"    server_name {names};\n"
            f"    root {docroot};\n    index index.php index.html;\n"
            f"    include {self._limits_conf(username)};\n"
            f"    error_log /var/log/litespanel/{primary}.error.log;\n"
            f"    {self._php_location(username)}\n}}\n"
        )

    def _sandwich_vhost(self, primary: str, names: str, docroot: Path, username: str,
                        has_ssl: bool, force_https: bool) -> str:
        """Full sandwich config for one site: public terminator(s) + backend."""
        if has_ssl:
            cert = f"/etc/letsencrypt/live/{primary}"
            http = self._terminator_http(primary, names, username, redirect_https=force_https)
            return (http
                    + self._terminator_https(primary, names, username, cert)
                    + self._backend_block(primary, names, docroot, username))
        return (self._terminator_http(primary, names, username, redirect_https=False)
                + self._backend_block(primary, names, docroot, username))

    def _vhost(self, server_name: str, extra_names: str, docroot: Path, username: str) -> str:
        names = f"{server_name}{extra_names}"
        if web_fronting_enabled():
            return self._sandwich_vhost(server_name, names, docroot, username,
                                        has_ssl=False, force_https=False)
        return (
            f"server {{\n    listen 80;\n    server_name {names};\n"
            f"    root {docroot};\n    index index.php index.html;\n"
            f"    include {self._limits_conf(username)};\n"
            f"    access_log /var/log/litespanel/{server_name}.access.log;\n"
            f"    error_log /var/log/litespanel/{server_name}.error.log;\n"
            f"    location /lpanel {{ return 301 {config.PANEL_URL}/login; }}\n"
            f"    location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(username)};"
            f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}\n}}\n"
        )

    # --- Web hosting ------------------------------------------------------
    def create_site(self, domain: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        self._ensure_weblog_dir()
        self._ensure_limits(system_user)
        docroot.mkdir(parents=True, exist_ok=True)
        # Hand ownership of the whole site tree to the account (its real primary
        # group, which may be a panel-namespaced fallback on a name collision).
        group = self._primary_group(system_user)
        _run(["chown", "-R", f"{system_user}:{group}", str(Path(docroot).parent)])
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
        self._ensure_limits(system_user)
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
        # Keep nginx's body cap in lock-step with the account's PHP upload limits
        # so neither layer becomes the silent 413. Rewrites the one per-account
        # include and reloads nginx; every vhost that includes it now honours the
        # new cap without being regenerated.
        self.set_upload_limit(system_user, upload_cap_mb(directives))

    # --- PHP extension packages -------------------------------------------
    _EXT_NAME_RE = re.compile(r"^[a-z0-9_]{1,40}$")

    def list_installed_extensions(self, php_version: str) -> set[str]:
        # `php -m` lists the modules loaded for the CLI SAPI; close enough to
        # what FPM loads for the UI's "installed?" indicator. Names are
        # lowercased to match the catalog.
        try:
            proc = subprocess.run(
                [f"php{php_version}", "-m"], capture_output=True, text=True
            )
        except (FileNotFoundError, OSError):
            # The phpX.Y CLI isn't installed on this host (FPM can still be
            # present). We can't enumerate loaded modules, so report none —
            # the same signal as a non-zero exit. Callers treat this as
            # best-effort, so saving PHP config never 500s over a missing CLI.
            return set()
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
        self._ensure_limits(system_user)
        docroot = Path(docroot)
        names = f"{domain} www.{domain}"
        if web_fronting_enabled():
            # Sandwich mode: same TLS/redirect semantics, but every request path
            # runs edge nginx -> Varnish -> backend nginx -> PHP-FPM.
            text = self._sandwich_vhost(domain, names, docroot, system_user,
                                        has_ssl=has_ssl, force_https=enabled)
            (NGINX_SITES / f"{domain}.conf").write_text(text)
            self.reload_web()
            return
        logs = (f" access_log /var/log/litespanel/{domain}.access.log;"
                f" error_log /var/log/litespanel/{domain}.error.log;")
        body = f" include {self._limits_conf(system_user)};"
        php = (f"location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(system_user)};"
               f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}")
        lpanel = f"location /lpanel {{ return 301 {config.PANEL_URL}/login; }}"
        blocks = []
        if has_ssl:
            cert = f"/etc/letsencrypt/live/{domain}"
            if enabled:
                blocks.append(f"server {{ listen 80; server_name {names};"
                              f"{logs} return 301 https://$host$request_uri; }}")
            else:
                blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                              f" index index.php index.html;{body}{logs} {lpanel} {php} }}")
            blocks.append(f"server {{ listen 443 ssl; server_name {names};"
                          f" ssl_certificate {cert}/fullchain.pem; ssl_certificate_key {cert}/privkey.pem;"
                          f" root {docroot}; index index.php index.html;{body}{logs} {lpanel} {php} }}")
        else:
            blocks.append(f"server {{ listen 80; server_name {names}; root {docroot};"
                          f" index index.php index.html;{body}{logs} {lpanel} {php} }}")
        (NGINX_SITES / f"{domain}.conf").write_text("\n".join(blocks) + "\n")
        self.reload_web()

    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str, system_user: str) -> Path:
        _ident(system_user, "account username")
        self._ensure_weblog_dir()
        self._ensure_limits(system_user)
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
            f"    client_max_body_size {config.MAX_UPLOAD_MB}M;\n"
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

    def _node_work_dir(self, app_dir: Path, app_root: str) -> Path:
        """Working dir = app_dir/app_root, kept safely inside app_dir.

        A crafted app_root ("../etc", "/abs") is rejected back to app_dir so the
        unit's WorkingDirectory can never escape the account's app directory.
        """
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
        work_dir = self._node_work_dir(app_dir, app_root)
        work_dir.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", f"{system_user}:{system_user}", str(app_dir)])

        env_block = "".join(line + "\n" for line in node_env_lines(env_vars))
        exec_start = node_exec_start(node_bin, entrypoint, start_command)

        unit.write_text(
            "[Unit]\n"
            f"Description=LitesPanel Node app {name} ({domain})\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={system_user}\n"
            f"WorkingDirectory={work_dir}\n"
            "Environment=NODE_ENV=production\n"
            f"Environment=PORT={int(port)}\n"
            f"{env_block}"
            f"ExecStart={exec_start}\n"
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

    def npm_install(self, app, system_user: str) -> tuple[bool, str]:
        _ident(system_user, "account username")
        work_dir = self._node_work_dir(Path(app.app_dir), app.app_root or "")
        if not work_dir.exists():
            return False, f"App directory does not exist: {work_dir}"
        # Dev deps included so `npm run build` steps work. Put the Node bin dir on
        # PATH in case the runtime lives outside the default login PATH for sudo.
        import os

        env = {**os.environ, "PATH": f"/usr/bin:/usr/local/bin:{os.environ.get('PATH', '')}"}
        try:
            proc = subprocess.run(
                ["sudo", "-u", system_user, "npm", "install", "--no-fund", "--no-audit"],
                capture_output=True, text=True, cwd=str(work_dir), env=env, timeout=300,
            )
        except (FileNotFoundError, OSError) as exc:
            return False, f"npm unavailable: {exc}"
        except subprocess.TimeoutExpired:
            return False, "npm install timed out after 300s."
        out = (proc.stdout + "\n" + proc.stderr).strip()[-500:]
        if proc.returncode != 0:
            return False, out or "npm install failed."
        return True, out or "Dependencies installed."

    def node_app_logs(self, name: str, lines: int = 200) -> str:
        try:
            self._node_unit_path(name)  # validates the slug
        except ValueError as exc:
            return str(exc)
        lines = max(1, min(int(lines), 2000))
        try:
            proc = subprocess.run(
                ["journalctl", "-u", f"litespanel-node-{name}", "-n", str(lines),
                 "--no-pager"],
                capture_output=True, text=True,
            )
        except (FileNotFoundError, OSError):
            return "logs unavailable (journalctl not found)"
        return (proc.stdout or proc.stderr).strip() or "(no log output yet)"

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

    # --- Standalone MySQL users + grants ----------------------------------
    # Additive to the bundled per-database user. Users are hard-scoped to
    # '@localhost'; privileges are normalized against the allowlist here (defense
    # in depth) so only vetted tokens are ever interpolated into a GRANT.
    def create_db_user(self, username: str, password: str) -> None:
        _ident(username, "database user")
        pw = _mysql_str(password)
        _run(["mysql", "-e",
              f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{pw}'; FLUSH PRIVILEGES;"])

    def set_db_user_password(self, username: str, password: str) -> None:
        _ident(username, "database user")
        pw = _mysql_str(password)
        _run(["mysql", "-e",
              f"ALTER USER '{username}'@'localhost' IDENTIFIED BY '{pw}'; FLUSH PRIVILEGES;"])

    def drop_db_user(self, username: str) -> None:
        _ident(username, "database user")
        # Dropping the user also drops every privilege it held, so grants on any
        # database vanish with it.
        _run(["mysql", "-e", f"DROP USER IF EXISTS '{username}'@'localhost'; FLUSH PRIVILEGES;"])

    def _mysql_revoke_all(self, database: str, username: str) -> None:
        """Revoke a user's privileges on one database, tolerating 'no such grant'.

        A first-time grant has nothing to revoke — MySQL error 1141 is expected
        there and swallowed; any other failure is raised."""
        proc = subprocess.run(
            ["mysql", "-e",
             f"REVOKE ALL PRIVILEGES, GRANT OPTION ON `{database}`.* "
             f"FROM '{username}'@'localhost';"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            err = (proc.stderr or "").lower()
            if "1141" not in err and "no such grant" not in err:
                raise RuntimeError(f"mysql revoke failed: {proc.stderr.strip()}")

    def grant_privileges(self, database: str, username: str, privileges: list[str]) -> None:
        _ident(database, "database name")
        _ident(username, "database user")
        privs = db_privileges.normalize("mysql", privileges)
        grant_list = "ALL PRIVILEGES" if db_privileges.is_all(privs) else ", ".join(privs)
        # Authoritative: clear the existing grant first so "manage" can never
        # leave a stale privilege behind, then grant exactly the requested set.
        self._mysql_revoke_all(database, username)
        _run(["mysql", "-e",
              f"GRANT {grant_list} ON `{database}`.* TO '{username}'@'localhost'; "
              f"FLUSH PRIVILEGES;"])

    def revoke_privileges(self, database: str, username: str) -> None:
        _ident(database, "database name")
        _ident(username, "database user")
        self._mysql_revoke_all(database, username)
        _run(["mysql", "-e", "FLUSH PRIVILEGES;"])

    # --- PostgreSQL databases ---------------------------------------------
    # Administered as the postgres superuser over the local socket. Identifiers
    # are validated to plain names; the role password is escaped for a
    # single-quoted SQL literal (E'' with backslash escaping) so it can't break
    # out of the statement. Each command is a separate psql -c to keep a failure
    # (e.g. duplicate) from silently leaving half the objects behind.
    def _psql(self, sql: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", sql],
            capture_output=True, text=True,
        )

    @staticmethod
    def _pg_lit(value: str) -> str:
        """Escape a value for a single-quoted PostgreSQL string literal (E'...')."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def create_pg_database(self, name: str, user: str, password: str) -> DbCredentials:
        _ident(name, "database name")
        _ident(user, "database user")
        pw = self._pg_lit(password)
        # Role first, then a database owned by it. Identifiers are quoted with
        # double quotes; the password uses an E'' escaped literal.
        for stmt in (
            f"CREATE ROLE \"{user}\" LOGIN PASSWORD E'{pw}';",
            f"CREATE DATABASE \"{name}\" OWNER \"{user}\";",
            f"GRANT ALL PRIVILEGES ON DATABASE \"{name}\" TO \"{user}\";",
        ):
            proc = self._psql(stmt)
            if proc.returncode != 0:
                raise RuntimeError(
                    "psql failed: " + (proc.stderr or proc.stdout).strip()[-400:]
                )
        return DbCredentials(name=name, user=user, password=password,
                             host="localhost", port=5432)

    def drop_pg_database(self, name: str, user: str) -> None:
        _ident(name, "database name")
        _ident(user, "database user")
        # Drop the database before the role that owns it. WITH (FORCE) needs PG
        # 13+; fall back to a plain DROP if the server rejects the option.
        drop_db = self._psql(f"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE);")
        if drop_db.returncode != 0:
            self._psql(f"DROP DATABASE IF EXISTS \"{name}\";")
        self._psql(f"DROP ROLE IF EXISTS \"{user}\";")

    def pg_available(self) -> bool:
        try:
            proc = subprocess.run(
                ["sudo", "-u", "postgres", "psql", "-tAc", "SELECT 1;"],
                capture_output=True, text=True,
            )
        except (FileNotFoundError, OSError):
            return False
        return proc.returncode == 0

    # --- Standalone PostgreSQL roles + grants -----------------------------
    # PG privileges are database-scoped (CONNECT/CREATE/TEMPORARY, granted ON
    # DATABASE) and table-scoped (the rest, granted across schema public). The
    # schema/table statements must run *inside* the target database, hence
    # _psql_db. Revoke-then-grant makes "manage" authoritative. Privileges are
    # normalized against the allowlist here (defense in depth).
    def _psql_db(self, dbname: str, sql: str) -> subprocess.CompletedProcess:
        """Run one statement as postgres, connected to a specific database."""
        _ident(dbname, "database name")  # keeps a crafted name out of the -d argv
        return subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-d", dbname, "-c", sql],
            capture_output=True, text=True,
        )

    def _psql_ck(self, sql: str) -> None:
        proc = self._psql(sql)
        if proc.returncode != 0:
            raise RuntimeError("psql failed: " + (proc.stderr or proc.stdout).strip()[-400:])

    def _psql_db_ck(self, dbname: str, sql: str) -> None:
        proc = self._psql_db(dbname, sql)
        if proc.returncode != 0:
            raise RuntimeError("psql failed: " + (proc.stderr or proc.stdout).strip()[-400:])

    def create_pg_user(self, username: str, password: str) -> None:
        _ident(username, "database user")
        pw = self._pg_lit(password)
        self._psql_ck(f"CREATE ROLE \"{username}\" LOGIN PASSWORD E'{pw}';")

    def set_pg_user_password(self, username: str, password: str) -> None:
        _ident(username, "database user")
        pw = self._pg_lit(password)
        self._psql_ck(f"ALTER ROLE \"{username}\" WITH PASSWORD E'{pw}';")

    def drop_pg_user(self, username: str) -> None:
        _ident(username, "database user")
        # The caller revokes the role's grants first; a role with no remaining
        # privileges/owned objects then drops cleanly.
        self._psql(f"DROP ROLE IF EXISTS \"{username}\";")

    def _pg_revoke_all(self, database: str, username: str) -> None:
        """Strip a role's DB + public-schema privileges. Tolerant: PG treats a
        revoke of an unheld privilege as a no-op (a NOTICE, not an error)."""
        self._psql(f'REVOKE ALL PRIVILEGES ON DATABASE "{database}" FROM "{username}";')
        self._psql_db(database, f'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{username}";')
        self._psql_db(database, f'REVOKE ALL PRIVILEGES ON SCHEMA public FROM "{username}";')
        self._psql_db(database,
                      f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM "{username}";')

    def grant_pg_privileges(self, database: str, username: str, privileges: list[str]) -> None:
        _ident(database, "database name")
        _ident(username, "database user")
        privs = db_privileges.normalize("pg", privileges)
        self._pg_revoke_all(database, username)  # authoritative reset
        if db_privileges.is_all(privs):
            self._psql_ck(f'GRANT ALL PRIVILEGES ON DATABASE "{database}" TO "{username}";')
            self._psql_db_ck(database, f'GRANT ALL ON SCHEMA public TO "{username}";')
            self._psql_db_ck(database, f'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{username}";')
            self._psql_db_ck(database,
                             f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "{username}";')
            return
        db_scoped = [p for p in privs if p in db_privileges.PG_DATABASE_SCOPED]
        table_scoped = [p for p in privs if p in db_privileges.PG_TABLE_SCOPED]
        if db_scoped:
            self._psql_ck(f'GRANT {", ".join(db_scoped)} ON DATABASE "{database}" TO "{username}";')
        if table_scoped:
            cols = ", ".join(table_scoped)
            # USAGE on the schema is required before the role can touch any object.
            self._psql_db_ck(database, f'GRANT USAGE ON SCHEMA public TO "{username}";')
            self._psql_db_ck(database, f'GRANT {cols} ON ALL TABLES IN SCHEMA public TO "{username}";')
            # Cover tables created later in this schema too.
            self._psql_db_ck(database,
                             f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT {cols} ON TABLES TO "{username}";')

    def revoke_pg_privileges(self, database: str, username: str) -> None:
        _ident(database, "database name")
        _ident(username, "database user")
        self._pg_revoke_all(database, username)

    def issue_certificate(self, domain: str) -> CertInfo:
        if web_fronting_enabled():
            # Sandwich mode: nginx is a hand-built terminator -> Varnish -> backend.
            # certbot --nginx would rewrite that vhost and break the sandwich, so
            # obtain the cert over the shared ACME webroot (the :80 terminator
            # already serves /.well-known/acme-challenge from it) and let the
            # existing :443 terminator pick the new cert up on reload.
            self._ensure_acme_webroot()
            base = ["certbot", "certonly", "--webroot", "-w", config.ACME_WEBROOT,
                    "--non-interactive", "--agree-tos", "-m", f"admin@{domain}"]
        else:
            base = ["certbot", "--nginx", "--non-interactive", "--agree-tos",
                    "--redirect", "-m", f"admin@{domain}"]
        try:
            # Prefer covering both the apex and the www host.
            _run(base + ["-d", domain, "-d", f"www.{domain}"])
        except Exception:  # noqa: BLE001 — www may not resolve; retry apex only.
            _run(base + ["-d", domain])
        self._ensure_renew_hook()  # so future auto-renewals reload the web stack
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

    def _ensure_renew_hook(self) -> None:
        """Drop a global certbot deploy hook that reloads the web stack after any
        renewal. Best-effort: renewal still succeeds without it (the cert would
        just need a manual reload), so a read-only /etc must never fail issuance."""
        try:
            _RENEW_HOOK_DIR.mkdir(parents=True, exist_ok=True)
            hook = _RENEW_HOOK_DIR / "litespanel-reload.sh"
            hook.write_text(
                "#!/bin/sh\n"
                "# Managed by LitesPanel: reload web services after a cert renewal\n"
                "# so the freshly-issued certificate is served without manual action.\n"
                "systemctl reload nginx 2>/dev/null || true\n"
                "systemctl reload varnish 2>/dev/null || true\n"
            )
            hook.chmod(0o755)
        except (OSError, PermissionError):
            pass

    def live_cert_expiry(self, cert_path: str) -> datetime | None:
        """notAfter of the leaf cert on disk (via openssl), or None if unreadable.

        openssl prints e.g. `notAfter=Nov 18 12:00:00 2026 GMT`; single-digit days
        are space-padded, so whitespace is collapsed before parsing. Always GMT."""
        if not cert_path or not Path(cert_path).exists():
            return None
        try:
            out = _run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path])
        except (RuntimeError, FileNotFoundError, OSError):
            return None
        _, _, raw = out.partition("=")
        raw = " ".join(raw.split())              # collapse the space-padded day
        if raw.endswith(" GMT"):
            raw = raw[:-4]
        try:
            return datetime.strptime(raw, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def autorenew_active(self) -> bool:
        """certbot's automatic renewal is on when its systemd timer is
        enabled/active, or (older setups) the packaged cron job is present."""
        for check in (["systemctl", "is-enabled", "certbot.timer"],
                      ["systemctl", "is-active", "certbot.timer"]):
            try:
                if subprocess.run(check, capture_output=True, text=True).returncode == 0:
                    return True
            except (OSError, FileNotFoundError):
                pass
        return Path("/etc/cron.d/certbot").exists()

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
                lines.append(f'{name} IN TXT {txt_record_chunks(r["value"])}')
            else:
                lines.append(f"{name} IN {r['type']} {r['value']}")
        zone_path.write_text("\n".join(lines) + "\n")
        # Best-effort reload: a missing rndc or a zone not yet declared in
        # named.conf must not break the panel action that triggered this sync.
        try:
            _run(["rndc", "reload", domain])
        except (RuntimeError, FileNotFoundError, OSError):
            pass

    def generate_dkim(self, domain: str, selector: str = "default") -> tuple[str, str]:
        # Store keys at the conventional opendkim path so the signer finds
        # them, falling back to DKIM_DIR when /etc/opendkim isn't writable.
        key_dir = _OPENDKIM_DIR / "keys" / domain
        try:
            key_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            key_dir = config.DKIM_DIR / domain
        selector, txt_value = dkim_generate(key_dir, domain, selector)
        # Wire the key into opendkim's signing tables (only when the mail stack
        # is installed — setup-mail.sh lays down these files). This makes the
        # published DKIM TXT record *actually sign* outgoing mail.
        self._register_opendkim(domain, selector, key_dir / f"{domain}.{selector}.private")
        return selector, txt_value

    def _register_opendkim(self, domain: str, selector: str, priv_path: Path) -> None:
        """Register a DKIM key with opendkim's KeyTable and SigningTable.
        Idempotent: if the domain already has an entry, don't duplicate it.
        Guard: if /etc/opendkim doesn't exist, the mail stack isn't installed — no-op.
        """
        if not _OPENDKIM_DIR.is_dir():
            return  # mail stack not installed
        key_table = _OPENDKIM_DIR / "KeyTable"
        signing_table = _OPENDKIM_DIR / "SigningTable"
        # KeyTable line:  <selector>._domainkey.<domain> <domain>:<selector>:<priv_path>
        # SigningTable:    *@<domain> <selector>._domainkey.<domain>
        key_line = f"{selector}._domainkey.{domain} {domain}:{selector}:{priv_path}"
        sign_line = f"*@{domain} {selector}._domainkey.{domain}"
        # Append if not already present (idempotent).
        if key_table.exists():
            existing = key_table.read_text()
            if f"{selector}._domainkey.{domain}" not in existing:
                key_table.write_text(existing.rstrip() + "\n" + key_line + "\n")
        else:
            key_table.write_text(key_line + "\n")
        if signing_table.exists():
            existing = signing_table.read_text()
            if f"*@{domain} " not in existing and not existing.rstrip().endswith(f"*@{domain}"):
                signing_table.write_text(existing.rstrip() + "\n" + sign_line + "\n")
        else:
            signing_table.write_text(sign_line + "\n")
        # opendkim runs as its own user — must own the key dir to read private keys.
        try:
            subprocess.run(["chown", "-R", "opendkim:opendkim", str(priv_path.parent)],
                           capture_output=True, check=False)
        except (OSError, RuntimeError):
            pass
        # Reload opendkim so it picks up the new key.
        try:
            subprocess.run(["systemctl", "reload", "opendkim"], capture_output=True, check=False)
        except (OSError, RuntimeError):
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

    def set_mailbox_password(self, address: str, password: str) -> None:
        # Recompute the Dovecot hash and swap only the password field of the
        # mailbox's line, leaving the quota tail untouched. The users-file line
        # is  address:hash::::::userdb_quota_rule=*:storage=NM  and the
        # SHA512-CRYPT hash never contains ':', so split(':', 2) is safe.
        users = Path("/etc/dovecot/users")
        if not users.exists():
            return
        hashed = _run(["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password]).strip()
        out = []
        for line in users.read_text().splitlines():
            if line.startswith(f"{address}:"):
                _addr, _hash, tail = line.split(":", 2)
                out.append(f"{address}:{hashed}:{tail}")
            elif line:
                out.append(line)
        users.write_text("\n".join(out) + "\n")

    def set_mailbox_quota(self, address: str, quota_mb: int) -> None:
        # Keep the existing password hash, regenerate the standard quota tail.
        users = Path("/etc/dovecot/users")
        if not users.exists():
            return
        out = []
        for line in users.read_text().splitlines():
            if line.startswith(f"{address}:"):
                _addr, hashed, _tail = line.split(":", 2)
                out.append(f"{address}:{hashed}::::::userdb_quota_rule=*:storage={quota_mb}M")
            elif line:
                out.append(line)
        users.write_text("\n".join(out) + "\n")

    def mailbox_usage(self, address: str) -> int:
        # Sum the mailbox's Maildir on disk. `du -sb` reports apparent bytes;
        # a missing mailbox (or no mail stack) just yields 0 so the list still
        # renders. Cheap enough per-account for the small scale this targets.
        local, _, domain = address.partition("@")
        path = f"/var/mail/vhosts/{domain}/{local}"
        try:
            out = subprocess.run(["du", "-sb", path], capture_output=True, text=True)
        except OSError:
            return 0
        if out.returncode != 0:
            return 0
        try:
            return int(out.stdout.split("\t", 1)[0].split()[0])
        except (ValueError, IndexError):
            return 0

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

    # --- IP Blocker -------------------------------------------------------
    # Manual, permanent blocks are blanket `ufw deny from <ip>` rules (no port),
    # inserted at position 1 so they win over any allow rules below. Reported
    # separately from fail2ban's automatic bans (list_banned_ips).
    _BLOCK_COMMENT_RE = re.compile(r"^[\w .:\-/]{0,64}$")

    def list_blocked_ips(self) -> list[dict]:
        try:
            out = subprocess.run(["ufw", "status", "numbered"],
                                 capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return []
        blocked: list[dict] = []
        # A manual block is a blanket source-deny: the "to" is Anywhere and the
        # action is DENY, e.g. "[ 4] Anywhere    DENY IN    203.0.113.7".
        for line in (out.stdout or "").splitlines():
            m = re.match(r"\[\s*(\d+)\]\s+(.*)", line)
            if not m:
                continue
            num = int(m.group(1))
            rest = m.group(2)
            am = re.search(r"\b(ALLOW|DENY|REJECT|LIMIT)\b(?:\s+(IN|OUT|FWD))?", rest)
            if not am or am.group(1) != "DENY":
                continue
            to = rest[:am.start()].strip()
            source = rest[am.end():].strip()
            # Only blanket denies (whole-host, any port) count as IP blocks; a
            # port-scoped deny belongs to the firewall rules list, not here.
            if to not in ("Anywhere", "Anywhere (v6)"):
                continue
            # ufw appends "# comment" to the source column when a rule has one.
            comment = ""
            if "#" in source:
                source, comment = (p.strip() for p in source.split("#", 1))
            if not source:
                continue
            blocked.append({"num": num, "ip": source, "comment": comment})
        return blocked

    def block_ip(self, ip: str, comment: str | None = None) -> tuple[bool, str]:
        ip = (ip or "").strip()
        if not _IP_RE.match(ip):
            return False, "invalid IP or CIDR"
        cmd = ["ufw", "insert", "1", "deny", "from", ip]
        comment = (comment or "").strip()
        if comment and self._BLOCK_COMMENT_RE.match(comment):
            cmd += ["comment", comment]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "ufw is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"blocked {ip}"

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        ip = (ip or "").strip()
        if not _IP_RE.match(ip):
            return False, "invalid IP or CIDR"
        try:
            proc = subprocess.run(["ufw", "delete", "deny", "from", ip],
                                  capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "ufw is not installed on this host"
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        return True, f"unblocked {ip}"

    # --- ModSecurity WAF --------------------------------------------------
    # The panel owns exactly one directive: the SecRuleEngine state, written to
    # a small file the admin Includes from their ModSecurity main config
    # (e.g. `Include /etc/nginx/modsec/litespanel-engine.conf`). Toggling
    # rewrites that one line, tests nginx, then reloads — rolling back the file
    # if the test fails so a bad state can never take the web server down.
    _MODSEC_DIR = Path("/etc/nginx/modsec")
    _MODSEC_ENGINE_FILE = _MODSEC_DIR / "litespanel-engine.conf"

    def _modsec_read_engine(self) -> str | None:
        """Return the current SecRuleEngine value from our managed file, or None."""
        try:
            text = self._MODSEC_ENGINE_FILE.read_text(encoding="utf-8")
        except (OSError, ValueError):
            return None
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("secruleengine"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        return None

    def modsecurity_status(self) -> dict:
        available = self._MODSEC_DIR.exists()
        engine = self._modsec_read_engine()  # "On" / "DetectionOnly" / "Off" / None
        val = (engine or "Off")
        return {
            "available": available,
            "enabled": val.lower() != "off",
            "mode": val if val in ("On", "DetectionOnly") else "On",
            "engine": "ModSecurity (nginx connector)",
            "ruleset": "OWASP CRS",
        }

    def set_modsecurity(self, enabled: bool, mode: str = "On") -> tuple[bool, str]:
        if mode not in ("On", "DetectionOnly"):
            return False, "invalid mode"
        if not self._MODSEC_DIR.exists():
            return False, "ModSecurity is not configured on this host"
        value = mode if enabled else "Off"
        previous = None
        try:
            previous = self._MODSEC_ENGINE_FILE.read_text(encoding="utf-8")
        except (OSError, ValueError):
            previous = None
        body = (
            "# Managed by LitesPanel — Include this from your ModSecurity main\n"
            "# config. Do not edit by hand; the panel rewrites this line.\n"
            f"SecRuleEngine {value}\n"
        )
        try:
            self._MODSEC_ENGINE_FILE.write_text(body, encoding="utf-8")
        except OSError as exc:
            return False, f"could not write engine file: {exc}"

        # Validate; roll the file back to its prior contents if nginx rejects it.
        try:
            test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "nginx is not installed on this host"
        if test.returncode != 0:
            if previous is None:
                self._MODSEC_ENGINE_FILE.unlink(missing_ok=True)
            else:
                self._MODSEC_ENGINE_FILE.write_text(previous, encoding="utf-8")
            return False, "nginx config test failed: " + (test.stderr or test.stdout).strip()[-400:]

        try:
            reload = subprocess.run(["systemctl", "reload", "nginx"],
                                    capture_output=True, text=True)
        except (FileNotFoundError, OSError):
            return False, "could not reload nginx"
        if reload.returncode != 0:
            return False, (reload.stderr or reload.stdout).strip()[-500:]

        if not enabled:
            return True, "ModSecurity turned off"
        return True, f"ModSecurity turned on ({mode})"

    # --- Service Manager --------------------------------------------------
    def _resolve_unit(self, key: str) -> tuple[str | None, str]:
        """Return (unit, load_state) for a catalog key.

        Picks the first candidate unit that is `loaded`; if none is loaded,
        returns (None, "not-found"). Uses `systemctl show` — one cheap,
        machine-readable call per candidate.
        """
        candidates = _SERVICE_UNITS.get(key)
        if not candidates:
            return None, "unknown-key"
        first = candidates[0]
        for unit in candidates:
            try:
                proc = subprocess.run(
                    ["systemctl", "show", f"{unit}.service",
                     "--property=LoadState", "--no-pager"],
                    capture_output=True, text=True,
                )
            except (FileNotFoundError, OSError):
                return None, "no-systemctl"
            state = ""
            for line in (proc.stdout or "").splitlines():
                if line.startswith("LoadState="):
                    state = line.split("=", 1)[1].strip()
            if state == "loaded":
                return unit, "loaded"
        return None, "not-found"

    def list_services(self) -> list[dict]:
        rows: list[dict] = []
        for key, label, group in config.MANAGED_SERVICES:
            unit, load = self._resolve_unit(key)
            if unit is None:
                # Not installed here, or systemctl itself is unavailable.
                rows.append({"key": key, "label": label, "group": group,
                             "status": "unknown", "available": False})
                continue
            try:
                proc = subprocess.run(
                    ["systemctl", "show", f"{unit}.service",
                     "--property=ActiveState", "--no-pager"],
                    capture_output=True, text=True,
                )
            except (FileNotFoundError, OSError):
                rows.append({"key": key, "label": label, "group": group,
                             "status": "unknown", "available": False})
                continue
            active = ""
            for line in (proc.stdout or "").splitlines():
                if line.startswith("ActiveState="):
                    active = line.split("=", 1)[1].strip()
            if active == "active":
                status = "running"
            elif active in ("inactive", "failed", "deactivating", "activating"):
                status = "stopped"
            else:
                status = "unknown"
            rows.append({"key": key, "label": label, "group": group,
                         "status": status, "available": True})
        return rows

    def control_service(self, key: str, action: str) -> tuple[bool, str]:
        if action not in ("start", "stop", "restart"):
            return False, f"Unknown action: {action}"
        label = config.SERVICE_LABELS.get(key)
        if label is None:
            return False, f"Unknown service: {key}"
        unit, _load = self._resolve_unit(key)
        if unit is None:
            return False, f"{label} is not installed on this server."
        # A broken nginx config must never let us take the web server fully
        # down — validate before touching it (start/restart both re-read config).
        if key == "nginx" and action in ("start", "restart"):
            try:
                _run(["nginx", "-t"])
            except RuntimeError as exc:
                return False, f"nginx config test failed: {exc}"
        try:
            _run(["systemctl", action, f"{unit}.service"])
        except RuntimeError as exc:
            return False, str(exc)
        past = {"start": "Started", "stop": "Stopped", "restart": "Restarted"}[action]
        return True, f"{past} {label}."

    def service_status(self, key: str) -> tuple[bool, str]:
        label = config.SERVICE_LABELS.get(key)
        if label is None:
            return False, f"Unknown service: {key}"
        unit, _load = self._resolve_unit(key)
        if unit is None:
            return False, f"{label} is not installed on this server."
        try:
            proc = subprocess.run(
                ["systemctl", "status", f"{unit}.service", "--no-pager", "-n", "30"],
                capture_output=True, text=True,
            )
        except (FileNotFoundError, OSError):
            return False, "systemctl is not available on this host."
        # `systemctl status` exits non-zero for an inactive/failed unit but still
        # prints the full status block — that's exactly what we want to show, so
        # ignore the return code and prefer stdout.
        return True, proc.stdout or proc.stderr or "(no output)"

    def install_service(self, key: str) -> tuple[bool, str]:
        import os

        pkgs = config.SERVICE_PACKAGES.get(key)
        label = config.SERVICE_LABELS.get(key, key)
        if not pkgs:
            return False, f"{label} can't be installed from the panel."
        # Bare subprocess.run with a timeout (not _run, which has none) so a
        # slow apt can never hang the worker. Mirrors install_node / _apt.
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        proc = subprocess.run(
            ["apt-get", "install", "-y", *pkgs],
            capture_output=True, text=True, env=env, timeout=600,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-500:]
        # Bring it up now and on boot. If it installs but won't start, the
        # Status page will show why — don't fail the whole install for that.
        unit, _load = self._resolve_unit(key)
        if unit:
            try:
                _run(["systemctl", "enable", "--now", f"{unit}.service"])
            except RuntimeError:
                pass
        return True, f"Installed {label}."

    # --- Varnish web-fronting (admin-only) --------------------------------
    def _ensure_acme_webroot(self) -> None:
        """The shared webroot every :80 terminator serves ACME challenges from,
        so certbot certonly --webroot renewals work while fronting is on."""
        Path(config.ACME_WEBROOT).mkdir(parents=True, exist_ok=True)

    def _varnish_vcl(self) -> str:
        return (
            "vcl 4.1;\n\n"
            "# Managed by LitesPanel. Single backend: the internal nginx that\n"
            "# serves every hosted site, server_name-routed on loopback.\n"
            "backend default {\n"
            '    .host = "127.0.0.1";\n'
            f'    .port = "{config.NGINX_BACKEND_PORT}";\n'
            "}\n\n"
            "sub vcl_recv {\n"
            "    # Never cache authenticated traffic: a session cookie or auth\n"
            "    # header goes straight to the backend so the panel, wp-admin,\n"
            "    # carts, etc. stay per-user.\n"
            "    if (req.http.Authorization || req.http.Cookie) {\n"
            "        return (pass);\n"
            "    }\n"
            '    if (req.method != "GET" && req.method != "HEAD") {\n'
            "        return (pass);\n"
            "    }\n"
            "}\n\n"
            "sub vcl_backend_response {\n"
            "    # A response that sets a cookie is user-specific: don't cache it.\n"
            "    if (beresp.http.Set-Cookie) {\n"
            "        set beresp.uncacheable = true;\n"
            "    }\n"
            "}\n"
        )

    def _varnish_override(self) -> str:
        # Clear ExecStart first (systemd appends otherwise), then rebind varnishd
        # to loopback only and load the panel VCL. Public ports stay untouched.
        return (
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart=/usr/sbin/varnishd -a 127.0.0.1:{config.VARNISH_PORT} "
            f"-f {VARNISH_VCL} -s malloc,256m\n"
        )

    def _ensure_varnish_config(self) -> tuple[bool, str]:
        """Write the panel VCL + systemd drop-in and (re)start varnishd on
        loopback:VARNISH_PORT. Returns (ok, message)."""
        try:
            VARNISH_VCL.parent.mkdir(parents=True, exist_ok=True)
            VARNISH_VCL.write_text(self._varnish_vcl())
            VARNISH_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
            VARNISH_OVERRIDE.write_text(self._varnish_override())
        except OSError as exc:
            return False, f"could not write Varnish config: {exc}"
        try:
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "restart", "varnish"])
        except RuntimeError as exc:
            return False, f"Varnish failed to restart: {exc}"
        return True, f"Varnish bound to 127.0.0.1:{config.VARNISH_PORT}."

    def _rollback_vhosts(self, changed: dict[Path, str | None]) -> None:
        for conf, original in changed.items():
            try:
                if original is None:
                    conf.unlink(missing_ok=True)
                else:
                    conf.write_text(original)
            except OSError:
                pass

    def _regenerate_all_vhosts(self, sites: Sequence[SiteVhost]) -> tuple[bool, str]:
        """Rewrite every hosted site's vhost in the current mode as one atomic
        batch: write all files, validate once with `nginx -t`, roll them all
        back on failure so a mode switch can never leave nginx unable to reload.
        Node-app domains are left untouched (they never front through Varnish)."""
        if not NGINX_SITES.is_dir():
            return True, "no vhosts to regenerate."
        self._ensure_weblog_dir()
        changed: dict[Path, str | None] = {}   # path -> original text (None = new)
        for site in sites:
            if site.is_node:
                continue
            conf = NGINX_SITES / f"{site.name}.conf"
            try:
                original: str | None = conf.read_text()
            except OSError:
                original = None
            self._ensure_limits(site.system_user)
            names = f"{site.name}{site.extra_names}"
            docroot = Path(site.docroot)
            if web_fronting_enabled():
                content = self._sandwich_vhost(site.name, names, docroot, site.system_user,
                                               has_ssl=site.has_ssl, force_https=site.force_https)
            elif site.has_ssl:
                # Direct mode with a cert: rebuild the :80(+redirect)/:443 pair.
                # This is set_https_redirect's non-sandwich output, inlined so the
                # batch stays a single nginx -t.
                cert = f"/etc/letsencrypt/live/{site.name}"
                logs = (f" access_log /var/log/litespanel/{site.name}.access.log;"
                        f" error_log /var/log/litespanel/{site.name}.error.log;")
                body = f" include {self._limits_conf(site.system_user)};"
                php = (f"location ~ \\.php$ {{ fastcgi_pass unix:{self._php_sock(site.system_user)};"
                       f" include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }}")
                lpanel = f"location /lpanel {{ return 301 {config.PANEL_URL}/login; }}"
                if site.force_https:
                    top = (f"server {{ listen 80; server_name {names};"
                           f"{logs} return 301 https://$host$request_uri; }}")
                else:
                    top = (f"server {{ listen 80; server_name {names}; root {docroot};"
                           f" index index.php index.html;{body}{logs} {lpanel} {php} }}")
                tls = (f"server {{ listen 443 ssl; server_name {names};"
                       f" ssl_certificate {cert}/fullchain.pem; ssl_certificate_key {cert}/privkey.pem;"
                       f" root {docroot}; index index.php index.html;{body}{logs} {lpanel} {php} }}")
                content = top + "\n" + tls + "\n"
            else:
                content = self._vhost(site.name, site.extra_names, docroot, site.system_user)
            try:
                conf.write_text(content)
                changed[conf] = original
            except OSError as exc:
                self._rollback_vhosts(changed)
                return False, f"could not write {conf.name}: {exc}"
        if not changed:
            return True, "no vhosts to regenerate."
        try:
            subprocess.run(["nginx", "-t"], capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            self._rollback_vhosts(changed)
            detail = getattr(exc, "stderr", "") or str(exc)
            return False, f"nginx config test failed, rolled back: {str(detail).strip()[-300:]}"
        _run(["systemctl", "reload", "nginx"])
        return True, f"regenerated {len(changed)} vhost(s)."

    def set_web_fronting(self, enabled: bool, sites: Sequence[SiteVhost]) -> tuple[bool, str]:
        enabled = bool(enabled)
        prev = web_fronting_enabled()
        # Persist the mode first so the vhost builders below read the new mode.
        try:
            config.WEB_FRONTING_FILE.write_text(json.dumps({"varnish": enabled}))
        except OSError as exc:
            return False, f"could not save fronting flag: {exc}"

        def _restore() -> None:
            try:
                config.WEB_FRONTING_FILE.write_text(json.dumps({"varnish": prev}))
            except OSError:
                pass

        try:
            if enabled:
                self._ensure_acme_webroot()
                ok, msg = self._ensure_varnish_config()
                if not ok:
                    _restore()
                    return False, msg
            ok, msg = self._regenerate_all_vhosts(sites)
        except Exception as exc:  # noqa: BLE001 — any failure must not strand the mode.
            _restore()
            return False, str(exc)
        if not ok:
            _restore()
            return False, msg
        mode = "ON" if enabled else "OFF"
        return True, f"Web fronting turned {mode} — {msg}"

    # --- Redis daemon tuning (admin-only) ---------------------------------
    def _redis_override(self, maxmemory_mb: int, policy: str) -> str:
        # Clear ExecStart first (systemd appends otherwise), then relaunch
        # redis-server with our caps appended after the stock config file — CLI
        # options override redis.conf, so we win without editing the distro file.
        # --supervised systemd --daemonize no mirror Debian's own unit so systemd
        # keeps tracking the process. maxmemory_mb/policy are pre-validated by the
        # caller (clamped int + allowlisted policy), so nothing here can inject.
        return (
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart={REDIS_BIN} {REDIS_CONF} "
            f"--maxmemory {maxmemory_mb}mb --maxmemory-policy {policy} "
            "--supervised systemd --daemonize no\n"
        )

    def tune_redis(self, maxmemory_mb: int, policy: str) -> tuple[bool, str]:
        # Validate + clamp before anything touches the system. The router checks
        # too, but the provider is the last line of defense: a bad value can
        # never reach the systemd unit.
        if policy not in config.REDIS_EVICTION_POLICIES:
            return False, f"Unknown eviction policy: {policy}"
        try:
            maxmemory_mb = int(maxmemory_mb)
        except (TypeError, ValueError):
            return False, "maxmemory must be a whole number of MB."
        maxmemory_mb = max(config.REDIS_MAXMEMORY_MIN_MB,
                           min(config.REDIS_MAXMEMORY_MAX_MB, maxmemory_mb))
        unit, _load = self._resolve_unit("redis")
        if unit is None:
            return False, "Redis is not installed on this server."
        # Drop-in path follows the resolved unit so we never guess the name.
        override = Path(f"/etc/systemd/system/{unit}.service.d/litespanel.conf")
        prev = override.read_text() if override.exists() else None
        try:
            override.parent.mkdir(parents=True, exist_ok=True)
            override.write_text(self._redis_override(maxmemory_mb, policy))
        except OSError as exc:
            return False, f"could not write Redis tuning: {exc}"

        def _rollback() -> None:
            # Put the previous drop-in back (or remove ours) and best-effort
            # restart, so a failed tune never leaves Redis wedged on our config.
            try:
                if prev is None:
                    override.unlink(missing_ok=True)
                else:
                    override.write_text(prev)
                _run(["systemctl", "daemon-reload"])
                subprocess.run(["systemctl", "restart", f"{unit}.service"],
                               capture_output=True, text=True)
            except (RuntimeError, OSError):
                pass

        try:
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "restart", f"{unit}.service"])
        except RuntimeError as exc:
            _rollback()
            return False, f"Redis failed to restart, rolled back: {exc}"
        try:
            _run(["systemctl", "enable", f"{unit}.service"])
        except RuntimeError:
            pass  # already-enabled / masked shouldn't fail the tune
        # Persist only after the daemon actually came back up.
        try:
            config.REDIS_TUNING_FILE.write_text(
                json.dumps({"maxmemory_mb": maxmemory_mb, "policy": policy})
            )
        except OSError as exc:
            return False, f"Redis tuned but could not save state: {exc}"
        return True, f"Redis capped at {maxmemory_mb} MB, policy {policy}."

    # --- Panel self-update ------------------------------------------------
    # Admin-only: check for updates and upgrade the panel itself via git pull +
    # migrations + restart. The work runs fully detached (systemd-run --scope)
    # so restarting the litespanel.service doesn't kill the update mid-flight.
    def panel_version(self) -> dict:
        import os

        panel_dir = Path(config.PANEL_INSTALL_DIR)
        # If the install dir isn't a git checkout (install.sh copies files),
        # we can't determine a version. Return a best-effort dict.
        if not (panel_dir / ".git").is_dir():
            return {"commit": None, "short": "unknown", "branch": None,
                    "dirty": False, "describe": "not a git repository"}
        try:
            # Current commit hash (HEAD)
            proc = subprocess.run(["git", "rev-parse", "HEAD"],
                                  cwd=str(panel_dir), capture_output=True, text=True)
            commit = proc.stdout.strip() if proc.returncode == 0 else None
            short = commit[:7] if commit else "unknown"
            # Current branch
            proc = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                  cwd=str(panel_dir), capture_output=True, text=True)
            branch = proc.stdout.strip() if proc.returncode == 0 else None
            # Uncommitted changes?
            proc = subprocess.run(["git", "status", "--porcelain"],
                                  cwd=str(panel_dir), capture_output=True, text=True)
            dirty = bool(proc.stdout.strip()) if proc.returncode == 0 else False
            # git describe (human label)
            proc = subprocess.run(["git", "describe", "--always", "--tags"],
                                  cwd=str(panel_dir), capture_output=True, text=True)
            describe = proc.stdout.strip() if proc.returncode == 0 else short
        except (FileNotFoundError, OSError):
            return {"commit": None, "short": "unknown", "branch": None,
                    "dirty": False, "describe": "git not available"}
        return {"commit": commit, "short": short, "branch": branch,
                "dirty": dirty, "describe": describe}

    def check_panel_update(self) -> dict:
        panel_dir = Path(config.PANEL_INSTALL_DIR)
        cur = self.panel_version()
        if cur["commit"] is None:
            return {"available": False, "current": cur["short"], "latest": cur["short"],
                    "behind": 0, "message": "The panel is not a git repository."}
        # Fetch the remote (read-only, doesn't change the working tree)
        try:
            subprocess.run(["git", "fetch", "origin", config.PANEL_REPO_BRANCH],
                           cwd=str(panel_dir), capture_output=True, text=True,
                           timeout=30, check=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            return {"available": False, "current": cur["short"], "latest": cur["short"],
                    "behind": 0, "message": f"Could not fetch remote: {exc}"}
        # Compare HEAD with origin/<branch>
        try:
            proc = subprocess.run(
                ["git", "rev-list", "--count", f"HEAD..origin/{config.PANEL_REPO_BRANCH}"],
                cwd=str(panel_dir), capture_output=True, text=True, timeout=10)
            behind = int(proc.stdout.strip()) if proc.returncode == 0 else 0
            proc = subprocess.run(["git", "rev-parse", f"origin/{config.PANEL_REPO_BRANCH}"],
                                  cwd=str(panel_dir), capture_output=True, text=True)
            latest_hash = proc.stdout.strip() if proc.returncode == 0 else cur["commit"]
            latest_short = latest_hash[:7] if latest_hash else cur["short"]
        except (ValueError, subprocess.TimeoutExpired, OSError):
            return {"available": False, "current": cur["short"], "latest": cur["short"],
                    "behind": 0, "message": "Could not compare versions."}
        if behind > 0:
            return {"available": True, "current": cur["short"], "latest": latest_short,
                    "behind": behind, "message": f"{behind} newer commit(s) available."}
        return {"available": False, "current": cur["short"], "latest": cur["short"],
                "behind": 0, "message": "The panel is up to date."}

    def update_panel(self) -> tuple[bool, str]:
        """Launch a detached background update (sync to latest + migrate + restart).

        The update runs via `systemd-run` as a transient unit — OUTSIDE the
        panel's own cgroup — so `systemctl restart litespanel` at the end can't
        kill the update mid-flight. The script is written under DATA_DIR (not the
        panel dir) so `git reset --hard` can't rewrite the file bash is running.

        Idempotent and data-safe: the working tree is synced to origin (via
        `git init` + `reset --hard` when the install isn't yet a checkout), while
        the DB and all hosted data live under a separate DATA_DIR that git never
        touches — the same guarantee as re-running install.sh.
        """
        cur = self.panel_version()
        panel_dir = config.PANEL_INSTALL_DIR
        branch = config.PANEL_REPO_BRANCH
        repo = config.PANEL_REPO_URL
        log = config.PANEL_UPDATE_LOG
        service = config.PANEL_SERVICE_NAME
        venv_py = f"{panel_dir}/.venv/bin/python"
        venv_pip = f"{panel_dir}/.venv/bin/pip"
        venv_alembic = f"{panel_dir}/.venv/bin/alembic"
        # Script lives outside panel_dir so a `git reset --hard` can't rewrite
        # the file bash is mid-way through executing.
        script = Path(config.DATA_DIR) / "update-panel.sh"
        script.write_text(f"""#!/usr/bin/env bash
# LitesPanel self-updater — launched detached by the WHM Update page.
set -uo pipefail
LOG="{log}"
say() {{ echo "$(date '+%Y-%m-%d %H:%M:%S'): $*" >> "$LOG"; }}
fail() {{ say "FAILED: $*"; exit 1; }}

say "=== panel update started ==="
command -v git >/dev/null 2>&1 || {{ apt-get update -qq && apt-get install -y -qq git; }} >> "$LOG" 2>&1
cd "{panel_dir}" || fail "cannot cd into {panel_dir}"

# Ensure the install dir is a git checkout tracking origin/{branch}. install.sh
# copies files (no .git), so on the first update we initialise in place. This
# only rewrites tracked files; .venv and DATA_DIR are untouched.
if [ ! -d .git ]; then
    say "not a git checkout yet — initialising from {repo}"
    git init -q >> "$LOG" 2>&1 || fail "git init failed"
    git remote add origin "{repo}" 2>/dev/null || git remote set-url origin "{repo}"
fi
git fetch origin "{branch}" >> "$LOG" 2>&1 || fail "git fetch failed"
git reset --hard "origin/{branch}" >> "$LOG" 2>&1 || fail "git reset failed"
git branch --set-upstream-to="origin/{branch}" 2>/dev/null || true

# Dependencies may have changed between versions.
"{venv_pip}" install -q -r requirements.txt >> "$LOG" 2>&1 || say "pip install had warnings (continuing)"

# Apply migrations. init_db() runs `alembic upgrade head`; a fresh DB gets every
# table, an existing one only new migrations — no data loss.
if [ -x "{venv_alembic}" ]; then
    "{venv_alembic}" upgrade head >> "$LOG" 2>&1 || fail "database migration failed"
else
    "{venv_py}" -c "from app.db import init_db; init_db()" >> "$LOG" 2>&1 || fail "database migration failed"
fi

NEW=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
say "restarting {service} (now at $NEW)"
systemctl restart "{service}" >> "$LOG" 2>&1 || fail "service restart failed"
say "=== panel update finished successfully (now at $NEW) ==="
""", encoding="utf-8")
        script.chmod(0o755)
        # systemd-run puts the script in its own transient unit/cgroup, so the
        # final `systemctl restart litespanel` won't take the updater down with
        # it. start_new_session detaches from the request's process group too.
        try:
            proc = subprocess.run(
                ["systemd-run", "--collect", "--unit", "litespanel-update",
                 "--description", "LitesPanel self-update",
                 "bash", str(script)],
                capture_output=True, text=True, start_new_session=True, timeout=15,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            return False, f"Could not launch the updater: {exc}"
        if proc.returncode != 0:
            return False, "Could not launch the updater: " + (proc.stderr or proc.stdout).strip()[-300:]
        return True, (f"Update started in the background (currently {cur['short']}). "
                      "The panel will restart in a moment — refresh this page shortly.")

    def panel_update_log(self, lines: int = 200) -> str:
        """Return the tail of the self-update log (empty string if none yet)."""
        try:
            content = Path(config.PANEL_UPDATE_LOG).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return "\n".join(content.splitlines()[-lines:])

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
