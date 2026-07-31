"""The Provider interface.

Every method here is something a real hosting box does at the OS level. The
demo provider fakes them on the local filesystem; the linux provider shells
out to the real tools. Keep this list small and stable — it's the contract.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


def safe_extract_path(base: Path, relative: str) -> Path | None:
    """Resolve `relative` under `base`, returning None if it escapes (Zip Slip).

    Used when unpacking a backup archive so a crafted member like
    "../../etc/passwd" can never write outside the intended directory.
    """
    base = base.resolve()
    target = (base / relative).resolve()
    if target == base or base in target.parents:
        return target
    return None


def tail_file(path: Path, lines: int = 200, grep: str | None = None) -> str:
    """Return roughly the last `lines` lines of a text file, cheaply.

    Reads from the end in blocks so a multi-gigabyte log never loads into
    memory whole. When `grep` is given, only lines containing that substring
    (case-insensitive) are kept, and up to `lines` of the most recent matches
    are returned. Missing/unreadable files yield an empty string.
    """
    lines = max(1, min(lines, 5000))
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)  # end of file
            end = fh.tell()
            block = 8192
            data = b""
            # Grepping needs to scan more of the file to find enough matches.
            want = lines if grep is None else lines * 20
            while end > 0 and data.count(b"\n") <= want:
                step = min(block, end)
                end -= step
                fh.seek(end)
                data = fh.read(step) + data
    except OSError:
        return ""

    text = data.decode("utf-8", errors="replace")
    result = text.splitlines()
    if grep:
        needle = grep.lower()
        result = [ln for ln in result if needle in ln.lower()]
    return "\n".join(result[-lines:])



@dataclass
class CertInfo:
    issuer: str
    issued_at: datetime
    expires_at: datetime
    cert_path: str


@dataclass
class DbCredentials:
    name: str
    user: str
    password: str
    host: str = "localhost"
    port: int = 3306


class Provider(ABC):
    """OS-level operations for one hosting node."""

    name: str = "base"

    # --- Accounts (system-user isolation) ---------------------------------
    @abstractmethod
    def ensure_account(self, username: str) -> Path:
        """Create the account's Linux user + PHP-FPM pool if missing.

        Idempotent. Returns the account's home directory. Sites owned by this
        account run PHP as this user, so accounts can't read each other's files.
        """

    @abstractmethod
    def remove_account(self, username: str) -> None:
        """Delete the account's system user, home directory and PHP-FPM pool."""

    # --- Web hosting (nginx vhosts) ---------------------------------------
    @abstractmethod
    def create_site(self, domain: str, docroot: Path, php_version: str, system_user: str) -> Path:
        """Provision a vhost at docroot, running PHP as system_user. Returns docroot."""

    @abstractmethod
    def remove_site(self, domain: str) -> None:
        """Tear down the vhost and its config (docroot handling is caller's)."""

    @abstractmethod
    def reload_web(self) -> None:
        """Apply web-server config changes (nginx -s reload)."""

    @abstractmethod
    def set_php_version(self, domain: str, docroot: str, php_version: str, system_user: str) -> None:
        """Rewrite the vhost so the site runs on a different PHP-FPM version."""

    @abstractmethod
    def apply_php_config(self, system_user: str, php_version: str,
                         extensions: dict[str, bool], directives: dict[str, str],
                         domain: str | None = None) -> None:
        """Materialize an account's PHP settings to disk.

        The panel DB (PhpConfig rows) is the source of truth; this writes the
        chosen extensions and php.ini directives into the account's PHP-FPM
        pool config and reloads PHP. `domain` is None for the account-global
        profile, or a domain name when a per-domain override is applied.
        """

    @abstractmethod
    def list_installed_extensions(self, php_version: str) -> set[str]:
        """Return the set of PHP extensions actually loaded on this host.

        Used by the PHP Selector to show which toggled extensions are really
        available (installed) vs merely requested.
        """

    @abstractmethod
    def install_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        """Install one PHP extension's system package. Returns (ok, message).

        Admin-only at the router layer — this shells out to the package manager
        as root, so it must never be reachable by ordinary hosting accounts.
        """

    @abstractmethod
    def uninstall_extension(self, extension: str, php_version: str) -> tuple[bool, str]:
        """Remove one PHP extension's system package. Returns (ok, message)."""

    @abstractmethod
    def set_https_redirect(self, domain: str, docroot: str, php_version: str,
                           system_user: str, enabled: bool, has_ssl: bool) -> None:
        """Rewrite the vhost to force (or stop forcing) an HTTP→HTTPS redirect."""

    # --- Node.js (admin-only) ---------------------------------------------
    @abstractmethod
    def install_node(self, version: str) -> tuple[bool, str]:
        """Install the Node.js runtime (major `version`) on this host.

        Admin-only at the router layer — this shells out to the package manager
        as root (NodeSource), so it must never be reachable by ordinary hosting
        accounts. Returns (ok, message).
        """

    @abstractmethod
    def node_installed_version(self) -> str | None:
        """Return the installed Node.js version string, or None if absent."""

    @abstractmethod
    def deploy_node_app(self, name: str, domain: str, app_dir: Path, port: int,
                        entrypoint: str, system_user: str, node_version: str) -> tuple[bool, str]:
        """Create/refresh a Node app's systemd unit + nginx reverse proxy and start it.

        Admin-only at the router layer. Writes a per-app systemd service that
        runs `node <entrypoint>` in `app_dir` as `system_user` on `port`,
        rewrites the domain's vhost to proxy_pass to that port, then reloads.
        Returns (ok, message).
        """

    @abstractmethod
    def control_node_app(self, name: str, action: str) -> tuple[bool, str]:
        """Start/stop/restart a Node app's service. action in {start, stop, restart}."""

    @abstractmethod
    def remove_node_app(self, name: str, domain: str) -> None:
        """Stop+disable the service, remove its unit and the reverse-proxy vhost."""

    @abstractmethod
    def node_app_status(self, name: str) -> str:
        """Return "running", "stopped" or "unknown" for the app's service."""

    # --- Subdomains -------------------------------------------------------
    @abstractmethod
    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str, system_user: str) -> Path:
        """Provision a subdomain vhost pointing at docroot. Returns docroot."""

    @abstractmethod
    def remove_subdomain(self, fqdn: str) -> None:
        ...

    @abstractmethod
    def set_owner(self, path: Path, system_user: str) -> None:
        """Give a path (recursively) to the account's system user."""

    @abstractmethod
    def run_wp_cli(self, docroot: Path, system_user: str, args: list[str]) -> tuple[bool, str]:
        """Run wp-cli in docroot as the account user. Returns (ok, output)."""

    # --- Cron -------------------------------------------------------------
    @abstractmethod
    def sync_cron(self, lines: list[str]) -> None:
        """Replace the managed crontab with these `schedule command` lines."""

    # --- Databases --------------------------------------------------------
    @abstractmethod
    def create_database(self, name: str, user: str, password: str) -> DbCredentials:
        ...

    @abstractmethod
    def drop_database(self, name: str, user: str) -> None:
        ...

    @abstractmethod
    def reset_db_password(self, name: str, user: str, password: str) -> None:
        """Set the database user's password (used to enable phpMyAdmin auto-login)."""

    @abstractmethod
    def db_tables(self, name: str) -> list[str]:
        """List table names in the database (for the DB manager)."""

    @abstractmethod
    def db_execute(self, name: str, sql: str) -> dict:
        """Run SQL. Returns {columns, rows, message, error}."""

    # --- SSL --------------------------------------------------------------
    @abstractmethod
    def issue_certificate(self, domain: str) -> CertInfo:
        """Obtain/generate a TLS cert for the domain."""

    @abstractmethod
    def revoke_certificate(self, domain: str) -> None:
        ...

    # --- DNS --------------------------------------------------------------
    @abstractmethod
    def sync_zone(self, domain: str, records: list[dict]) -> None:
        """Write/reload the DNS zone for a domain from the given records.

        Each record: {type, name, value, ttl, priority}.
        """

    # --- Email ------------------------------------------------------------
    @abstractmethod
    def create_mailbox(self, address: str, password: str, quota_mb: int) -> None:
        ...

    @abstractmethod
    def delete_mailbox(self, address: str) -> None:
        ...

    @abstractmethod
    def sync_forwarders(self, domain: str, pairs: list[tuple[str, str]]) -> None:
        """Rewrite the domain's forwarders from (source_local, destination) pairs."""

    @abstractmethod
    def set_autoresponder(self, address: str, subject: str, body: str, enabled: bool) -> None:
        ...

    @abstractmethod
    def remove_autoresponder(self, address: str) -> None:
        ...

    # --- Backups ----------------------------------------------------------
    @abstractmethod
    def create_backup(self, dest_zip: Path, sites: list[tuple[str, str]], databases: list[str]) -> dict:
        """Archive the given sites + databases (+ their dns/mail) into dest_zip.

        `sites` is a list of (domain_name, site_directory) so files are read
        from wherever they actually live. Returns {size_bytes, items}.
        """

    @abstractmethod
    def restore_backup(self, zip_path: Path) -> dict:
        """Restore files/databases from a backup archive. Returns {items}."""

    # --- Health -----------------------------------------------------------
    @abstractmethod
    def system_stats(self) -> dict:
        """Coarse host metrics for the dashboard (cpu/mem/disk)."""

    # --- Firewall / security (admin-only) ---------------------------------
    @abstractmethod
    def firewall_status(self) -> dict:
        """Return the host firewall state.

        Shape: {backend, available, active, default_incoming, default_outgoing}.
        `backend` is "ufw" (or "none"); `available` is False when the tool is
        not installed. Admin-only at the router layer.
        """

    @abstractmethod
    def list_firewall_rules(self) -> list[dict]:
        """List active firewall rules.

        Each rule: {num, to, action, source}. `num` is the ufw rule index used
        by delete_firewall_rule. Returns [] when the firewall is off/absent.
        """

    @abstractmethod
    def set_firewall_enabled(self, enabled: bool) -> tuple[bool, str]:
        """Enable or disable the host firewall. Returns (ok, message).

        Admin-only — enabling ufw applies packet filtering to the whole host,
        so a bad rule set can lock out SSH. The caller is expected to warn.
        """

    @abstractmethod
    def add_firewall_rule(self, port: int, proto: str, action: str,
                          source: str | None = None) -> tuple[bool, str]:
        """Allow/deny a port (optionally from one source IP/CIDR).

        proto in {tcp, udp}; action in {allow, deny}. Returns (ok, message).
        """

    @abstractmethod
    def delete_firewall_rule(self, num: int) -> tuple[bool, str]:
        """Delete the firewall rule with index `num`. Returns (ok, message)."""

    @abstractmethod
    def fail2ban_status(self) -> dict:
        """Return the fail2ban state: {available, active, jails}.

        `jails` is the list of configured jail names. Admin-only.
        """

    @abstractmethod
    def list_banned_ips(self, jail: str) -> list[str]:
        """List currently banned IPs for a jail. Returns [] if none/absent."""

    @abstractmethod
    def ban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        """Ban an IP in a jail via fail2ban-client. Returns (ok, message)."""

    @abstractmethod
    def unban_ip(self, ip: str, jail: str) -> tuple[bool, str]:
        """Unban an IP from a jail via fail2ban-client. Returns (ok, message)."""

    # --- Logs (admin-only) ------------------------------------------------
    @abstractmethod
    def log_sources(self) -> list[dict]:
        """Return the log files this host exposes to the viewer.

        Each entry: {key, label, category}. `key` is an opaque identifier the
        router passes back to read_log — the raw filesystem path is NEVER
        accepted from the client, so the viewer can only ever read files on
        this provider-defined allowlist (no path traversal). Entries whose
        underlying file is absent are omitted. Admin-only at the router layer.
        """

    @abstractmethod
    def read_log(self, key: str, lines: int = 200, grep: str | None = None) -> tuple[bool, str]:
        """Return the tail of the log identified by `key`.

        Returns (ok, text). ok is False (with an explanatory message) when
        `key` is not a known source. `lines` caps how many trailing lines come
        back; `grep` optionally filters to matching lines. Admin-only.
        """

