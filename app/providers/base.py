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

    # --- Web hosting (nginx vhosts) ---------------------------------------
    @abstractmethod
    def create_site(self, domain: str, php_version: str) -> Path:
        """Provision a vhost + docroot. Returns the document root path."""

    @abstractmethod
    def remove_site(self, domain: str) -> None:
        """Tear down the vhost and its config (docroot handling is caller's)."""

    @abstractmethod
    def reload_web(self) -> None:
        """Apply web-server config changes (nginx -s reload)."""

    @abstractmethod
    def set_php_version(self, domain: str, docroot: str, php_version: str) -> None:
        """Rewrite the vhost so the site runs on a different PHP-FPM version."""

    # --- Subdomains -------------------------------------------------------
    @abstractmethod
    def create_subdomain(self, fqdn: str, docroot: Path, php_version: str) -> Path:
        """Provision a subdomain vhost pointing at docroot. Returns docroot."""

    @abstractmethod
    def remove_subdomain(self, fqdn: str) -> None:
        ...

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
    def create_backup(self, dest_zip: Path, domains: list[str], databases: list[str]) -> dict:
        """Archive the given sites + databases (+ their dns/mail) into dest_zip.

        Returns {size_bytes, items}.
        """

    @abstractmethod
    def restore_backup(self, zip_path: Path) -> dict:
        """Restore files/databases from a backup archive. Returns {items}."""

    # --- Health -----------------------------------------------------------
    @abstractmethod
    def system_stats(self) -> dict:
        """Coarse host metrics for the dashboard (cpu/mem/disk)."""
