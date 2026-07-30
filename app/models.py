"""ORM models — the panel's own metadata.

These describe *what the panel knows about*. The actual system side (nginx
config on disk, the real MySQL database, the cert file) is created by the
provider layer; these rows are the panel's record of it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(default=True)
    # Access role: "admin" (full WHM), "reseller" (manages own users), "user".
    role: Mapped[str] = mapped_column(String(16), default="user")
    # Which admin/reseller created this account (null for the root admin).
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    suspended: Mapped[bool] = mapped_column(default=False)
    # Dedicated Linux system user for this hosting account (isolation). Sites
    # owned by this account run PHP as this user and live under its home dir.
    system_user: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Assigned hosting package (reusable plan). When set, its limits win over
    # the inline per-account limits below.
    package_id: Mapped[int | None] = mapped_column(ForeignKey("packages.id"), nullable=True)
    # Per-account inline limits, used when no package is assigned. 0 = unlimited.
    max_domains: Mapped[int] = mapped_column(default=0)
    max_databases: Mapped[int] = mapped_column(default=0)
    max_email: Mapped[int] = mapped_column(default=0)
    disk_quota_mb: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domains: Mapped[list["Domain"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    databases: Mapped[list["Database"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    cron_jobs: Mapped[list["CronJob"]] = relationship(cascade="all, delete-orphan")
    backups: Mapped[list["Backup"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    package: Mapped["Package | None"] = relationship(
        back_populates="users", foreign_keys="User.package_id"
    )

    @property
    def unlimited(self) -> bool:
        return self.role == "admin"

    # Effective limits: package overrides inline values when assigned.
    @property
    def eff_domains(self) -> int:
        return self.package.max_domains if self.package else self.max_domains

    @property
    def eff_databases(self) -> int:
        return self.package.max_databases if self.package else self.max_databases

    @property
    def eff_email(self) -> int:
        return self.package.max_email if self.package else self.max_email

    @property
    def eff_disk_mb(self) -> int:
        return self.package.disk_quota_mb if self.package else self.disk_quota_mb


class Package(Base):
    """A reusable hosting plan — a named bundle of account limits (WHM-style)."""

    __tablename__ = "packages"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_package_owner_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))  # admin/reseller who owns it
    max_domains: Mapped[int] = mapped_column(default=0)
    max_databases: Mapped[int] = mapped_column(default=0)
    max_email: Mapped[int] = mapped_column(default=0)
    disk_quota_mb: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    users: Mapped[list["User"]] = relationship(
        back_populates="package", foreign_keys="User.package_id"
    )


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # Filesystem path of this site's document root (public_html).
    docroot: Mapped[str] = mapped_column(String(500))
    php_version: Mapped[str] = mapped_column(String(16), default="8.3")
    active: Mapped[bool] = mapped_column(default=True)
    force_https: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    owner: Mapped["User"] = relationship(back_populates="domains")
    certificate: Mapped["Certificate | None"] = relationship(
        back_populates="domain", cascade="all, delete-orphan", uselist=False
    )
    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="parent", cascade="all, delete-orphan"
    )
    dns_records: Mapped[list["DnsRecord"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )
    email_accounts: Mapped[list["EmailAccount"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )
    forwarders: Mapped[list["EmailForwarder"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )
    autoresponders: Mapped[list["Autoresponder"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("fqdn", name="uq_subdomain_fqdn"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(63))          # e.g. "blog"
    fqdn: Mapped[str] = mapped_column(String(253), index=True)  # e.g. "blog.example.com"
    parent_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    docroot: Mapped[str] = mapped_column(String(500))
    php_version: Mapped[str] = mapped_column(String(16), default="8.3")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    parent: Mapped["Domain"] = relationship(back_populates="subdomains")


class PhpConfig(Base):
    """A PHP configuration profile: enabled extensions + php.ini directives.

    Two scopes, mirroring cPanel's PHP Selector:
      * Account global  — owner_id set, domain_id NULL. The account default.
      * Per domain      — domain_id set (owner_id still set for cheap lookups).

    `extensions` is {ext_name: bool} and `directives` is {ini_key: str}. Both
    are stored as JSON so the schema doesn't churn as PHP's option set changes;
    an empty dict means "inherit the provider default".
    """
    __tablename__ = "php_configs"
    __table_args__ = (
        UniqueConstraint("owner_id", "domain_id", name="uq_phpconfig_scope"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # NULL => this row is the account-global profile.
    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id"), nullable=True, index=True
    )
    php_version: Mapped[str] = mapped_column(String(16), default="8.3")
    extensions: Mapped[dict] = mapped_column(JSON, default=dict)
    directives: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    owner: Mapped["User"] = relationship()
    domain: Mapped["Domain | None"] = relationship()


class CronJob(Base):
    __tablename__ = "cron_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    minute: Mapped[str] = mapped_column(String(32), default="*")
    hour: Mapped[str] = mapped_column(String(32), default="*")
    day: Mapped[str] = mapped_column(String(32), default="*")
    month: Mapped[str] = mapped_column(String(32), default="*")
    weekday: Mapped[str] = mapped_column(String(32), default="*")
    command: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    @property
    def schedule(self) -> str:
        return f"{self.minute} {self.hour} {self.day} {self.month} {self.weekday}"


class DnsRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    rtype: Mapped[str] = mapped_column(String(10))          # A, AAAA, CNAME, MX, TXT, NS
    name: Mapped[str] = mapped_column(String(253), default="@")  # host, "@" = apex
    value: Mapped[str] = mapped_column(String(500))
    ttl: Mapped[int] = mapped_column(default=14400)
    priority: Mapped[int | None] = mapped_column(nullable=True)  # MX only
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domain: Mapped["Domain"] = relationship(back_populates="dns_records")


class EmailAccount(Base):
    __tablename__ = "email_accounts"
    __table_args__ = (UniqueConstraint("domain_id", "local_part", name="uq_email_addr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    local_part: Mapped[str] = mapped_column(String(64))     # the bit before @
    quota_mb: Mapped[int] = mapped_column(default=250)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domain: Mapped["Domain"] = relationship(back_populates="email_accounts")

    @property
    def address(self) -> str:
        return f"{self.local_part}@{self.domain.name}"


class EmailForwarder(Base):
    """Forward mail from source@domain to another address ('*' = catch-all)."""

    __tablename__ = "email_forwarders"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    source: Mapped[str] = mapped_column(String(64))          # local part, or "*"
    destination: Mapped[str] = mapped_column(String(255))    # full email address
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domain: Mapped["Domain"] = relationship(back_populates="forwarders")


class Autoresponder(Base):
    """Automatic reply for a mailbox (e.g. out-of-office)."""

    __tablename__ = "autoresponders"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    local_part: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(String(2000))
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domain: Mapped["Domain"] = relationship(back_populates="autoresponders")

    @property
    def address(self) -> str:
        return f"{self.local_part}@{self.domain.name}"


class WordPressApp(Base):
    """A WordPress install the panel manages (for auto-login + listing)."""

    __tablename__ = "wordpress_apps"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"))
    admin_user: Mapped[str] = mapped_column(String(64))
    admin_email: Mapped[str] = mapped_column(String(255))
    login_secret: Mapped[str] = mapped_column(String(64))  # HMAC key for auto-login
    db_name: Mapped[str | None] = mapped_column(String(64), nullable=True)  # for uninstall
    # Subdirectory the install lives in ("" = domain root, "wp" = /wp). Lets one
    # domain host several WordPress sites, Softaculous-style.
    path: Mapped[str] = mapped_column(String(64), default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    domain: Mapped["Domain"] = relationship()


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(default=0)
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    owner: Mapped["User"] = relationship(back_populates="backups")


class Database(Base):
    __tablename__ = "databases"
    __table_args__ = (UniqueConstraint("name", name="uq_database_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    db_user: Mapped[str] = mapped_column(String(64))
    # The MySQL user's password, encrypted at rest (see app/crypto.py). Stored
    # only so the Database Manager can auto-login to phpMyAdmin as this scoped
    # user; null for databases created before auto-login existed.
    db_password_enc: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    owner: Mapped["User"] = relationship(back_populates="databases")


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), unique=True)
    issuer: Mapped[str] = mapped_column(String(64), default="Let's Encrypt")
    # ISO date strings kept simple for the demo.
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    cert_path: Mapped[str] = mapped_column(String(500))

    domain: Mapped["Domain"] = relationship(back_populates="certificate")
