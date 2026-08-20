"""The privilege catalog for standalone database users — the single source of
truth shared by the routers, the providers and the templates.

cPanel-style: a database user is created independently, then *added to* a
database with a chosen set of privileges. Each engine has its own native
privilege vocabulary (MySQL's table-privilege list is not PostgreSQL's
database/schema grants), so both are listed here and validated the same way.

The safety contract: privileges are ALWAYS drawn from these fixed allowlists.
`normalize()` rejects anything else, so only these exact tokens — which contain
letters and spaces but never quotes/backticks — are ever interpolated into a
GRANT/REVOKE statement by the provider layer.
"""
from __future__ import annotations

from typing import Iterable

# The sentinel stored/emitted when a user holds every privilege on a database.
# MySQL and PostgreSQL both understand `GRANT ALL PRIVILEGES`, and collapsing to
# it keeps a "grant everything" intent future-proof if the catalog grows.
ALL = "ALL PRIVILEGES"

# MySQL/MariaDB database-level privileges (as accepted by `GRANT <priv> ON db.*`).
# Order is the canonical display + emit order.
MYSQL_PRIVILEGES: tuple[str, ...] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "ALTER",
    "INDEX",
    "CREATE TEMPORARY TABLES",
    "LOCK TABLES",
    "CREATE VIEW",
    "SHOW VIEW",
    "CREATE ROUTINE",
    "ALTER ROUTINE",
    "EXECUTE",
    "EVENT",
    "TRIGGER",
    "REFERENCES",
)

# PostgreSQL privileges — a mix of database-scoped (CONNECT, CREATE, TEMPORARY)
# and table-scoped (the rest), which the provider applies across schema `public`
# and as default privileges. This is PG's native vocabulary, not MySQL's.
PG_PRIVILEGES: tuple[str, ...] = (
    "CONNECT",
    "CREATE",
    "TEMPORARY",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

# PostgreSQL split: which tokens are granted ON DATABASE vs on tables in the
# public schema. Providers use these to build the right statements.
PG_DATABASE_SCOPED: frozenset[str] = frozenset({"CONNECT", "CREATE", "TEMPORARY"})
PG_TABLE_SCOPED: tuple[str, ...] = tuple(
    p for p in PG_PRIVILEGES if p not in PG_DATABASE_SCOPED
)

_CATALOGS: dict[str, tuple[str, ...]] = {
    "mysql": MYSQL_PRIVILEGES,
    "pg": PG_PRIVILEGES,
}

# Accepted spellings of "everything", collapsed to the ALL sentinel.
_ALL_ALIASES: frozenset[str] = frozenset({"ALL", ALL})


def catalog(engine: str) -> tuple[str, ...]:
    """The ordered privilege tuple for an engine ("mysql" | "pg")."""
    try:
        return _CATALOGS[engine]
    except KeyError:
        raise ValueError(f"Unknown database engine: {engine!r}")


def normalize(engine: str, tokens: Iterable[str]) -> list[str]:
    """Validate + canonicalize a set of requested privilege tokens.

    Returns the tokens in catalog order, deduped, and collapsed to
    ``["ALL PRIVILEGES"]`` when the caller asked for ALL or selected every
    privilege in the catalog. Raises ``ValueError`` on any token that is not in
    the engine's allowlist, so nothing outside the catalog can reach a GRANT.
    An empty selection raises — a grant with no privileges is meaningless.
    """
    allowed = catalog(engine)
    allowed_set = set(allowed)
    requested: set[str] = set()
    for raw in tokens:
        token = " ".join(str(raw).strip().upper().split())  # squeeze inner spaces
        if not token:
            continue
        if token in _ALL_ALIASES:
            return [ALL]
        if token not in allowed_set:
            raise ValueError(f"Unknown {engine} privilege: {raw!r}")
        requested.add(token)
    if not requested:
        raise ValueError("At least one privilege is required.")
    if requested == allowed_set:
        return [ALL]
    return [p for p in allowed if p in requested]


def is_all(privileges: Iterable[str]) -> bool:
    """True when a normalized privilege list is the ALL sentinel."""
    privs = list(privileges)
    return privs == [ALL] or ALL in privs


def to_csv(privileges: Iterable[str]) -> str:
    """Join a normalized privilege list for storage in a grant row."""
    return ",".join(privileges)


def from_csv(value: str | None) -> list[str]:
    """Split a stored grant's CSV back into a privilege list (for display/apply)."""
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]
