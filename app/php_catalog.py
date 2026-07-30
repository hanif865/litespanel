"""Static catalog for the PHP Selector.

The set of togglable extensions and the editable php.ini directives are the
same regardless of which provider is running, so they live here as plain data
rather than in provider state. The panel DB (PhpConfig rows) stores the user's
choices; the provider only *applies* them to disk, the same way DnsRecord rows
drive sync_zone.
"""
from __future__ import annotations

# PHP-FPM versions the panel offers. Newest first (index 0 is the default).
PHP_VERSIONS = ["8.3", "8.2", "8.1", "8.0", "7.4"]

DEFAULT_PHP_VERSION = PHP_VERSIONS[0]

# Extensions shown in the selector. `default` = enabled on a fresh account.
# All ship enabled so a new account has the full stack available out of the box.
_EXTENSIONS: list[tuple[str, bool]] = [
    ("amqp", True),
    ("apcu", True),
    ("bcmath", True),
    ("bz2", True),
    ("calendar", True),
    ("curl", True),
    ("exif", True),
    ("gd", True),
    ("gmp", True),
    ("imagick", True),
    ("imap", True),
    ("intl", True),
    ("ioncube_loader", True),
    ("ldap", True),
    ("mbstring", True),
    ("mysqli", True),
    ("opcache", True),
    ("pdo_mysql", True),
    ("pdo_sqlite", True),
    ("redis", True),
    ("soap", True),
    ("sodium", True),
    ("sqlite3", True),
    ("xml", True),
    ("zip", True),
]

AVAILABLE_EXTENSIONS: list[str] = [name for name, _ in _EXTENSIONS]

# Editable php.ini directives with their default values (strings — the form
# posts strings and php.ini is textual anyway).
_DIRECTIVES: list[tuple[str, str]] = [
    ("allow_url_fopen", "On"),
    ("display_errors", "Off"),
    ("max_execution_time", "30"),
    ("max_input_time", "60"),
    ("max_input_vars", "1000"),
    ("memory_limit", "256M"),
    ("post_max_size", "32M"),
    ("upload_max_filesize", "32M"),
    ("session.gc_maxlifetime", "1440"),
    ("date.timezone", "UTC"),
]

DEFAULT_DIRECTIVES: dict[str, str] = dict(_DIRECTIVES)

DIRECTIVE_ORDER: list[str] = [key for key, _ in _DIRECTIVES]


def default_extensions() -> dict[str, bool]:
    """A fresh {ext: enabled} map with catalog defaults."""
    return {name: on for name, on in _EXTENSIONS}


def default_directives() -> dict[str, str]:
    """A fresh {directive: value} map with catalog defaults."""
    return dict(DEFAULT_DIRECTIVES)


def merged_extensions(saved: dict | None) -> dict[str, bool]:
    """Catalog defaults overlaid with the user's saved choices.

    Unknown keys in `saved` are dropped and missing keys fall back to default,
    so the returned map always covers exactly AVAILABLE_EXTENSIONS.
    """
    result = default_extensions()
    for name in result:
        if saved and name in saved:
            result[name] = bool(saved[name])
    return result


def merged_directives(saved: dict | None) -> dict[str, str]:
    """Catalog defaults overlaid with the user's saved directive values."""
    result = default_directives()
    for key in result:
        if saved and key in saved and saved[key] != "":
            result[key] = str(saved[key])
    return result
