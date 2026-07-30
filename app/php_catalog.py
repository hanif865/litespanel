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

# The full catalog of extensions the panel exposes, cPanel-style. Every
# extension a typical Ubuntu/CloudLinux PHP install can offer is listed so the
# user can enable exactly what they need. Order is alphabetical; the UI groups
# them by first letter.
ALL_EXTENSIONS: list[str] = [
    "amqp", "apcu",
    "bcmath", "bitset", "brotli", "bz2",
    "calendar", "core", "ctype", "curl",
    "date", "dba", "dbase", "diseval", "dom",
    "eio", "elastic_apm", "enchant", "exif",
    "ffi", "fileinfo", "filter", "ftp",
    "gd", "gearman", "gender", "geoip", "geos", "gettext", "gmagick", "gmp",
    "gnupg", "grpc",
    "hash", "htscanner", "http",
    "iconv", "igbinary", "imagick", "imap", "inotify", "intl", "ioncube_loader",
    "jsmin", "json",
    "ldap", "leveldb", "libxml", "luasandbox", "lzf",
    "mailparse", "mbstring", "mcrypt", "memcache", "memcached", "mongodb",
    "msgpack", "mysqli", "mysqlnd",
    "nd_mysqli", "nd_pdo_mysql", "newrelic",
    "oauth", "oci8", "odbc", "opcache", "openssl",
    "pcntl", "pcre", "pdf", "pdo", "pdo_dblib", "pdo_firebird", "pdo_mysql",
    "pdo_oci", "pdo_odbc", "pdo_pgsql", "pdo_sqlite", "pdo_sqlsrv", "pgsql",
    "phalcon5", "phar", "phpiredis", "posix", "protobuf", "pspell", "psr",
    "random", "raphf", "rar", "readline", "redis", "reflection", "rrd",
    "scoutapm", "session", "shmop", "simplexml", "snmp", "snuffleupagus",
    "soap", "sockets", "sodium", "solr", "sourceguardian", "spl", "sqlite3",
    "sqlsrv", "ssh2", "standard", "stats", "swoole", "sysvmsg", "sysvsem",
    "sysvshm",
    "tideways_xhprof", "tidy", "timezonedb", "tokenizer", "trader",
    "uploadprogress", "uuid",
    "vips",
    "xdebug", "xdiff", "xml", "xmlreader", "xmlrpc", "xmlwriter", "xsl",
    "yaf", "yaml", "yaz",
    "zip", "zlib", "zmq",
]

# Enabled on a fresh account: the common stack that a typical WordPress /
# Laravel / general PHP site needs. Everything else stays available but off so
# the user turns on only what they use (xdebug, oci8, sqlsrv, profilers, etc.
# are intentionally off by default). Core/always-compiled modules are included
# so the list reflects reality.
_DEFAULT_ON: set[str] = {
    "apcu", "bcmath", "bz2", "calendar", "core", "ctype", "curl", "date",
    "dom", "exif", "fileinfo", "filter", "ftp", "gd", "gettext", "gmp",
    "hash", "iconv", "igbinary", "imagick", "intl", "json", "libxml",
    "mbstring", "mysqli", "mysqlnd", "opcache", "openssl", "pcre", "pdo",
    "pdo_mysql", "pdo_sqlite", "phar", "posix", "random", "readline", "redis",
    "reflection", "session", "simplexml", "soap", "sockets", "sodium", "spl",
    "sqlite3", "standard", "tokenizer", "xml", "xmlreader", "xmlrpc",
    "xmlwriter", "xsl", "zip", "zlib",
}

AVAILABLE_EXTENSIONS: list[str] = list(ALL_EXTENSIONS)

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
    return {name: (name in _DEFAULT_ON) for name in ALL_EXTENSIONS}


def default_directives() -> dict[str, str]:
    """A fresh {directive: value} map with catalog defaults."""
    return dict(DEFAULT_DIRECTIVES)


def grouped_extensions() -> list[tuple[str, list[str]]]:
    """Extensions bucketed by first letter, e.g. [('A', ['amqp','apcu']), ...]."""
    groups: list[tuple[str, list[str]]] = []
    for name in ALL_EXTENSIONS:
        letter = name[0].upper()
        if not groups or groups[-1][0] != letter:
            groups.append((letter, []))
        groups[-1][1].append(name)
    return groups


def merged_extensions(saved: dict | None) -> dict[str, bool]:
    """Catalog defaults overlaid with the user's saved choices.

    Unknown keys in `saved` are dropped and missing keys fall back to default,
    so the returned map always covers exactly ALL_EXTENSIONS.
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
