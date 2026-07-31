"""Access/error-log parsing for the Metrics page.

Providers are responsible only for *locating and reading* a domain's logs
(where they live differs per host); the parsing lives here so both the demo and
linux providers feed the exact same analysis. Input is the nginx "combined" log
format — the default — so no custom log_format is required on the host.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime

# Combined log format:
#   IP - - [10/Oct/2000:13:55:36 +0000] "GET /path HTTP/1.1" 200 2326 "ref" "ua"
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def human_bytes(n: int) -> str:
    step = 1024.0
    val = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < step:
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.1f} {unit}"
        val /= step
    return f"{val:.1f} PB"


def parse_access_log(lines: list[str], top: int = 10) -> dict:
    """Parse combined-format access-log lines into a metrics summary."""
    hits = 0
    total_bytes = 0
    visitors: set[str] = set()
    pages: Counter = Counter()
    statuses: Counter = Counter()
    referrers: Counter = Counter()
    not_found: Counter = Counter()
    by_day: Counter = Counter()

    for line in lines:
        m = _COMBINED_RE.match(line.strip())
        if not m:
            continue
        hits += 1
        visitors.add(m.group("ip"))
        nbytes = m.group("bytes")
        if nbytes.isdigit():
            total_bytes += int(nbytes)
        path = m.group("path")
        status = m.group("status")
        pages[path] += 1
        statuses[status] += 1
        if status == "404":
            not_found[path] += 1
        ref = m.group("referer")
        if ref and ref != "-":
            referrers[ref] += 1
        # Group hits per calendar day for a simple traffic breakdown.
        raw_time = m.group("time")
        try:
            day = datetime.strptime(raw_time.split()[0], "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d")
            by_day[day] += 1
        except (ValueError, IndexError):
            pass

    # Bucket status codes into cPanel-style classes for a quick health read.
    classes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for code, count in statuses.items():
        cls = f"{code[0]}xx"
        if cls in classes:
            classes[cls] += count

    return {
        "hits": hits,
        "visitors": len(visitors),
        "bandwidth_bytes": total_bytes,
        "bandwidth_display": human_bytes(total_bytes),
        "top_pages": pages.most_common(top),
        "status_counts": dict(sorted(statuses.items())),
        "status_classes": classes,
        "top_referrers": referrers.most_common(top),
        "not_found": not_found.most_common(top),
        "by_day": sorted(by_day.items()),
    }


def parse_error_log(lines: list[str], limit: int = 50) -> list[str]:
    """Return the most recent error-log lines (already tail-ordered)."""
    cleaned = [ln.rstrip("\n") for ln in lines if ln.strip()]
    return cleaned[-limit:]
