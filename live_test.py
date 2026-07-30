"""Live panel crawler for authorized dev-site testing.

Logs in as admin then regular user, GETs every route, records status codes
and role-gating behaviour. Results written UTF-8 to live_test_report.txt.
"""
from __future__ import annotations

import sys
import re
import requests

BASE = "https://panel.netlihost.com"

ADMIN = ("admin", sys.argv[1] if len(sys.argv) > 1 else "")
USER = ("sostahaat", sys.argv[2] if len(sys.argv) > 2 else "")

# Every GET route mounted in app/main.py include order.
ROUTES = [
    "/", "/domains", "/subdomains", "/dns", "/email", "/forwarders",
    "/autoresponders", "/files", "/databases", "/database-wizard",
    "/database-manager", "/php", "/node", "/cron", "/wordpress", "/ssl",
    "/backups", "/packages", "/users",
]

# Routes that should be blocked for a non-admin (redirect to / or error).
ADMIN_ONLY = {"/node", "/packages", "/users"}

OUT = []


def log(line: str = "") -> None:
    OUT.append(line)


def login(username: str, password: str):
    s = requests.Session()
    s.headers.update({"Origin": BASE, "Referer": BASE + "/login"})
    r = s.post(
        BASE + "/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=30,
    )
    ok = r.status_code in (302, 303) and "set-cookie" in {k.lower() for k in r.headers}
    return s, r, ok


def crawl(label: str, s: requests.Session) -> None:
    log(f"\n{'='*60}\n{label}\n{'='*60}")
    for path in ROUTES:
        try:
            r = s.get(BASE + path, allow_redirects=False, timeout=30)
        except Exception as e:  # noqa: BLE001
            log(f"  {path:22} EXC {e}")
            continue
        loc = r.headers.get("location", "")
        note = ""
        if r.status_code >= 500:
            note = "  <<< SERVER ERROR"
        elif r.status_code in (302, 303):
            note = f"  -> {loc}"
        # Detect whether the returned HTML is an error page or a login redirect.
        body_flag = ""
        if r.status_code == 200:
            low = r.text.lower()
            if "internal server error" in low or "traceback" in low:
                body_flag = "  <<< ERROR IN BODY"
            title = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
            if title:
                body_flag += f"  [{title.group(1).strip()[:40]}]"
        log(f"  {path:22} {r.status_code}{note}{body_flag}")


def main() -> None:
    log("LITESPANEL LIVE TEST — " + BASE)

    # Health.
    try:
        h = requests.get(BASE + "/healthz", timeout=30).json()
        log(f"health: {h}")
    except Exception as e:  # noqa: BLE001
        log(f"health: EXC {e}")

    for label, (u, p) in [("ADMIN", ADMIN), ("USER (sostahaat)", USER)]:
        if not p:
            log(f"\n[{label}] no password given, skipping")
            continue
        s, r, ok = login(u, p)
        log(f"\n[{label}] login POST -> {r.status_code} "
            f"loc={r.headers.get('location','')} ok={ok}")
        if not ok:
            log(f"  login FAILED for {u}; body snippet: {r.text[:200]!r}")
            continue
        crawl(f"{label} route crawl", s)

    with open("live_test_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(OUT))
    print("done -> live_test_report.txt")


if __name__ == "__main__":
    main()
