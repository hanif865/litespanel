"""Cloudflare DNS integration — mirror the panel's zones into Cloudflare.

The panel DB is the source of truth for DNS. When Cloudflare is enabled (an API
token is saved on the WHM → Cloudflare page), every DNS change funnels through
`provider.sync_zone(domain, records)`, which calls `push_zone()` here. That makes
subdomains and Zone Editor edits go live automatically — the cPanel experience,
without touching DNS by hand.

Safety model — the panel only manages records it created:
  * Every record the panel creates on Cloudflare is tagged with a comment marker
    (`_MARKER`). Reconciliation only ever deletes records carrying that marker.
  * Records you added directly in the Cloudflare dashboard have no marker, so
    they are never modified or removed. If a record identical to a panel record
    already exists (same type/name/content), it's left as-is (no duplicate).

Everything is best-effort: a Cloudflare outage, a wrong token, or a zone that
isn't on this Cloudflare account must never break the panel action that
triggered the sync — errors are swallowed and surfaced through the WHM page's
"Test connection" instead.

Stdlib only (urllib) so the panel gains no new dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import config
from .crypto import decrypt, encrypt

_API = "https://api.cloudflare.com/client/v4"
_MARKER = "litespanel"          # tags records this panel owns
_TIMEOUT = 12                   # seconds — keep panel actions snappy on CF hiccups
# DNS record types the panel manages. Anything else on the Cloudflare zone
# (SRV, CAA, ...) is out of scope and never touched.
_MANAGED_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}
# Cloudflare only proxies (orange-cloud) these types.
_PROXIABLE = {"A", "AAAA", "CNAME"}


# --------------------------------------------------------------------------
# Settings (persisted, token encrypted at rest)
# --------------------------------------------------------------------------
def _load() -> dict:
    try:
        data = json.loads(config.CLOUDFLARE_FILE.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _token() -> str | None:
    """The decrypted API token, or None if unset/undecryptable."""
    return decrypt(_load().get("token_enc"))


def settings() -> dict:
    """Display-safe settings for the WHM page — never exposes the token itself."""
    data = _load()
    return {
        "enabled": bool(data.get("enabled", False)),
        "proxied": bool(data.get("proxied", False)),
        "token_set": bool(_token()),
    }


def configured() -> bool:
    """True when the integration is switched on AND a usable token is stored."""
    data = _load()
    return bool(data.get("enabled", False)) and bool(_token())


def save(*, enabled: bool, token: str | None, proxied: bool) -> None:
    """Persist settings. A blank/None `token` keeps the existing one; pass the
    sentinel "" only via clear_token() to actually remove it."""
    data = _load()
    data["enabled"] = bool(enabled)
    data["proxied"] = bool(proxied)
    token = (token or "").strip()
    if token:
        data["token_enc"] = encrypt(token)
    config.CLOUDFLARE_FILE.write_text(json.dumps(data, indent=2))


def clear_token() -> None:
    data = _load()
    data.pop("token_enc", None)
    data["enabled"] = False
    config.CLOUDFLARE_FILE.write_text(json.dumps(data, indent=2))


# --------------------------------------------------------------------------
# Low-level API
# --------------------------------------------------------------------------
def _api(method: str, path: str, token: str, body: dict | None = None) -> dict:
    """One Cloudflare API call. Returns the parsed JSON envelope.

    Raises RuntimeError with a readable message on transport errors or when
    Cloudflare reports success=false, so callers can catch a single type.
    """
    url = f"{_API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # CF returns a JSON error envelope even on 4xx — surface its message.
        try:
            payload = json.loads(e.read().decode())
            msg = "; ".join(err.get("message", "") for err in payload.get("errors", []))
        except Exception:  # noqa: BLE001
            msg = f"HTTP {e.code}"
        raise RuntimeError(msg or f"HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"cannot reach Cloudflare: {e}") from e
    if not payload.get("success", False):
        msg = "; ".join(err.get("message", "") for err in payload.get("errors", []))
        raise RuntimeError(msg or "Cloudflare reported failure")
    return payload


def verify() -> tuple[bool, str]:
    """Validate the stored token (WHM 'Test connection' button)."""
    token = _token()
    if not token:
        return False, "No API token saved."
    try:
        _api("GET", "/user/tokens/verify", token)
    except RuntimeError as e:
        return False, str(e)
    # Also count how many zones the token can see, as a friendly sanity signal.
    try:
        zones = _api("GET", "/zones?per_page=50", token).get("result", [])
        return True, f"Token OK — {len(zones)} zone(s) visible on this account."
    except RuntimeError:
        return True, "Token OK."


def _zone_id(token: str, domain: str) -> str | None:
    res = _api("GET", f"/zones?name={domain}", token).get("result", [])
    return res[0]["id"] if res else None


def _list_records(token: str, zone_id: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        env = _api("GET", f"/zones/{zone_id}/dns_records?per_page=100&page={page}", token)
        out.extend(env.get("result", []))
        info = env.get("result_info") or {}
        if page >= int(info.get("total_pages", 1) or 1):
            break
        page += 1
    return out


# --------------------------------------------------------------------------
# Record normalization
# --------------------------------------------------------------------------
def _fqdn(name: str, domain: str) -> str:
    name = (name or "@").strip().rstrip(".").lower()
    if name in ("@", ""):
        return domain.lower()
    if name.endswith("." + domain.lower()) or name == domain.lower():
        return name
    return f"{name}.{domain.lower()}"


def _norm_content(rtype: str, value: str) -> str:
    v = (value or "").strip()
    if rtype in ("CNAME", "MX", "NS"):
        return v.rstrip(".").lower()
    if rtype == "TXT":
        # CF stores TXT unquoted; strip a single pair of surrounding quotes so
        # our value and CF's compare equal.
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        return v
    return v


def _key(rtype: str, fqdn: str, content: str) -> tuple[str, str, str]:
    return (rtype.upper(), fqdn, content)


def _desired(domain: str, records: list[dict]) -> dict[tuple, dict]:
    """Panel records → {key: cf_create_body}, managed types only."""
    proxied_default = bool(_load().get("proxied", False))
    out: dict[tuple, dict] = {}
    for r in records:
        rtype = str(r.get("type", "")).upper()
        if rtype not in _MANAGED_TYPES:
            continue
        fqdn = _fqdn(r.get("name", "@"), domain)
        content = _norm_content(rtype, r.get("value", ""))
        if not content:
            continue
        ttl = int(r.get("ttl") or 14400)
        # CF accepts 1 (auto) or 60..86400.
        if ttl != 1:
            ttl = max(60, min(ttl, 86400))
        body: dict[str, Any] = {
            "type": rtype, "name": fqdn, "content": content,
            "ttl": ttl, "comment": _MARKER,
        }
        if rtype == "MX":
            body["priority"] = int(r.get("priority") or 10)
        if rtype in _PROXIABLE and proxied_default:
            body["proxied"] = True
            body["ttl"] = 1  # proxied records must use automatic TTL
        out[_key(rtype, fqdn, content)] = body
    return out


# --------------------------------------------------------------------------
# The public entry point
# --------------------------------------------------------------------------
def push_zone(domain: str, records: list[dict]) -> tuple[bool, str]:
    """Mirror `records` into the domain's Cloudflare zone (best-effort).

    Returns (ok, message). Callers in the provider ignore the result — this is
    fire-and-forget — but the WHM 'Sync now' button surfaces it.
    """
    if not configured():
        return False, "Cloudflare integration is off."
    token = _token()
    if not token:
        return False, "No API token saved."

    try:
        zone_id = _zone_id(token, domain)
    except RuntimeError as e:
        return False, f"{domain}: {e}"
    if not zone_id:
        return False, f"{domain}: not a zone on this Cloudflare account (skipped)."

    try:
        existing = _list_records(token, zone_id)
    except RuntimeError as e:
        return False, f"{domain}: {e}"

    # Index existing records.
    existing_keys: dict[tuple, dict] = {}
    for e in existing:
        rtype = str(e.get("type", "")).upper()
        if rtype not in _MANAGED_TYPES:
            continue
        key = _key(rtype, str(e.get("name", "")).lower(),
                   _norm_content(rtype, e.get("content", "")))
        existing_keys[key] = e

    desired = _desired(domain, records)
    created = deleted = 0
    errors: list[str] = []

    # 1. Create records the panel wants that Cloudflare doesn't have yet.
    for key, body in desired.items():
        if key in existing_keys:
            continue  # already present (ours or the user's identical record)
        try:
            _api("POST", f"/zones/{zone_id}/dns_records", token, body)
            created += 1
        except RuntimeError as e:
            errors.append(f"{body['type']} {body['name']}: {e}")

    # 2. Delete panel-owned records that are no longer desired. Only records we
    #    tagged (_MARKER) are eligible, so user-made records are never removed.
    for key, rec in existing_keys.items():
        if key in desired:
            continue
        if (rec.get("comment") or "") != _MARKER:
            continue
        try:
            _api("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}", token)
            deleted += 1
        except RuntimeError as e:
            errors.append(f"delete {rec.get('type')} {rec.get('name')}: {e}")

    msg = f"{domain}: +{created} / -{deleted}"
    if errors:
        return False, msg + " — " + "; ".join(errors[:5])
    return True, msg
