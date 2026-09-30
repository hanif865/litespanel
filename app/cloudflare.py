"""Cloudflare DNS integration — mirror each account's zones into *their own*
Cloudflare account.

Per-client: every hosting account can save its own scoped Cloudflare API token
(cPanel-side "Cloudflare" page). When enabled, every DNS change that account
makes — subdomains and Zone Editor edits — is mirrored to that client's own
Cloudflare, so records go live automatically without touching DNS by hand. The
token lives in the `cloudflare_credentials` table, one row per owner, encrypted
at rest (app/crypto.py) and never re-displayed.

The push happens at the router layer (dns.py / subdomains.py) right after
`provider.sync_zone(...)`, because resolving the domain's owner and their token
needs the database — and the provider layer never touches the ORM.

Safety model — the panel only manages records it created:
  * Every record the panel creates on Cloudflare is tagged with a comment marker
    (`_MARKER`). Reconciliation only ever deletes records carrying that marker.
  * Records the client added directly in the Cloudflare dashboard have no marker,
    so they are never modified or removed. If a record identical to a panel
    record already exists (same type/name/content), it's left as-is (no dup).

Everything is best-effort: a Cloudflare outage, a wrong token, or a zone that
isn't on that account must never break the panel action that triggered the sync
— errors are swallowed and surfaced through the page's "Test connection" button.

Stdlib only (urllib) so the panel gains no new dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from sqlalchemy.orm import Session

from .crypto import decrypt, encrypt
from .models import CloudflareCredential, Domain

_API = "https://api.cloudflare.com/client/v4"
_MARKER = "litespanel"          # tags records this panel owns
_TIMEOUT = 12                   # seconds — keep panel actions snappy on CF hiccups
# DNS record types the panel manages. Anything else on the Cloudflare zone
# (SRV, CAA, ...) is out of scope and never touched.
_MANAGED_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}
# Cloudflare only proxies (orange-cloud) these types.
_PROXIABLE = {"A", "AAAA", "CNAME"}


# --------------------------------------------------------------------------
# Per-account credentials (DB-backed, token encrypted at rest)
# --------------------------------------------------------------------------
def get_cred(db: Session, owner_id: int) -> CloudflareCredential | None:
    return db.query(CloudflareCredential).filter_by(owner_id=owner_id).one_or_none()


def token_of(cred: CloudflareCredential | None) -> str | None:
    """The decrypted API token for an account, or None if unset/undecryptable."""
    return decrypt(cred.token_enc) if cred else None


def settings_for(db: Session, owner_id: int) -> dict:
    """Display-safe settings for the account's page — never exposes the token."""
    cred = get_cred(db, owner_id)
    return {
        "enabled": bool(cred.enabled) if cred else False,
        "proxied": bool(cred.proxied) if cred else False,
        "token_set": bool(token_of(cred)),
    }


def enabled_for(db: Session, owner_id: int) -> bool:
    """True when this account has auto-sync on AND a usable token stored."""
    cred = get_cred(db, owner_id)
    return bool(cred and cred.enabled and token_of(cred))


def save_cred(db: Session, owner_id: int, *, enabled: bool, token: str | None,
              proxied: bool) -> None:
    """Create/update an account's Cloudflare settings. A blank/None `token`
    keeps the existing one (so re-saving other fields doesn't wipe it)."""
    cred = get_cred(db, owner_id)
    if cred is None:
        cred = CloudflareCredential(owner_id=owner_id)
        db.add(cred)
    cred.enabled = bool(enabled)
    cred.proxied = bool(proxied)
    token = (token or "").strip()
    if token:
        cred.token_enc = encrypt(token)
    db.commit()


def clear_cred(db: Session, owner_id: int) -> None:
    """Remove an account's token and switch auto-sync off."""
    cred = get_cred(db, owner_id)
    if cred is not None:
        db.delete(cred)
        db.commit()


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


def verify(token: str | None) -> tuple[bool, str]:
    """Validate an API token (the 'Test connection' button)."""
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


def _desired(domain: str, records: list[dict], proxied_default: bool) -> dict[tuple, dict]:
    """Panel records → {key: cf_create_body}, managed types only."""
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
# Core reconcile (parametrized by token/proxied)
# --------------------------------------------------------------------------
def push_zone(token: str, proxied: bool, domain: str,
              records: list[dict]) -> tuple[bool, str]:
    """Mirror `records` into the domain's Cloudflare zone (best-effort).

    Returns (ok, message). Low-level: callers pass the account's token/proxied
    flag. Prefer `publish()` from routers, which resolves those from the DB.
    """
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

    desired = _desired(domain, records, proxied)
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


# --------------------------------------------------------------------------
# Router-facing entry points (resolve the owner's token from the DB)
# --------------------------------------------------------------------------
def verify_owner(db: Session, owner_id: int) -> tuple[bool, str]:
    """Validate the account's saved token."""
    return verify(token_of(get_cred(db, owner_id)))


def publish(db: Session, domain: Domain, records: list[dict]) -> tuple[bool, str]:
    """Mirror a domain's records to its owner's Cloudflare (best-effort).

    Called from dns.py / subdomains.py right after provider.sync_zone(). No-op
    (returns ok=False) when that account hasn't enabled Cloudflare. Never
    raises — a CF problem must not break the DNS operation that triggered it.
    """
    try:
        cred = get_cred(db, domain.owner_id)
        if not (cred and cred.enabled):
            return False, "Cloudflare not enabled for this account."
        token = token_of(cred)
        if not token:
            return False, "No API token saved."
        return push_zone(token, bool(cred.proxied), domain.name, records)
    except Exception as e:  # noqa: BLE001 — defensive: never break the caller
        return False, f"{getattr(domain, 'name', '?')}: {e}"


def sync_all_for(db: Session, owner_id: int) -> tuple[int, int, list[str]]:
    """Push every domain owned by this account to their Cloudflare.

    Returns (ok_count, fail_count, notes). Used by the page's 'Sync now' button.
    """
    cred = get_cred(db, owner_id)
    token = token_of(cred)
    if not (cred and cred.enabled and token):
        return 0, 0, ["Cloudflare not enabled."]
    ok_n = fail_n = 0
    notes: list[str] = []
    domains = db.query(Domain).filter_by(owner_id=owner_id).order_by(Domain.name).all()
    for d in domains:
        payload = [
            {"type": r.rtype, "name": r.name, "value": r.value,
             "ttl": r.ttl, "priority": r.priority}
            for r in d.dns_records
        ]
        ok, msg = push_zone(token, bool(cred.proxied), d.name, payload)
        if ok:
            ok_n += 1
        else:
            fail_n += 1
            notes.append(msg)
    return ok_n, fail_n, notes
