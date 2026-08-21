"""Pure Sieve-script compiler for LitesPanel email filters.

This module has **no I/O and no root** — it turns a mailbox's filter rules (and
an optional autoresponder "vacation" block) into a single Sieve script string.
That makes it fully unit-testable on any platform (the demo provider writes the
output to a file; the linux provider writes it to `~/.dovecot.sieve`), and keeps
the one tricky, correctness-critical surface — Sieve string quoting and the
`:matches` wildcard escaping — in one place.

The panel owns each mailbox's active script, so both the Email Filters router and
the Autoresponders router funnel through `compile_sieve` (a mailbox can have both
filter rules *and* a vacation reply, and they must live in the same script).

Rule payload shape (one dict per named filter)::

    {"match": "all" | "any",
     "conditions": [{"field": ..., "op": ..., "value": ..., "header": ...}],
     "actions":    [{"type": ..., "value": ...}]}

Vacation payload shape (from an Autoresponder row)::

    {"enabled": bool, "subject": str, "body": str, "days": int (optional)}
"""
from __future__ import annotations

# Condition "field" -> the mail header it tests. "Any Header" and "Body" are
# handled specially in _condition().
_FIELD_HEADER = {
    "From": "From",
    "To": "To",
    "Cc": "Cc",
    "Subject": "Subject",
}


def sieve_quote(s: str) -> str:
    """Encode a Python string as a Sieve quoted-string *source* literal.

    Within a Sieve quoted string a backslash escapes the following character, so
    a literal backslash is ``\\\\`` and a literal quote is ``\\"``. Newlines can't
    appear in a quoted string at all, so we flatten them to spaces (multi-line
    text uses the ``text:`` form via _multiline_text, not this).
    """
    s = (s or "").replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + s + '"'


def _escape_wildcards(s: str) -> str:
    """Escape the ``:matches`` pattern metacharacters (``\\`` ``*`` ``?``) so the
    given text matches *literally*.

    Operates in the *decoded* match-pattern space; `sieve_quote` re-encodes the
    result into a source literal afterwards (so a literal ``*`` ends up as the
    two source characters ``\\*`` inside the quotes, which Dovecot decodes back to
    the escaped-star pattern token).
    """
    return s.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _multiline_text(s: str) -> str:
    """Body text for a Sieve ``text:`` multi-line literal, dot-stuffed.

    A line consisting solely of ``.`` terminates the literal, so any body line
    that begins with ``.`` gets an extra leading ``.`` (identical to SMTP
    dot-stuffing). The caller adds the terminating ``.`` line.
    """
    lines = (s or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(("." + ln) if ln.startswith(".") else ln for ln in lines)


def _match_type(op: str, value: str) -> tuple[str, str]:
    """Map an operator to a Sieve match-type + the (decoded) comparison value."""
    if op == "is":
        return ":is", value
    if op == "matches":
        return ":matches", value           # user supplies a raw wildcard pattern
    if op == "begins_with":
        return ":matches", _escape_wildcards(value) + "*"
    if op == "ends_with":
        return ":matches", "*" + _escape_wildcards(value)
    return ":contains", value              # "contains", "not_contains", default


def _condition(cond: dict, require: set) -> str | None:
    """Compile one condition dict to a Sieve test, or None if it's unusable."""
    field = (cond.get("field") or "").strip()
    op = (cond.get("op") or "contains").strip()
    value = cond.get("value") or ""

    if field == "Body":
        require.add("body")
        mt, val = _match_type(op, value)
        return f"body :text {mt} {sieve_quote(val)}"

    header = (_FIELD_HEADER.get(field) or cond.get("header") or "").strip()
    if not header:
        return None
    if op == "exists":
        return f"exists {sieve_quote(header)}"

    mt, val = _match_type(op, value)
    test = f"header {mt} {sieve_quote(header)} {sieve_quote(val)}"
    if op == "not_contains":
        return f"not {test}"
    return test


def _action(action: dict, require: set) -> str | None:
    """Compile one action dict to a Sieve command, or None if it's unusable."""
    kind = (action.get("type") or "").strip()
    value = (action.get("value") or "").strip()

    if kind == "fileinto":
        if not value:
            return None
        require.update(("fileinto", "mailbox"))
        return f"fileinto :create {sieve_quote(value)};"
    if kind == "redirect":
        if not value:
            return None
        return f"redirect {sieve_quote(value)};"
    if kind == "seen":
        require.add("imap4flags")
        return 'addflag "\\\\Seen";'       # source: addflag "\Seen";
    if kind in ("discard", "keep", "stop"):
        return f"{kind};"
    return None


def _compile_rule(rule: dict, require: set) -> list[str] | None:
    """Compile one named filter to Sieve lines, or None if nothing usable."""
    conditions = [t for t in (_condition(c, require) for c in rule.get("conditions", [])) if t]
    actions = [a for a in (_action(a, require) for a in rule.get("actions", [])) if a]
    if not conditions or not actions:
        return None

    if len(conditions) == 1:
        clause = conditions[0]
    else:
        joiner = "allof" if (rule.get("match") or "all") == "all" else "anyof"
        clause = f"{joiner} ({', '.join(conditions)})"

    lines: list[str] = []
    name = (rule.get("name") or "").replace("\r", " ").replace("\n", " ").strip()
    if name:
        lines.append(f"# {name[:80]}")
    lines.append(f"if {clause} {{")
    lines.extend(f"    {a}" for a in actions)
    lines.append("}")
    return lines


def _compile_vacation(vacation: dict, require: set) -> list[str]:
    """Compile an autoresponder vacation block to Sieve lines."""
    require.add("vacation")
    days = vacation.get("days", 1)
    try:
        days = max(1, int(days))
    except (TypeError, ValueError):
        days = 1
    return [
        f"vacation :days {days} :subject {sieve_quote(vacation.get('subject', ''))} text:",
        _multiline_text(vacation.get("body", "")),
        ".",
        ";",
    ]


def compile_sieve(rules: list[dict], vacation: dict | None = None) -> str:
    """Compile a mailbox's filter rules (+ optional vacation) to a Sieve script.

    Returns the empty string when there is nothing to emit (no usable rules and
    no enabled vacation) so callers can treat that as "remove the script".
    """
    require: set[str] = set()
    body: list[str] = []

    for rule in rules or []:
        compiled = _compile_rule(rule, require)
        if compiled:
            if body:
                body.append("")            # blank line between rules
            body.extend(compiled)

    if vacation and vacation.get("enabled", True):
        if body:
            body.append("")
        body.extend(_compile_vacation(vacation, require))

    if not body:
        return ""

    out = ["# Managed by LitesPanel - do not edit by hand."]
    if require:
        tokens = ", ".join(sieve_quote(x) for x in sorted(require))
        out.append(f"require [{tokens}];")
    out.append("")
    out.extend(body)
    return "\n".join(out) + "\n"
