"""Shared web helpers: the Jinja environment and small utilities."""
from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from . import config

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Make config available to every template (app name, provider badge, etc.).
templates.env.globals["APP_NAME"] = config.APP_NAME
templates.env.globals["PROVIDER"] = config.PROVIDER
templates.env.globals["WEBMAIL_URL"] = config.WEBMAIL_URL


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


templates.env.filters["human_size"] = human_size


# Map a leading emoji in a flash message to a severity level. The 200+ flash
# strings across the routers encode intent via this prefix; the template uses
# this filter to pick an icon + colour and to strip the emoji from the text.
_FLASH_EMOJI_LEVEL = {
    "✅": "success",  # ✅
    "\U0001F389": "success",  # 🎉
    "\U0001F513": "success",  # 🔓
    "▶️": "success",  # ▶️
    "▶": "success",  # ▶ (without variation selector)
    "\U0001F4E6": "success",  # 📦
    "\U0001F5D1️": "success",  # 🗑️
    "\U0001F5D1": "success",  # 🗑 (without variation selector)
    "❌": "error",  # ❌
    "\U0001F6AB": "error",  # 🚫
    "⛔": "error",  # ⛔
    "⚠️": "warning",  # ⚠️
    "⚠": "warning",  # ⚠ (without variation selector)
    "\U0001F512": "info",  # 🔒
    "ℹ️": "info",  # ℹ️
    "ℹ": "info",  # ℹ (without variation selector)
}


def flash_kind(message) -> tuple[str, str]:
    """Return (level, clean_text) for a flash message.

    Derives severity from a leading emoji prefix and strips it. Total: never
    raises, defaults to ("info", text) for anything unrecognised.
    """
    text = "" if message is None else str(message)
    for emoji, level in _FLASH_EMOJI_LEVEL.items():
        if text.startswith(emoji):
            return level, text[len(emoji):].strip()
    return "info", text.strip()


templates.env.filters["flash_kind"] = flash_kind
