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


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


templates.env.filters["human_size"] = human_size
