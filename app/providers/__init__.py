"""Provider layer: abstracts every OS-level operation behind one interface.

The rest of the app never calls nginx/certbot/mysql directly — it calls the
active provider. Swap PANEL_PROVIDER=demo (Windows dev) for =linux (VPS) and
the routers and UI stay identical.
"""
from __future__ import annotations

from functools import lru_cache

from .. import config
from .base import Provider


@lru_cache(maxsize=1)
def get_provider() -> Provider:
    if config.PROVIDER == "linux":
        from .linux import LinuxProvider

        return LinuxProvider()
    from .demo import DemoProvider

    return DemoProvider()
