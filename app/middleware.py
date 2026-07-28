"""Security middleware — defensive HTTP headers and CSRF protection.

CSRF is handled with two layers that need no per-form token:
  1. The session cookie is SameSite=Lax (set in main.py), so a browser won't
     attach it to a cross-site POST — a forged request arrives unauthenticated.
  2. This middleware additionally rejects any state-changing request whose
     Origin/Referer header names a different site.
"""
from __future__ import annotations

from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach defensive response headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject unsafe-method requests coming from a different origin."""

    async def dispatch(self, request: Request, call_next):
        if request.method not in _SAFE_METHODS and not self._same_origin(request):
            return PlainTextResponse("CSRF check failed: cross-origin request.", status_code=403)
        return await call_next(request)

    @staticmethod
    def _same_origin(request: Request) -> bool:
        host = request.headers.get("host", "")
        # A cross-site form POST still carries an Origin header in modern
        # browsers; if present it must match. Fall back to Referer. If neither
        # is present we allow it and rely on the SameSite=Lax cookie.
        for header in ("origin", "referer"):
            value = request.headers.get(header)
            if value:
                return urlparse(value).netloc == host
        return True
