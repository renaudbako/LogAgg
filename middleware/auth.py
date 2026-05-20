"""
Token-based authentication middleware.

If `auth_enabled = True` in config, every HTTP request must carry:
    Authorization: Bearer <token>

OR the token as a query parameter:
    ?token=<token>

WebSocket connections pass the token in the handshake query string.

The token is set in config.py:
    auth_token   = "change-me-to-a-strong-secret"
    auth_enabled = True

Endpoints exempt from auth (always accessible):
    GET /api/health
"""
import secrets
from functools import wraps
from typing import Optional

from flask import Request, jsonify, request


class AuthMiddleware:
    """
    Wraps a Flask app with bearer-token authentication.
    Attach with `auth.init_app(app)`.
    """

    EXEMPT_PATHS = {"/api/health"}

    def __init__(self, token: str, enabled: bool = True):
        self._token   = token
        self._enabled = enabled

    def init_app(self, app):
        if not self._enabled:
            return
        app.before_request(self._check)

    # ── Request hook ──────────────────────────────────────────

    def _check(self):
        if not self._enabled:
            return None

        path = request.path
        if path in self.EXEMPT_PATHS:
            return None

        # Allow Socket.IO handshake paths (they use query-param token)
        if path.startswith("/socket.io"):
            tok = request.args.get("token","")
            if secrets.compare_digest(tok, self._token):
                return None
            return jsonify({"error": "Unauthorized"}), 401

        # Standard Bearer token
        tok = self._extract_token(request)
        if tok and secrets.compare_digest(tok, self._token):
            return None

        return jsonify({"error": "Unauthorized — provide Bearer token"}), 401

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _extract_token(req: Request) -> Optional[str]:
        # Header: Authorization: Bearer <token>
        auth_header = req.headers.get("Authorization","")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Query param fallback: ?token=<token>
        return req.args.get("token")


def make_auth(config) -> AuthMiddleware:
    token   = getattr(config, "auth_token",   "")
    enabled = getattr(config, "auth_enabled", False) and bool(token)
    if enabled and (not token or token == "change-me"):
        import secrets as _s
        token = _s.token_hex(32)
        print(f"\n[Auth] Generated token: {token}\n"
              f"       Set auth_token in config.py to fix this.\n")
    return AuthMiddleware(token=token, enabled=enabled)
