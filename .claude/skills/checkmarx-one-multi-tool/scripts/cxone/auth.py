"""
Authentication for Checkmarx One.

Uses an API key as an OAuth2 refresh token against the tenant's IAM realm,
caching the access token and refreshing shortly before expiry. This is the
same grant the CxOne CLI and plugins use (client_id `ast-app`).
"""

from __future__ import annotations

import time
import logging
import threading

import requests

from .config import CxConfig

logger = logging.getLogger("cxone.auth")


class AuthManager:
    TOKEN_REFRESH_BUFFER = 60  # refresh this many seconds before expiry

    def __init__(self, config: CxConfig):
        self.config = config
        self._token: str | None = None
        self._expires_at: float = 0.0
        # Scan/triage call token() from CXONE_WORKERS threads; without a lock,
        # every thread crossing the expiry boundary fires its own refresh.
        # Double-checked: fast path reads without the lock, refresh re-checks
        # inside it so only one thread actually hits the token endpoint.
        self._lock = threading.Lock()
        self._auth_url = (
            f"{config.resolved_iam_base_url}"
            f"/auth/realms/{config.tenant_name}"
            f"/protocol/openid-connect/token"
        )

    def _expired(self) -> bool:
        return time.time() >= self._expires_at - self.TOKEN_REFRESH_BUFFER

    def token(self) -> str:
        if self._expired():
            with self._lock:
                if self._expired():
                    self._authenticate()
        return self._token  # type: ignore[return-value]

    def _authenticate(self) -> None:
        logger.debug("Authenticating against %s", self._auth_url)
        resp = requests.post(
            self._auth_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token",
                "client_id": "ast-app",
                "refresh_token": self.config.api_key,
            },
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise ValueError("No access_token in authentication response")
        self._token = token
        self._expires_at = time.time() + int(body.get("expires_in", 600))
        logger.debug("Authenticated; token valid ~%ss", body.get("expires_in"))
