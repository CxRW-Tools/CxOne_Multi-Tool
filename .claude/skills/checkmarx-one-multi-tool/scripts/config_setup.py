"""
Credential + .env helpers for the Checkmarx One Multi-Tool.

A Checkmarx One API key is an OAuth2 refresh token (a JWT). Its `iss` claim is the
Keycloak realm URL, e.g. https://iam.checkmarx.net/auth/realms/<tenant>, which
encodes BOTH the IAM host and the tenant. From that we derive the AST base URL
(iam.->ast.), so a user only has to paste their key; we extract the rest and
confirm it.

Policy: one .env holds exactly ONE tenant. Changing the tenant is an explicit,
forced action — this keeps a chat/project pinned to a single tenant so operations
can't get crossed between environments.

The JWT payload is decoded WITHOUT signature verification — purely to read claims
for convenience. The token is still validated server-side at auth time; we never
trust these claims for security.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

REQUIRED = ("CXONE_BASE_URL", "CXONE_TENANT", "CXONE_API_KEY")

# Known optional SCM token vars (provider alias -> env var).
SCM_TOKENS = {
    "github": "CXONE_GITHUB_TOKEN",
    "azure": "CXONE_AZURE_TOKEN", "ado": "CXONE_AZURE_TOKEN",
    "gitlab": "CXONE_GITLAB_TOKEN",
    "bitbucket": "CXONE_BITBUCKET_TOKEN",
}


# ----------------------------------------------------------------- JWT
def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_jwt_payload(token: str) -> dict:
    """Return the JWT payload claims (no signature verification)."""
    parts = (token or "").split(".")
    if len(parts) < 2:
        raise ValueError("API key is not a JWT (expected header.payload.signature)")
    try:
        return json.loads(_b64url_decode(parts[1]))
    except Exception as exc:
        raise ValueError(f"Could not decode API key payload: {exc}")


def derive_tenant_info(token: str) -> dict:
    """
    Extract {base_url, tenant_name, iam_base_url, claims} from the API key.
    base_url is derived from the IAM host (iam.->ast.); confirm/override if the
    deployment uses non-standard host naming.
    """
    claims = decode_jwt_payload(token)
    iss = claims.get("iss", "") or ""
    iam_base = tenant = None
    if "/auth/realms/" in iss:
        iam_base, _, realm = iss.partition("/auth/realms/")
        tenant = realm.split("/")[0]
    tenant = tenant or claims.get("tenant_name") or claims.get("tenant")
    base_url = None
    if iam_base:
        from cxone.config import swap_host_label
        base_url = swap_host_label(iam_base, "iam", "ast")  # None if host isn't iam.*
    return {"base_url": base_url, "tenant_name": tenant,
            "iam_base_url": iam_base, "claims": claims}


def mask_secret(val: str) -> str:
    if not val:
        return ""
    return f"{val[:6]}…{val[-4:]}" if len(val) > 12 else "****"


# ----------------------------------------------------------------- .env I/O
def read_env_file(path: str) -> dict:
    data: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return data
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        data[k.strip()] = v.strip()
    return data


def write_env_file(path: str, data: dict) -> None:
    lines = [
        "# Checkmarx One Multi-Tool — credentials for a SINGLE tenant.",
        "# Managed via `multitool.py env`. Keep out of version control.",
        "",
    ]
    order = ["CXONE_BASE_URL", "CXONE_TENANT", "CXONE_API_KEY", "CXONE_IAM_BASE_URL",
             "CXONE_GITHUB_TOKEN", "CXONE_AZURE_TOKEN", "CXONE_GITLAB_TOKEN",
             "CXONE_BITBUCKET_TOKEN", "CXONE_DEBUG", "CXONE_DRY_RUN", "CXONE_WORKERS"]
    for k in order:
        if data.get(k):
            lines.append(f"{k}={data[k]}")
    for k, v in data.items():
        if k not in order and v:
            lines.append(f"{k}={v}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def current_tenant(path: str) -> str | None:
    return read_env_file(path).get("CXONE_TENANT")


class TenantConflict(Exception):
    """Raised when an action would change the .env to a different tenant."""


def build_env(api_key: str, *, github_token: str | None = None,
              base_url: str | None = None, tenant: str | None = None,
              iam_base_url: str | None = None) -> dict:
    """Assemble a single-tenant env dict from the key (+ optional overrides)."""
    info = derive_tenant_info(api_key)
    data = {
        "CXONE_BASE_URL": base_url or info["base_url"] or "",
        "CXONE_TENANT": tenant or info["tenant_name"] or "",
        "CXONE_API_KEY": api_key,
    }
    if iam_base_url or info["iam_base_url"]:
        # Only persist IAM override if it isn't the plain iam.->derivable default.
        data["CXONE_IAM_BASE_URL"] = iam_base_url or ""
    if github_token:
        data["CXONE_GITHUB_TOKEN"] = github_token
    return {k: v for k, v in data.items() if v}


def init_env(path: str, api_key: str, *, github_token: str | None = None,
             base_url: str | None = None, tenant: str | None = None,
             force: bool = False) -> dict:
    """
    Write a single-tenant .env from the key. If a .env already exists for a
    DIFFERENT tenant, refuse unless force=True (single-tenant policy).
    Returns the written env dict.
    """
    new = build_env(api_key, github_token=github_token, base_url=base_url, tenant=tenant)
    existing_tenant = current_tenant(path)
    new_tenant = new.get("CXONE_TENANT")
    if existing_tenant and new_tenant and existing_tenant != new_tenant and not force:
        raise TenantConflict(
            f".env is already configured for tenant '{existing_tenant}'. "
            f"This key is for '{new_tenant}'. One chat/project should manage one "
            f"tenant — use a separate chat/project, or pass force to replace."
        )
    # Preserve existing optional tokens unless overridden.
    merged = read_env_file(path)
    if existing_tenant and new_tenant and existing_tenant != new_tenant:
        merged = {}  # replacing tenant: start clean
    merged.update(new)
    write_env_file(path, merged)
    return merged


def set_token(path: str, provider: str, value: str) -> str:
    """Set an SCM token (e.g. 'ado'/'azure'/'github'/'gitlab'/'bitbucket')."""
    var = SCM_TOKENS.get((provider or "").lower())
    if not var:
        raise ValueError(f"Unknown provider '{provider}'. Known: {sorted(set(SCM_TOKENS))}")
    data = read_env_file(path)
    data[var] = value
    write_env_file(path, data)
    return var


def set_var(path: str, key: str, value: str, force: bool = False) -> None:
    """Set an arbitrary CXONE_* var, guarding tenant/base-url changes."""
    key = key.upper()
    data = read_env_file(path)
    if key in ("CXONE_TENANT", "CXONE_BASE_URL") and data.get(key) and data[key] != value and not force:
        raise TenantConflict(
            f"{key} is already '{data[key]}'. Changing it switches tenants/host; "
            f"use force if that's intended (one chat/project = one tenant)."
        )
    data[key] = value
    write_env_file(path, data)
