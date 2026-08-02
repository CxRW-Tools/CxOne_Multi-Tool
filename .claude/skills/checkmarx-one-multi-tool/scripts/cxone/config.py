"""
Configuration for the CxOne demo-builder library.

Load order (later overrides earlier): .env file -> environment variables.
Region base URLs derive the IAM host by swapping `ast.` -> `iam.`, matching
how Checkmarx One pairs its AST and IAM (Keycloak) hosts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # dotenv is optional at import time; required to read .env
    load_dotenv = None


# Marker stamped on every resource this tool creates (a tag on projects and
# applications, an attribute on Keycloak groups and users). It is what lets the
# scoped `purge` (the default) delete ONLY tool-created resources. Resources
# created by versions before 3.0.0 are unstamped and need `purge --all`.
TOOL_MARKER = "cxone-multitool"


# The skill's ROOT directory (this file is scripts/cxone/config.py, so root is
# three levels up). The launcher `run.py` lives at the root and is the documented
# invocation point, so a bare `.env` default resolves to <skill-root>/.env just as
# easily as scripts/.env — the guard must cover the WHOLE skill tree, not only
# scripts/. Every chat lands in "some skill dir", so a bare `.env` default
# silently resolves to a shared/ephemeral file and two sessions can collide.
# These helpers make resolution explicit and refuse to treat any location inside
# the skill folder as a credential store.
_SKILL_ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def default_env_file() -> str:
    """Resolve the env file to use when `--env` isn't passed explicitly.

    Order: the CXONE_ENV_FILE environment variable (an absolute, project-owned
    path set once per session) wins; otherwise fall back to `.env`. Anchoring on
    CXONE_ENV_FILE rather than cwd is what keeps two chats from colliding on the
    skill's shared temp `.env` — each names its own tenant file.
    """
    return os.getenv("CXONE_ENV_FILE") or ".env"


def is_inside_skill_dir(path: str) -> bool:
    """True if `path` resolves to anywhere inside the skill's own tree (root,
    scripts/, config/, ...).

    Used to refuse reading/writing credentials inside the skill folder (which may
    be an ephemeral copy, wiped between turns and shared across sessions). The
    anchor is the skill ROOT so <skill-root>/.env — the path a bare `.env`
    default hits when running `python run.py ...` from the root — is caught too.
    """
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return False
    return _SKILL_ROOT_DIR == resolved.parent or _SKILL_ROOT_DIR in resolved.parents


def swap_host_label(url: str, old_label: str, new_label: str) -> str | None:
    """Swap the first WHOLE hostname label equal to `old_label` (e.g.
    ast.checkmarx.net -> iam.checkmarx.net, deu.ast.checkmarx.net ->
    deu.iam.checkmarx.net). Returns None if no label matches exactly.

    This replaces naive `str.replace("ast.", "iam.")` surgery, which corrupts
    hosts that merely CONTAIN the substring (e.g. coast.checkmarx.net ->
    coiam.checkmarx.net). Matching is on complete dot-separated labels only —
    regional hosts put the plane label in the middle (deu.ast....), so any
    position matches, but partial labels never do. Scheme, port, and path are
    preserved.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url if "//" in url else f"//{url}", scheme="https")
    host = parts.hostname or ""
    labels = host.split(".")
    for i, lab in enumerate(labels):
        if lab.lower() == old_label.lower():
            labels[i] = new_label
            netloc = ".".join(labels)
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query,
                               parts.fragment))
    return None


@dataclass
class CxConfig:
    base_url: str
    tenant_name: str
    api_key: str
    iam_base_url: str | None = None
    github_token: str | None = None
    debug: bool = False
    dry_run: bool = False
    workers: int = 10
    # Where from_env loaded credentials from (absolute), or None if constructed
    # directly. The identities sidecar (cxone-identities.yaml) resolves relative
    # to this file's directory, keeping ALL credentials in one project-owned place.
    source_env_file: str | None = None

    @classmethod
    def from_env(cls, env_file: str | None = None) -> "CxConfig":
        # When the caller doesn't name a file, resolve via CXONE_ENV_FILE (project
        # -owned, absolute) before falling back to `.env`. This prevents a
        # forgotten `--env` from silently reading the skill's shared temp `.env`.
        if env_file is None:
            env_file = default_env_file()
        if load_dotenv is not None:
            path = Path(env_file)
            if path.is_file():
                # READ guard, symmetric with env init's WRITE guard: never consume
                # credentials from inside the skill's own directory. A stale .env
                # there is shared across chats/sessions — silently reading it is
                # exactly the cross-tenant collision this tool is designed to
                # prevent. Refuse loudly with remediation instead.
                if is_inside_skill_dir(str(path)):
                    raise ValueError(
                        f"Refusing to read credentials from inside the skill "
                        f"directory: {path.resolve()}\n"
                        "That location is shared across chats and may be stale — "
                        "using it risks silently operating on the wrong tenant.\n"
                        "Fix: point at your project's own file, e.g.\n"
                        "  set CXONE_ENV_FILE=<project-dir>/cxone.env   (or pass "
                        "--env <abs-path>)\n"
                        "then re-run `env init --api-key <KEY>` if that file "
                        "doesn't exist yet. Delete the stray file inside the "
                        "skill directory."
                    )
                load_dotenv(dotenv_path=str(path.resolve()), override=False)

        base_url = (os.getenv("CXONE_BASE_URL") or "").rstrip("/")
        tenant = os.getenv("CXONE_TENANT") or ""
        api_key = os.getenv("CXONE_API_KEY") or ""

        missing = [
            name
            for name, val in (
                ("CXONE_BASE_URL", base_url),
                ("CXONE_TENANT", tenant),
                ("CXONE_API_KEY", api_key),
            )
            if not val
        ]
        if missing:
            raise ValueError(
                f"Missing required config: {', '.join(missing)}\n"
                f"(looked for env file: {Path(env_file).resolve()})\n"
                "No tenant is configured. To set one up: set "
                "CXONE_ENV_FILE=<project-dir>/cxone.env, then run "
                "`env init --api-key <KEY>` — the tenant and base URL are "
                "derived from the key."
            )

        return cls(
            base_url=base_url,
            tenant_name=tenant,
            api_key=api_key,
            source_env_file=str(Path(env_file).resolve()) if env_file else None,
            iam_base_url=(os.getenv("CXONE_IAM_BASE_URL") or "").rstrip("/") or None,
            github_token=os.getenv("CXONE_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN"),
            debug=os.getenv("CXONE_DEBUG", "").lower() == "true",
            dry_run=os.getenv("CXONE_DRY_RUN", "").lower() == "true",
            workers=int(os.getenv("CXONE_WORKERS", "10") or "10"),
        )

    @property
    def resolved_iam_base_url(self) -> str:
        """IAM (Keycloak) host. Explicit override wins; else derive from base URL."""
        if self.iam_base_url:
            return self.iam_base_url
        swapped = swap_host_label(self.base_url, "ast", "iam")
        if swapped:
            return swapped
        # Single-tenant / custom hosts often share the host; caller can override.
        return self.base_url
