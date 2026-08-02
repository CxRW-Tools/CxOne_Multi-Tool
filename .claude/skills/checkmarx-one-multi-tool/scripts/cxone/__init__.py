"""
Checkmarx One core library — configuration, auth, and the unified API client.

Every module in the Multi-Tool imports from here rather than reaching into the
submodules directly:

    from cxone import CxConfig, ApiClient, TOOL_MARKER

Also exposes the build/freshness helpers the CLI prints in `welcome`,
`version`, and `--help`.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path as _Path

from .config import (
    CxConfig,
    TOOL_MARKER,
    default_env_file,
    is_inside_skill_dir,
    swap_host_label,
)
from .auth import AuthManager
from .api_client import ApiClient, ApiResult, USER_AGENT

# How old the bundled reference spec may get before the CLI suggests a
# live-spec re-sync. The platform's API surface (enums, required fields) drifts
# between syncs; see spec/CLEANUP_NOTES.md ("spec/LAST_SYNCED") and
# references/api-index.md ("Where to look").
STALE_REFERENCE_DAYS = 90

# The skill ROOT (this file is scripts/cxone/__init__.py, so root is three
# levels up) — where VERSION and spec/LAST_SYNCED live.
_SKILL_ROOT = _Path(__file__).resolve().parent.parent.parent

_VERSION_FILE = _SKILL_ROOT / "VERSION"
_LAST_SYNCED_FILE = _SKILL_ROOT / "spec" / "LAST_SYNCED"

_UNKNOWN_VERSION = "0.0.0-unknown"


def _read_text(path: _Path) -> str | None:
    """Read a small single-line metadata file, or None if unreadable."""
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None


def get_version() -> str:
    """The installed skill version, from the root VERSION file.

    Printed by `welcome`, `version`/`--version`, and to stderr on every other
    command, so the running build is always identifiable. Falls back to a
    clearly-bogus sentinel rather than raising: an unreadable VERSION should
    never stop a tenant operation.
    """
    return _read_text(_VERSION_FILE) or _UNKNOWN_VERSION


def get_reference_freshness() -> tuple[str | None, int | None]:
    """When the bundled API reference was last synced against the live spec.

    Returns ``(date_str, days_ago)``:
      * ``(None, None)``      — spec/LAST_SYNCED is missing or unreadable.
      * ``(date_str, None)``  — present but not a parseable ISO date.
      * ``(date_str, N)``     — synced N days ago (never negative, so a
                                future-dated file reads as "0 days ago"
                                instead of a nonsensical warning).
    """
    raw = _read_text(_LAST_SYNCED_FILE)
    if not raw:
        return None, None
    try:
        synced = _dt.date.fromisoformat(raw)
    except ValueError:
        return raw, None
    return raw, max(0, (_dt.date.today() - synced).days)


__all__ = [
    "CxConfig",
    "AuthManager",
    "ApiClient",
    "ApiResult",
    "TOOL_MARKER",
    "USER_AGENT",
    "STALE_REFERENCE_DAYS",
    "default_env_file",
    "is_inside_skill_dir",
    "swap_host_label",
    "get_version",
    "get_reference_freshness",
]
