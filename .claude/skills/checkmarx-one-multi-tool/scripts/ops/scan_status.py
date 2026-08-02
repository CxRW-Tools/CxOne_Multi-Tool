"""
Scan status and history helpers (AST plane, read-only).

These complement the scan *trigger* path in ops/scans.py with on-demand checks:
  - status   : the latest scan per project, with per-engine breakdown
  - history  : the last N scans for a project (status, when, engines, finding delta)

Scans are fire-and-forget: once requested, the platform owns running them to
completion, so there is no client-side "wait until done" loop here — check status
whenever you want instead.

All read-only; no dry-run guard needed. Project names are resolved to ids via the
projects list. Finding deltas are computed from each scan's totalCount of results.
"""

from __future__ import annotations

import logging

from cxone import CxConfig, ApiClient
from ops.project_resolve import warn_unresolved_projects

logger = logging.getLogger("cxone.scanstatus")

ACTIVE = {"queued", "running"}


def _projects_by_name(api: ApiClient) -> dict[str, dict]:
    projects = api.paginate("projects", results_key="projects")
    return {p.get("name", ""): p for p in projects}


def _resolve_ids(api: ApiClient, names: list[str] | None) -> list[tuple[str, str]]:
    """Return [(name, id)] for the given names, or for ALL projects if names is empty."""
    index = _projects_by_name(api)
    if not names:
        return [(n, p.get("id")) for n, p in index.items() if p.get("id")]
    out: list[tuple[str, str]] = []
    lowered = {n.lower(): n for n, p in index.items()}
    found_names: set[str] = set()
    for name in names:
        match = index.get(name) or index.get(lowered.get(name.lower(), ""))
        if match and match.get("id"):
            out.append((match.get("name", name), match["id"]))
            found_names.add(name.lower())
    all_projects = list(index.values())
    warn_unresolved_projects(logger, names, all_projects, found_names)
    return out


def _latest_scan(api: ApiClient, project_id: str, limit: int = 1,
                 statuses: list[str] | None = None) -> list[dict]:
    params = {"project-id": project_id, "sort": "-created_at", "limit": limit}
    if statuses:
        params["statuses"] = statuses
    data = api.get("scans", params=params) or {}
    return data.get("scans") or []


def _finding_count(api: ApiClient, scan_id: str) -> int | None:
    """Total findings for a scan via the results endpoint's totalCount (cheap: limit=1)."""
    try:
        resp = api.get("results", params={"scan-id": scan_id, "limit": 1, "offset": 0}) or {}
        tc = resp.get("totalCount")
        return tc if isinstance(tc, int) else None
    except Exception:
        return None


def _engine_breakdown(scan: dict) -> str:
    """Compact per-engine status from statusDetails, e.g. 'sast:Completed sca:Running'."""
    parts = []
    for d in scan.get("statusDetails") or []:
        name = d.get("name")
        if name and name != "general":
            parts.append(f"{name}:{d.get('status', '?')}")
    return " ".join(parts)


# --------------------------------------------------------------------- status
def scan_status(cfg: CxConfig, project_names: list[str] | None = None) -> int:
    api = ApiClient(cfg)
    targets = _resolve_ids(api, project_names)
    if not targets:
        logger.warning("No matching projects.")
        return 1
    for name, pid in targets:
        scans = _latest_scan(api, pid, limit=1)
        if not scans:
            logger.info("%-28s no scans yet", name)
            continue
        s = scans[0]
        status = s.get("status", "?")
        created = (s.get("createdAt") or "")[:19]
        line = f"{name:<28} {status:<10} {created}  [{','.join(s.get('engines') or [])}]"
        logger.info(line)
        detail = _engine_breakdown(s)
        if detail and status.lower() in ACTIVE:
            logger.info("%-28s   %s", "", detail)
    return 0


# -------------------------------------------------------------------- history
def scan_history(cfg: CxConfig, project_name: str, limit: int = 10) -> int:
    api = ApiClient(cfg)
    targets = _resolve_ids(api, [project_name])
    if not targets:
        return 1
    name, pid = targets[0]
    scans = _latest_scan(api, pid, limit=limit)
    if not scans:
        logger.info("%s: no scans yet", name)
        return 0
    logger.info("Scan history for '%s' (most recent first):", name)
    # Oldest->newest counts let us show the finding delta scan-over-scan.
    prev_count: int | None = None
    rows = list(reversed(scans))  # oldest first to compute deltas forward
    counts: dict[str, int | None] = {}
    for s in rows:
        if (s.get("status") or "").lower() in ("completed", "partial"):
            counts[s["id"]] = _finding_count(api, s["id"])
        else:
            counts[s["id"]] = None
    for s in scans:  # display newest first
        sid = s.get("id", "?")
        status = s.get("status", "?")
        created = (s.get("createdAt") or "")[:19]
        count = counts.get(sid)
        count_str = str(count) if count is not None else "—"
        engines = ",".join(s.get("engines") or [])
        logger.info("  %s  %-10s %-19s findings=%-6s [%s]",
                    sid[:8], status, created, count_str, engines)
    # Delta between the two most recent completed scans
    completed = [s for s in scans if (s.get("status") or "").lower() in ("completed", "partial")]
    if len(completed) >= 2:
        newer, older = completed[0], completed[1]
        n, o = counts.get(newer["id"]), counts.get(older["id"])
        if n is not None and o is not None:
            delta = n - o
            sign = "+" if delta >= 0 else ""
            logger.info("  delta (latest vs previous completed): %s%d findings", sign, delta)
    return 0
