"""
Project-scoped scan queries.

Two traps live in `GET /api/scans`, and both produce a confidently wrong number
rather than an error:

1. **The filter parameter is `project-id`, not `projectId`.** An unrecognized
   parameter is IGNORED, not rejected, so `projectId=...` returns *other
   projects' scans* — the caller gets a full, plausible, wrong answer.

2. **`totalCount` is NOT filtered.** With `project-id` applied, the rows come
   back correctly scoped but `totalCount` still reports the tenant-wide total.
   Three unrelated projects each reporting "582" is what exposed it; a single
   project would just have looked like a busy project.

So: never read `totalCount` from a filtered scan query, and never spell the
parameter any other way. These helpers are the supported path.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("cxone.scanquery")

# The ONLY correct spelling of the project filter. See module docstring.
_PROJECT_PARAM = "project-id"


def scans_for_project(api, project_id: str, *, statuses: str | None = None,
                      limit: int = 200) -> list[dict]:
    """Every scan for one project, newest-first, correctly filtered.

    Uses `paginate`, which stops on a short page rather than trusting
    `totalCount` — the field that lies under a filter.
    """
    params = {_PROJECT_PARAM: project_id}
    if statuses:
        params["statuses"] = statuses
    rows = api.paginate("scans", results_key="scans", params=params, limit=limit)
    return [r for r in rows if not r.get("projectId") or r.get("projectId") == project_id]


def scan_count(api, project_id: str, **kw) -> int:
    """Number of scans for a project, derived from ROWS.

    Deliberately not a `totalCount` read: see the module docstring.
    """
    return len(scans_for_project(api, project_id, **kw))


def first_scan(api, project_id: str, **kw) -> dict | None:
    """Oldest scan for a project, or None."""
    rows = scans_for_project(api, project_id, **kw)
    return min(rows, key=lambda s: s.get("createdAt") or "", default=None) or None


def last_scan(api, project_id: str, **kw) -> dict | None:
    """Newest scan for a project, or None."""
    rows = scans_for_project(api, project_id, **kw)
    return max(rows, key=lambda s: s.get("createdAt") or "", default=None) or None


def bounds(api, project_id: str, **kw) -> tuple[dict | None, dict | None, int]:
    """(first, last, count) in ONE fetch.

    Callers usually want all three; asking separately would triple the API
    traffic for a tenant-wide inventory sweep.
    """
    rows = scans_for_project(api, project_id, **kw)
    if not rows:
        return (None, None, 0)
    ordered = sorted(rows, key=lambda s: s.get("createdAt") or "")
    return (ordered[0], ordered[-1], len(ordered))
