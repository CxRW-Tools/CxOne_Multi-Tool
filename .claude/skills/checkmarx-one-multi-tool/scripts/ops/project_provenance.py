"""
Who created a project, and how confident we are in that answer.

There are two ways to answer "who created this project", and they are NOT the
same claim:

  * `audit`      — a real `projects.create` event names the actor. Authoritative.
  * `first-scan` — nobody's create event survives, so we attribute to whoever
                   ran the earliest scan. A PROXY: usually right, occasionally
                   not (someone else may have created it and a colleague scanned
                   it first).

Audit events are retained for 365 days, so any project older than that has no
create event at all and can only ever be attributed by proxy — this is a
permanent property of those projects, not a transient gap.

Every result therefore carries its `source`. A caller that renders "created by"
without also rendering where that came from is making a stronger claim than the
data supports, which is exactly how a proxy ends up pasted into a report as
fact. `Provenance.describe()` exists so the honest form is the easy one.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, timedelta

logger = logging.getLogger("cxone.provenance")

SOURCE_AUDIT = "audit"
SOURCE_FIRST_SCAN = "first-scan"
SOURCE_UNKNOWN = "unknown"

# Matches audit.py's retention constant; a project created before this window
# has no recoverable create event.
_LOOKBACK_DAYS = 364


@dataclass
class Provenance:
    """Who created a project, when, and how we know."""

    project_id: str
    creator: str | None = None          # display name, best effort
    created_at: str | None = None       # ISO8601 UTC
    source: str = SOURCE_UNKNOWN

    @property
    def is_proxy(self) -> bool:
        """True when `creator` is inferred rather than recorded."""
        return self.source == SOURCE_FIRST_SCAN

    def describe(self) -> str:
        """Creator with its confidence made visible."""
        if self.source == SOURCE_AUDIT:
            return self.creator or "unknown"
        if self.source == SOURCE_FIRST_SCAN:
            return f"{self.creator} (first scan)" if self.creator else "unknown"
        return "unknown"


class ProvenanceResolver:
    """Resolves creator attribution for many projects with one audit sweep.

    The audit trail is fetched ONCE and indexed by project id: asking per project
    would re-download the whole window for every project in the tenant.
    """

    def __init__(self, api, principals=None, lookback_days: int = _LOOKBACK_DAYS):
        self.api = api
        self.lookback_days = lookback_days
        self._creates: dict[str, dict] | None = None
        if principals is None:
            from ops.principal_resolve import PrincipalResolver
            principals = PrincipalResolver(api)
        self.principals = principals

    # ------------------------------------------------------------------ audit
    def _load_creates(self) -> dict[str, dict]:
        """`projects.create` events indexed by project id (earliest per id)."""
        if self._creates is not None:
            return self._creates
        index: dict[str, dict] = {}
        try:
            from audit import AuditManager
            events = AuditManager(self.api).list_events(
                start=date.today() - timedelta(days=self.lookback_days),
                end=date.today(),
                event_type="projects.create")
        except Exception as exc:                                   # noqa: BLE001
            logger.debug("audit sweep for provenance failed: %s", exc)
            events = []
        for e in events:
            data = e.get("data") or {}
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:                                  # noqa: BLE001
                    continue
            pid = data.get("projectId")
            if not pid:
                continue
            prev = index.get(pid)
            if prev is None or (e.get("eventDate") or "") < (prev.get("eventDate") or ""):
                index[pid] = e
        self._creates = index
        return index

    # ------------------------------------------------------------------ solve
    def resolve(self, project_id: str, *, allow_first_scan: bool = True) -> Provenance:
        """Attribution for one project, preferring the audit record.

        `allow_first_scan=False` returns UNKNOWN rather than a proxy — for
        callers that must not present an inference as a fact.
        """
        event = self._load_creates().get(project_id)
        if event:
            actor = event.get("actionUserId") or ""
            name = (self.principals.full_name(actor, fallback=actor)
                    if actor else None)
            return Provenance(project_id=project_id, creator=name,
                              created_at=event.get("eventDate"),
                              source=SOURCE_AUDIT)
        if not allow_first_scan:
            return Provenance(project_id=project_id, source=SOURCE_UNKNOWN)

        from ops.scan_query import first_scan
        try:
            scan = first_scan(self.api, project_id)
        except Exception as exc:                                   # noqa: BLE001
            logger.debug("first-scan lookup failed for %s: %s", project_id, exc)
            scan = None
        if not scan:
            return Provenance(project_id=project_id, source=SOURCE_UNKNOWN)
        initiator = scan.get("initiator") or ""
        return Provenance(
            project_id=project_id,
            creator=self.principals.by_username(initiator) if initiator else None,
            created_at=scan.get("createdAt"),
            source=SOURCE_FIRST_SCAN)
