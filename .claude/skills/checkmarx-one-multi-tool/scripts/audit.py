"""
Audit trail — tenant activity history via GET /api/audit-events (AST plane).

Read-only: answers "who did what, when" (who created this project, when was a
user added to that group, who deleted an application). Useful mid-demo
("audit list --from 24h" shows everything provisioned/scanned/triaged this
session) and for scoped activity questions during a POV.

Coverage note: this endpoint is a work in progress on the platform side, not
a fixed catalog. Checkmarx began collecting these events on 2026-03-29 (no
events exist before that regardless of date range), and coverage keeps
growing engine by engine — as of this writing several engines (e.g. IaC) only
emit events for a subset of their actions. An empty or thin result for
something you know happened is a platform coverage gap, not a bug in this
module or proof the action didn't occur; say so rather than reporting
silence as a negative fact.

See references/cxone-api.md "Audit trail" for the endpoint's headers/params
and the live-validated event shape (the bundled OpenAPI spec's `auditEvent`
schema ref is unresolved — see that section for why the field list below is
sourced from a live-validated run instead).
"""

from __future__ import annotations

import re
import sys
import json
import logging
import argparse
from datetime import date, datetime, timedelta, timezone
from typing import Any

from cxone import CxConfig, ApiClient

logger = logging.getLogger("cxone.audit")

_ENDPOINT = "audit-events"
_AUDIT_HEADERS = {"Accept": "application/json; version=1.0"}
_MAX_LOOKBACK_DAYS = 365

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)

CSV_HEADER = [
    "eventID", "eventDate", "eventType", "auditResource",
    "actionType", "actionUserId", "ipAddress", "data",
]


def _is_uuid(value: Any) -> bool:
    return bool(value) and bool(_UUID_RE.match(str(value)))


def _rfc3339_utc_bounds(start: date, end: date) -> tuple[str, str]:
    start_dt = datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc)
    end_dt = datetime.combine(
        end, datetime.max.time().replace(microsecond=999999), tzinfo=timezone.utc
    )

    def to_z(dt: datetime) -> str:
        s = dt.isoformat()
        return s[:-6] + "Z" if s.endswith("+00:00") else s

    return to_z(start_dt), to_z(end_dt)


def parse_flex_date(text: str, *, today: date | None = None) -> date:
    """'30d' / '7d' / '24h' (relative, rounded up to a whole day) or an
    absolute YYYY-MM-DD."""
    today = today or date.today()
    t = (text or "").strip().lower()
    if t.endswith("d") and t[:-1].isdigit():
        return today - timedelta(days=int(t[:-1]))
    if t.endswith("h") and t[:-1].isdigit():
        hours = int(t[:-1])
        return today - timedelta(days=(hours + 23) // 24)
    try:
        return datetime.strptime(t, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"Unrecognized date '{text}' — use YYYY-MM-DD, '30d', or '24h'.")


class _UuidResolver:
    """Best-effort UUID -> human-readable name via IAM admin lookups. A miss
    (deleted principal, permission gap) falls back to the raw UUID rather than
    raising — resolution is a display nicety, not something an audit query
    should fail over."""

    def __init__(self, api: ApiClient):
        self.api = api
        self._cache: dict[str, str] = {}
        self._groups_by_id: dict[str, str] | None = None

    def _load_groups(self) -> dict[str, str]:
        if self._groups_by_id is None:
            try:
                groups = self.api.get("groups", use_iam=True) or []
            except Exception:
                groups = []
            self._groups_by_id = {g["id"]: g.get("name", g["id"]) for g in groups if g.get("id")}
        return self._groups_by_id

    def resolve(self, uid: str, kind: str) -> str:
        if uid in self._cache:
            return self._cache[uid]
        name = uid
        try:
            if kind in ("actionUserId", "userId"):
                data = self.api.get(f"users/{uid}", use_iam=True)
                if data:
                    full = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
                    username = data.get("username", uid)
                    name = f"{full} ({username})" if full else username
            elif kind in ("roleId", "assignedRoles", "unassignedRoles"):
                data = self.api.get(f"roles-by-id/{uid}", use_iam=True)
                if data:
                    name = data.get("name", uid)
            elif kind == "groupId":
                name = self._load_groups().get(uid, uid)
        except Exception as e:
            logger.debug("UUID resolution failed for %s (%s): %s", uid, kind, e)
        self._cache[uid] = name
        return name

    def resolve_in_place(self, obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in list(obj.items()):
                if isinstance(value, (dict, list)):
                    self.resolve_in_place(value)
                elif isinstance(value, str) and _is_uuid(value):
                    obj[key] = self.resolve(value, key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self.resolve_in_place(item)
                elif _is_uuid(item):
                    obj[i] = self.resolve(str(item), "roleId")


class AuditManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config

    def list_events(
        self,
        *,
        start: date,
        end: date,
        event_type: str | None = None,
        resource: str | None = None,
        user: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        human_readable: bool = False,
    ) -> list[dict]:
        today = date.today()
        if end > today:
            end = today
        earliest = today - timedelta(days=_MAX_LOOKBACK_DAYS)
        if start < earliest:
            raise ValueError(
                f"Audit events are only retained for the previous {_MAX_LOOKBACK_DAYS} days; "
                f"earliest allowed start date is {earliest.isoformat()}."
            )
        if start > end:
            raise ValueError("start date is after end date")

        start_s, end_s = _rfc3339_utc_bounds(start, end)
        events = self.api.paginate(
            _ENDPOINT,
            results_key="events",
            params={"startDate": start_s, "endDate": end_s},
            extra_headers=_AUDIT_HEADERS,
        )

        if user:
            uid = user if _is_uuid(user) else self._resolve_user_id(user)
            events = [e for e in events if e.get("actionUserId") == uid]
        if event_type:
            events = [e for e in events if (e.get("eventType") or "").lower() == event_type.lower()]
        if resource:
            events = [e for e in events if (e.get("auditResource") or "").lower() == resource.lower()]
        if search:
            needle = search.lower()
            events = [e for e in events if needle in json.dumps(e, default=str).lower()]

        events.sort(key=lambda e: e.get("eventDate") or "")
        if limit:
            events = events[-limit:]

        if human_readable:
            resolver = _UuidResolver(self.api)
            for ev in events:
                resolver.resolve_in_place(ev)

        return events

    def _resolve_user_id(self, username: str) -> str | None:
        """Best-effort username/email -> user id, via the same IAM users list
        every other module uses. Falls back to None (no match -> empty result)
        rather than raising, since a typo'd --user shouldn't crash the query."""
        try:
            matches = self.api.get(
                "users", params={"username": username, "exact": "true"}, use_iam=True
            ) or []
        except Exception:
            matches = []
        if not matches:
            logger.warning("No IAM user matched '%s'; --user filter will match nothing.", username)
            return None
        return matches[0].get("id")


def _summarize_data(data: dict | None, width: int = 80) -> str:
    if not data:
        return ""
    parts = []
    for k, v in data.items():
        if isinstance(v, list):
            v = ",".join(map(str, v))
        parts.append(f"{k}={v}")
    s = " ".join(parts)
    return s if len(s) <= width else s[: width - 1] + "…"


def print_table(events: list[dict]) -> None:
    if not events:
        print("No audit events matched.")
        return
    print(f"{'eventDate':<26} {'actor':<32} {'eventType':<24} {'resource':<16} {'action':<10} data")
    print("-" * 140)
    for e in events:
        print(
            f"{str(e.get('eventDate', '')):<26} "
            f"{str(e.get('actionUserId', '')):<32.32} "
            f"{str(e.get('eventType', '')):<24.24} "
            f"{str(e.get('auditResource', '')):<16.16} "
            f"{str(e.get('actionType', '')):<10.10} "
            f"{_summarize_data(e.get('data'))}"
        )
    print(f"\n{len(events)} event(s).")


def event_to_csv_row(event: dict) -> dict:
    data = event.get("data")
    return {
        "eventID": str(event.get("eventID") or ""),
        "eventDate": str(event.get("eventDate") or ""),
        "eventType": str(event.get("eventType") or ""),
        "auditResource": str(event.get("auditResource") or ""),
        "actionType": str(event.get("actionType") or ""),
        "actionUserId": str(event.get("actionUserId") or ""),
        "ipAddress": str(event.get("ipAddress") or ""),
        "data": json.dumps(data, ensure_ascii=False, default=str) if data is not None else "",
    }


def write_csv(path: str, events: list[dict]) -> int:
    import csv

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(event_to_csv_row(ev))
    return len(events)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="audit")
    p.add_argument("--env", default=None)
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    ls = sub.add_parser("list", help="list/search audit events for a date range")
    ls.add_argument("--from", dest="from_", default="30d",
                     help="start of range: YYYY-MM-DD, '30d', or '24h' (default: 30d)")
    ls.add_argument("--to", dest="to_", default=None,
                     help="end of range: YYYY-MM-DD (default: today)")
    ls.add_argument("--type", dest="event_type", default=None, help="filter by eventType")
    ls.add_argument("--resource", default=None, help="filter by auditResource")
    ls.add_argument("--user", default=None, help="filter by username/email or actionUserId")
    ls.add_argument("--search", default=None, help="keep events whose JSON contains this substring")
    ls.add_argument("--limit", type=int, default=None, help="keep only the most recent N events")
    ls.add_argument("--human-readable", action="store_true",
                     help="resolve user/group/role UUIDs via IAM admin lookups")
    ls.add_argument("--raw", action="store_true", help="print full event JSON instead of the table")
    ls.add_argument("--csv", dest="csv_path", default=None, help="also write a CSV to this path")

    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = CxConfig.from_env(args.env)
    mgr = AuditManager(ApiClient(cfg))

    if args.cmd == "list":
        try:
            start = parse_flex_date(args.from_)
            end = parse_flex_date(args.to_) if args.to_ else date.today()
        except ValueError as e:
            print(f"Error: {e}")
            return 2
        try:
            events = mgr.list_events(
                start=start, end=end,
                event_type=args.event_type, resource=args.resource,
                user=args.user, search=args.search, limit=args.limit,
                human_readable=args.human_readable,
            )
        except ValueError as e:
            print(f"Error: {e}")
            return 2

        if args.csv_path:
            n = write_csv(args.csv_path, events)
            print(f"CSV export: {n} rows written to {args.csv_path}")

        if args.raw:
            print(json.dumps(events, indent=2, ensure_ascii=False, default=str))
        else:
            print_table(events)

    return 0


if __name__ == "__main__":
    sys.exit(main())
