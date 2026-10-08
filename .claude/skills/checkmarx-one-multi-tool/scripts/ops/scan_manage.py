"""
Scan cancel / delete, selected by how the scan was started.

`scan cancel` and `scan delete` act on scans, not projects. Both are written
around two lessons from a real cleanup of a scan-replicator run:

1. **Who started a scan is not the `initiator` field.** A tool that submits scans
   with someone's API key shows up as THAT PERSON in `initiator`. The tool
   identifies itself in `userAgent` and `sourceOrigin` instead (the replicator
   reported `cxone-scan-replicator/1.0.0` / `cxone-scan-replicator`; this tool
   reports `cxone-multitool`). Selecting by initiator found nothing; selecting by
   origin found all 290. So the selector offers all three, and says which one
   matched.

2. **Unrecognised query parameters are silently ignored** (see ops/scan_query.py).
   Server-side filters are used to keep the sweep cheap, but every row is
   re-checked against the same predicate client-side, so a filter the server
   ignores can only make the sweep slower, never make the action wider.

Safety, in the order a caller meets it: an empty selector is refused (there is no
"every scan" default); the selected scans are listed before anything is touched;
`--dry-run` stops there; a selector-based action needs `--yes` or an interactive
confirmation (and refuses to run unattended without `--yes`); the first scan is
acted on alone and the run stops if it fails. `cancel` only touches Queued and
Running scans. `delete` never touches a Queued or Running scan: cancel it first.
"""

from __future__ import annotations

import logging
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("cxone.scanmanage")

ACTIVE = ("queued", "running")


def _parse_day(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(f"{value}T00:00:00+00:00")
    except ValueError:
        raise SystemExit(f"error: '{value}' is not a YYYY-MM-DD date")


def _created(scan: dict) -> datetime | None:
    text = str(scan.get("createdAt") or "").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class ScanSelector:
    """Which scans to act on. Empty = refused, never "all scans"."""

    scan_ids: list[str] = field(default_factory=list)
    project_names: list[str] = field(default_factory=list)
    project_ids: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    source_origins: list[str] = field(default_factory=list)   # sourceOrigin, exact
    user_agents: list[str] = field(default_factory=list)      # userAgent, substring
    initiators: list[str] = field(default_factory=list)       # initiator, substring
    branch: str | None = None
    created_after: str | None = None                          # YYYY-MM-DD, inclusive
    created_before: str | None = None                         # YYYY-MM-DD, exclusive

    @property
    def active(self) -> bool:
        return any([self.scan_ids, self.project_names, self.project_ids, self.statuses,
                    self.source_origins, self.user_agents, self.initiators, self.branch,
                    self.created_after, self.created_before])

    @property
    def explicit_ids_only(self) -> bool:
        """Named scans and nothing else: the caller has already read the list."""
        return bool(self.scan_ids) and not any([
            self.project_names, self.project_ids, self.statuses, self.source_origins,
            self.user_agents, self.initiators, self.branch, self.created_after,
            self.created_before])

    def describe(self) -> str:
        bits = []
        for label, vals in (("scan-id", self.scan_ids), ("project", self.project_names),
                            ("project-id", self.project_ids), ("status", self.statuses),
                            ("source-origin", self.source_origins),
                            ("user-agent", self.user_agents), ("initiator", self.initiators)):
            if vals:
                bits.append(f"{label}={','.join(vals)}")
        if self.branch:
            bits.append(f"branch={self.branch}")
        if self.created_after:
            bits.append(f"created>={self.created_after}")
        if self.created_before:
            bits.append(f"created<{self.created_before}")
        return "; ".join(bits)

    def matches(self, scan: dict) -> bool:
        """The authoritative check. Server-side filters only narrow the sweep."""
        if self.scan_ids and scan.get("id") not in set(self.scan_ids):
            return False
        if self.project_ids and scan.get("projectId") not in set(self.project_ids):
            return False
        if self.statuses and str(scan.get("status") or "").lower() \
                not in {s.lower() for s in self.statuses}:
            return False
        if self.source_origins and str(scan.get("sourceOrigin") or "").lower() \
                not in {o.lower() for o in self.source_origins}:
            return False
        if self.user_agents:
            ua = str(scan.get("userAgent") or "").lower()
            if not any(u.lower() in ua for u in self.user_agents):
                return False
        if self.initiators:
            who = str(scan.get("initiator") or "").lower()
            if not any(i.lower() in who for i in self.initiators):
                return False
        if self.branch and scan.get("branch") != self.branch:
            return False
        created = _created(scan)
        after, before = _parse_day(self.created_after), _parse_day(self.created_before)
        if after and (created is None or created < after):
            return False
        if before and (created is None or created >= before):
            return False
        return True


# ------------------------------------------------------------------ lookup
def _resolve_projects(api, selector: ScanSelector) -> list[str]:
    """Project ids from --project-names / --project-ids (exact name match)."""
    ids = list(selector.project_ids)
    if selector.project_names:
        known = {p.get("name"): p.get("id")
                 for p in api.paginate("projects", results_key="projects")}
        for name in selector.project_names:
            pid = known.get(name)
            if pid:
                ids.append(pid)
            else:
                logger.warning("Project not found: '%s'", name)
    return list(dict.fromkeys(ids))


def find_scans(api, selector: ScanSelector) -> list[dict]:
    """Every scan the selector matches, newest first."""
    rows: list[dict] = []
    if selector.scan_ids:
        for sid in selector.scan_ids:
            try:
                scan = api.get(f"scans/{sid}")
            except Exception as exc:                               # noqa: BLE001
                logger.warning("Could not read scan %s: %s", sid, exc)
                continue
            if isinstance(scan, dict) and scan.get("id"):
                rows.append(dict(scan))
    else:
        params: dict = {}
        if selector.statuses:
            params["statuses"] = ",".join(selector.statuses)
        if selector.source_origins:
            params["source-origins"] = ",".join(selector.source_origins)
        if selector.initiators and len(selector.initiators) == 1:
            params["initiators"] = selector.initiators[0]
        if selector.branch:
            params["branch"] = selector.branch
        if selector.created_after:
            params["from-date"] = selector.created_after
        if selector.created_before:
            params["to-date"] = selector.created_before
        if selector.project_names or selector.project_ids:
            targets = _resolve_projects(api, selector)
            if not targets:
                return []
            for pid in targets:       # `project-id`, never `projectId`: see scan_query.py
                rows += api.paginate("scans", results_key="scans",
                                     params={**params, "project-id": pid}, limit=200)
            # The server silently ignores a filter it doesn't recognise, which
            # would hand back other projects' scans. Re-check every row.
            allowed = set(targets)
            rows = [r for r in rows if r.get("projectId") in allowed]
        else:
            rows = api.paginate("scans", results_key="scans", params=params, limit=200)
    seen, out = set(), []
    for scan in rows:
        if scan.get("id") in seen or not selector.matches(scan):
            continue
        seen.add(scan["id"])
        out.append(scan)
    out.sort(key=lambda s: s.get("createdAt") or "", reverse=True)
    return out


def origin_index(api, origin: str) -> dict[str, tuple[int, int]]:
    """{project_id: (scans started by `origin`, all scans)} in one tenant sweep.

    Used by `project delete --scan-origin`. A scan counts as started by `origin`
    when its sourceOrigin equals it or its userAgent contains it.
    """
    want = origin.lower()
    mine: Counter = Counter()
    total: Counter = Counter()
    for scan in api.paginate("scans", results_key="scans", limit=200):
        pid = scan.get("projectId")
        if not pid:
            continue
        total[pid] += 1
        if str(scan.get("sourceOrigin") or "").lower() == want \
                or want in str(scan.get("userAgent") or "").lower():
            mine[pid] += 1
    return {pid: (mine[pid], total[pid]) for pid in mine}


# ------------------------------------------------------------------ actions
def _cancel_one(api, scan: dict) -> tuple[str, bool, str]:
    try:
        api.patch(f"scans/{scan['id']}", json_body={"status": "Canceled"})
        return scan["id"], True, ""
    except Exception as exc:                                       # noqa: BLE001
        return scan["id"], False, str(exc)


def _delete_one(api, scan: dict) -> tuple[str, bool, str]:
    try:
        api.delete(f"scans/{scan['id']}")
        return scan["id"], True, ""
    except Exception as exc:                                       # noqa: BLE001
        return scan["id"], False, str(exc)


def _print_selection(verb: str, eligible: list[dict], skipped: list[dict], reason: str) -> None:
    by_project = Counter((s.get("projectName") or s.get("projectId") or "?",
                          s.get("status") or "?") for s in eligible)
    print(f"{len(eligible)} scan(s) selected to {verb}:")
    for (proj, status), n in sorted(by_project.items(), key=lambda kv: (-kv[1], kv[0]))[:30]:
        print(f"  {n:>5}  {status:<10} {proj}")
    if len(by_project) > 30:
        print(f"  ... and {len(by_project) - 30} more project/status groups")
    if skipped:
        states = ", ".join(f"{n} {s}" for s, n in
                           Counter(str(x.get("status")) for x in skipped).most_common())
        print(f"{len(skipped)} matching scan(s) skipped ({reason}): {states}")
    sys.stdout.flush()


def run_manage(cfg, verb: str, selector: ScanSelector, *, yes: bool = False,
               workers: int | None = None) -> int:
    """`verb` is 'cancel' or 'delete'. Returns a process exit code."""
    from cxone import ApiClient

    if not selector.active:
        print("Nothing selected: pass at least one selector (--scan-id, --project-names, "
              "--status, --source-origin, --user-agent, --initiator, --branch, "
              "--created-after/--created-before). There is no \"all scans\" default.")
        return 2

    api = ApiClient(cfg)
    matched = find_scans(api, selector)
    if verb == "cancel":
        eligible = [s for s in matched if str(s.get("status") or "").lower() in ACTIVE]
        skipped = [s for s in matched if s not in eligible]
        reason = "only Queued/Running scans can be cancelled"
        act = _cancel_one
    else:
        eligible = [s for s in matched if str(s.get("status") or "").lower() not in ACTIVE]
        skipped = [s for s in matched if s not in eligible]
        reason = "still Queued/Running: cancel these first with `scan cancel`"
        act = _delete_one

    if not matched:
        print(f"No scans matched ({selector.describe()}).")
        return 0
    if not eligible:
        _print_selection(verb, [], skipped, reason)
        print(f"Nothing to {verb}.")
        return 0

    _print_selection(verb, eligible, skipped, reason)
    if cfg.dry_run:
        print(f"\n[dry-run] nothing was {'cancelled' if verb == 'cancel' else 'deleted'}.")
        return 0

    if not selector.explicit_ids_only and not yes:
        refusal = (f"\nRefusing a selector-based {verb} without confirmation. "
                   f"Re-run with --dry-run to review, then --yes to proceed.")
        if not sys.stdin.isatty():
            print(refusal)
            return 2
        what = "Permanently delete" if verb == "delete" else "Cancel"
        try:
            reply = input(f"\n{what} these {len(eligible)} scan(s)? [y/N] ").strip().lower()
        except EOFError:             # stdin looks like a terminal but has no input
            print(refusal)
            return 2
        if reply not in ("y", "yes"):
            print("Aborted.")
            return 1

    first = act(api, eligible[0])
    if not first[1]:
        logger.error("First %s failed, stopping: %s", verb, first[2])
        print(f"\nStopped: the first {verb} failed, so no other scan was touched.")
        return 1
    results = [first]
    rest = eligible[1:]
    if rest:
        n = max(1, min(workers or cfg.workers, 5))     # be gentle with a shared tenant
        with ThreadPoolExecutor(max_workers=n) as pool:
            results += list(pool.map(lambda s: act(api, s), rest))
    done = [r for r in results if r[1]]
    failed = [r for r in results if not r[1]]
    for sid, _, err in failed[:10]:
        logger.error("%s failed for %s: %s", verb, sid, err)
    past = "Cancelled" if verb == "cancel" else "Deleted"
    sys.stderr.flush()
    print(f"\n{past} {len(done)} of {len(eligible)} scan(s)." + (
        f" {len(failed)} failed." if failed else ""))
    if verb == "cancel":
        print("Cancellation is asynchronous: a running scan can take a moment to reach "
              "Canceled/Partial. Re-run with the same selector (or `scan status`) to confirm.")
    sys.stdout.flush()
    return 0 if not failed else 1
