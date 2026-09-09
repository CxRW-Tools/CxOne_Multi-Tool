"""
Project inventory — selection and enrichment for tenant hygiene.

Answers the question class "what is in this tenant that shouldn't be?":
scratch projects to clean up, projects nobody has scanned in a month, projects
created and abandoned, everything one person made before they left.

That was previously a multi-step investigation across three unrelated
endpoints — project tags, the audit trail, and the scans list — with a
different trap in each. This module is that join, done once and correctly.

Read-only. Selection here feeds `project delete`, so the two share one selector
vocabulary: whatever `inventory` lists is exactly what `delete` would remove.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("cxone.inventory")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_days(value: str | None) -> int | None:
    dt = _parse_iso(value)
    return None if dt is None else (_now() - dt).days


@dataclass
class Selector:
    """Which projects to act on. Empty selector = every project.

    Exclusions win over inclusions, matching the agent's project-scope rules, so
    a mistake fails safe: too few projects, never too many. That polarity
    matters more here than there, because this selector can feed a delete.
    """

    tags: list[str] = field(default_factory=list)        # "tmp" or "Demo:T&R"
    names: list[str] = field(default_factory=list)       # substring or glob
    exclude_names: list[str] = field(default_factory=list)
    owner: str | None = None                             # username/email substring
    stale_days: int | None = None                        # no scan in N days
    no_scans: bool = False                               # never scanned
    created_before: str | None = None                    # YYYY-MM-DD

    @property
    def active(self) -> bool:
        return any([self.tags, self.names, self.exclude_names, self.owner,
                    self.stale_days is not None, self.no_scans,
                    self.created_before])

    def describe(self) -> str:
        """The active filters, for an empty-result message. "Nothing matched" and
        "nothing exists" are different conclusions; naming the filter separates
        them without a second query."""
        bits = []
        if self.tags:
            bits.append(f"tag={','.join(self.tags)}")
        if self.names:
            bits.append(f"name={','.join(self.names)}")
        if self.exclude_names:
            bits.append(f"not-name={','.join(self.exclude_names)}")
        if self.owner:
            bits.append(f"owner={self.owner}")
        if self.stale_days is not None:
            bits.append(f"stale>={self.stale_days}d")
        if self.no_scans:
            bits.append("never-scanned")
        if self.created_before:
            bits.append(f"created<{self.created_before}")
        return "; ".join(bits)

    # ------------------------------------------------------------- predicates
    @staticmethod
    def _name_matches(name: str, pattern: str) -> bool:
        """Glob when the pattern looks like one, else case-insensitive substring."""
        name_l, pat_l = (name or "").lower(), (pattern or "").lower()
        if any(ch in pat_l for ch in "*?["):
            return fnmatch.fnmatch(name_l, pat_l)
        return pat_l in name_l

    @staticmethod
    def _tag_matches(tags: dict, spec: str) -> bool:
        """"key" matches the key at any value; "key:value" requires both."""
        if not isinstance(tags, dict):
            return False
        lowered = {str(k).lower(): str(v or "") for k, v in tags.items()}
        if ":" in spec:
            key, _, want = spec.partition(":")
            return lowered.get(key.strip().lower(), None) == want.strip()
        return spec.strip().lower() in lowered

    def matches_project(self, project: dict) -> bool:
        """Tag/name filters — everything decidable without extra API calls."""
        name = project.get("name") or ""
        for pattern in self.exclude_names:
            if self._name_matches(name, pattern):
                return False
        if self.names and not any(self._name_matches(name, p) for p in self.names):
            return False
        if self.tags:
            tags = project.get("tags") or {}
            if not any(self._tag_matches(tags, t) for t in self.tags):
                return False
        return True

    def matches_row(self, row: "InventoryRow") -> bool:
        """Filters that need enrichment (scan history, creator)."""
        if self.no_scans and row.scan_count:
            return False
        if self.stale_days is not None:
            if row.last_scan_at is None:
                pass  # never scanned is maximally stale — keep it
            else:
                age = _age_days(row.last_scan_at)
                if age is None or age < self.stale_days:
                    return False
        if self.owner:
            owner_l = self.owner.strip().lower()
            hay = " ".join(filter(None, [row.creator or "", row.creator_login or ""])).lower()
            if owner_l not in hay:
                return False
        if self.created_before:
            created = _parse_iso(row.created_at)
            cutoff = _parse_iso(self.created_before + "T00:00:00+00:00")
            if created is None or cutoff is None or created >= cutoff:
                return False
        return True


@dataclass
class InventoryRow:
    project_id: str
    name: str
    tags: dict = field(default_factory=dict)
    creator: str | None = None
    creator_login: str | None = None
    creator_source: str = "unknown"
    created_at: str | None = None
    first_scan_at: str | None = None
    last_scan_at: str | None = None
    scan_count: int = 0

    @property
    def stale_days(self) -> int | None:
        return _age_days(self.last_scan_at)

    def tag_str(self) -> str:
        if not self.tags:
            return ""
        return ",".join(f"{k}:{v}" if v else k for k, v in sorted(self.tags.items()))

    def creator_str(self) -> str:
        """Creator with provenance visible — a proxy is never shown as a fact."""
        if not self.creator:
            return "unknown"
        return (f"{self.creator} (first scan)"
                if self.creator_source == "first-scan" else self.creator)

    def as_dict(self) -> dict:
        return {
            "projectId": self.project_id,
            "name": self.name,
            "tags": self.tags,
            "creator": self.creator,
            "creatorLogin": self.creator_login,
            "creatorSource": self.creator_source,
            "createdAt": self.created_at,
            "firstScanAt": self.first_scan_at,
            "lastScanAt": self.last_scan_at,
            "scanCount": self.scan_count,
            "staleDays": self.stale_days,
        }


CSV_COLUMNS = ["projectId", "name", "tags", "creator", "creatorSource",
               "createdAt", "lastScanAt", "scanCount", "staleDays"]


class InventoryBuilder:
    """Builds enriched rows, doing the expensive work only when asked.

    Enrichment costs one scans call per project plus one tenant-wide audit
    sweep, so a plain `project list` stays as cheap as it always was and only
    pays when a column or filter actually needs the data.
    """

    def __init__(self, api, projects: list[dict] | None = None):
        self.api = api
        self._projects = projects
        self._provenance = None

    def projects(self) -> list[dict]:
        if self._projects is None:
            resp = self.api.get("projects", params={"limit": 200})
            data = resp.data if hasattr(resp, "data") else resp
            self._projects = (data or {}).get("projects") or []
        return self._projects

    def _prov(self):
        if self._provenance is None:
            from ops.project_provenance import ProvenanceResolver
            self._provenance = ProvenanceResolver(self.api)
        return self._provenance

    def build(self, selector: Selector | None = None, *,
              enrich_scans: bool = True, enrich_creator: bool = True,
              progress=None) -> list[InventoryRow]:
        selector = selector or Selector()
        candidates = [p for p in self.projects() if selector.matches_project(p)]
        rows: list[InventoryRow] = []
        for i, p in enumerate(candidates, 1):
            pid = p.get("id")
            row = InventoryRow(project_id=pid, name=p.get("name") or "",
                               tags=dict(p.get("tags") or {}))
            if enrich_scans:
                from ops.scan_query import bounds
                try:
                    first, last, count = bounds(self.api, pid)
                except Exception as exc:                           # noqa: BLE001
                    logger.debug("scan bounds failed for %s: %s", pid, exc)
                    first = last = None
                    count = 0
                row.first_scan_at = (first or {}).get("createdAt")
                row.last_scan_at = (last or {}).get("createdAt")
                row.scan_count = count
                if first:
                    row.creator_login = first.get("initiator")
            if enrich_creator:
                prov = self._prov().resolve(pid)
                row.creator = prov.creator
                row.creator_source = prov.source
                row.created_at = prov.created_at
            if progress:
                progress(i, len(candidates), row)
            rows.append(row)
        return [r for r in rows if selector.matches_row(r)]


# ------------------------------------------------------------------ rendering

def render_table(rows: list[InventoryRow], columns: list[str], stream=None) -> None:
    stream = stream or sys.stdout
    headers = {"id": "PROJECT ID", "name": "NAME", "tags": "TAGS",
               "creator": "CREATED BY", "created": "CREATED",
               "last-scan": "LAST SCAN", "scans": "SCANS", "stale": "STALE"}

    def cell(row: InventoryRow, col: str) -> str:
        if col == "id":
            return row.project_id or ""
        if col == "name":
            return row.name
        if col == "tags":
            return row.tag_str()
        if col == "creator":
            return row.creator_str()
        if col == "created":
            return (row.created_at or "")[:19].replace("T", " ")
        if col == "last-scan":
            return (row.last_scan_at or "-")[:19].replace("T", " ")
        if col == "scans":
            return str(row.scan_count)
        if col == "stale":
            d = row.stale_days
            return "never" if row.last_scan_at is None else f"{d}d"
        return ""

    table = [[headers.get(c, c.upper()) for c in columns]]
    table += [[cell(r, c) for c in columns] for r in rows]
    widths = [max(len(r[i]) for r in table) for i in range(len(columns))]
    for i, line in enumerate(table):
        print("  ".join(v.ljust(widths[j]) for j, v in enumerate(line)).rstrip(),
              file=stream)
        if i == 0:
            print("  ".join("-" * w for w in widths), file=stream)


def render_json(rows: list[InventoryRow], stream=None) -> None:
    json.dump([r.as_dict() for r in rows], stream or sys.stdout,
              indent=2, ensure_ascii=False)
    print(file=stream or sys.stdout)


def render_csv(rows: list[InventoryRow], path: str) -> int:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            d = r.as_dict()
            d["tags"] = r.tag_str()
            w.writerow({k: d.get(k) for k in CSV_COLUMNS})
    return len(rows)
