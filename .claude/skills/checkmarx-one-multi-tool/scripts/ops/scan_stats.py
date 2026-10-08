"""
`scan stats`: one row of statistics per scan, for many scans, as CSV / JSONL /
JSON / a table. The bulk counterpart of `scan info` (one scan in depth).

It is deliberately lean so it scales to thousands of scans: every 50 scans cost
four batch calls (`scans` for the list, `sast-metadata`, `sast-metadata/
engine-version`, `scan-summary`), and the per-scan calls (`--languages` metrics,
and the incremental detail) run on a bounded thread pool. Rows are written as
each chunk completes, so memory is bounded by the chunk, not the run, and
`--resume` skips scans already present in the output file.

Two facts the numbers rely on, both verified live:

* **`sast_loc` is the codebase size even for an incremental scan.** A full scan
  of 13,423 LOC followed by an incremental that added one file reported 13,504
  (the new file's lines); a no-change incremental reports its base's LOC. Only
  `sast_scanned_loc` and the per-language figures are limited to re-analysed
  files. So no "sizing" column or look-back is needed, and the totals below
  sum the LATEST scan per project and branch to avoid counting a codebase twice.
* `scan-summary`'s `filesScannedCounter` is "NOT IN USE (always 0)" for SAST, SCA
  and micro-engines; it is read only for KICS. SAST's file count is
  `sast-metadata.fileCount`.
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ops.scan_inputs import (REFUSED_INSIDE_SKILL, collect_names, collect_scan_ids, open_output,
                             output_file)

logger = logging.getLogger("cxone.scanstats")

_CHUNK = 50
_ENGINE_TIMING = ("sast", "sca", "kics", "containers", "apisec", "microengines")

FIELDS = [
    "scan_id", "project_id", "project_name", "branch", "status", "created_at", "engines",
    "initiator", "source_type", "source_origin",
    "duration_s", "sast_duration_s", "sca_duration_s", "kics_duration_s",
    "containers_duration_s", "apisec_duration_s", "microengines_duration_s",
    "sast_loc", "sast_files", "preset", "scan_mode", "base_scan_id", "files_added",
    "files_changed", "files_deleted", "change_pct", "engine_version",
    "sast_scanned_loc", "memory_peak_mb", "languages", "languages_not_scanned",
    "sast_findings", "sast_by_severity", "sast_by_status",
    "iac_files_scanned", "iac_findings", "iac_by_severity", "iac_platforms",
    "sca_packages", "sca_outdated", "sca_vulnerabilities", "sca_by_severity",
    "container_packages", "vulnerable_images", "container_findings", "errors",
]
_TABLE = [("project_name", "Project", 28), ("branch", "Branch", 14), ("created_at", "Created", 11),
          ("scan_mode", "Mode", 12), ("sast_loc", "SAST LOC", 10), ("sast_files", "Files", 6),
          ("iac_files_scanned", "IaC files", 9), ("sca_packages", "SCA pkgs", 8),
          ("duration_s", "Duration", 9)]


# ---------------------------------------------------------------- selection
def _in_window(scan: dict, since: str | None, until: str | None) -> bool:
    created = str(scan.get("createdAt") or "")[:10]
    if since and created < since:
        return False
    if until and created > until:
        return False
    return True


def select_scans(api, *, scan_ids: list[str], names: list[str], all_projects: bool, mode: str,
                 scope: str, branch: str | None, statuses: list[str], since: str | None,
                 until: str | None, engine: str | None, workers: int) -> list[dict]:
    """The scan rows to report. Project selections honour --mode and the filters;
    explicit scan ids are taken as given (any status, any branch)."""
    from ops.branch_scope import BranchResolver
    from ops.scan_info import resolve_project, scan_detail
    from ops.scan_query import scans_for_project

    if scan_ids:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = [r for r in pool.map(lambda s: scan_detail(api, s), scan_ids) if r]
        return rows

    if all_projects:
        projects = api.paginate("projects", results_key="projects")
    else:
        projects = [p for p in (resolve_project(api, n) for n in names) if p]
    resolver = BranchResolver(api)

    def per_project(project: dict) -> list[dict]:
        pid = project.get("id") or ""
        if mode == "latest":
            choice = resolver.resolve(project, scope=scope, branch=branch)
            if not choice.scan_id:
                return []
            scan = next((s for s in resolver.completed_scans(pid)
                         if s.get("id") == choice.scan_id), None)
            return [scan] if scan and _in_window(scan, since, until) else []
        rows = scans_for_project(api, pid, statuses=",".join(statuses) if statuses else None)
        wanted = {s.lower() for s in statuses}
        return [s for s in rows if _in_window(s, since, until)
                and (not wanted or str(s.get("status") or "").lower() in wanted)
                and (not branch or s.get("branch") == branch)]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        groups = list(pool.map(per_project, projects))
    out = [s for g in groups for s in g]
    if engine:
        out = [s for s in out if engine.lower() in [e.lower() for e in (s.get("engines") or [])]]
    names_by_id = {p.get("id"): p.get("name") for p in projects}
    for s in out:
        s.setdefault("projectName", names_by_id.get(s.get("projectId")))
    out.sort(key=lambda s: s.get("createdAt") or "", reverse=True)
    return out


# ---------------------------------------------------------------- row building
def _pairs(d: dict | None) -> str:
    return ";".join(f"{k}={v}" for k, v in (d or {}).items())


def _row(scan: dict, meta: dict | None, version: str | None, summ_shaped: dict,
         metrics: dict | None, errors: list[str]) -> dict:
    from ops.scan_info import _seconds, engine_timeline, is_full_scan
    row = {k: None for k in FIELDS}
    row.update({
        "scan_id": scan.get("id"), "project_id": scan.get("projectId"),
        "project_name": scan.get("projectName"), "branch": scan.get("branch"),
        "status": scan.get("status"), "created_at": scan.get("createdAt"),
        "engines": ";".join(scan.get("engines") or []), "initiator": scan.get("initiator"),
        "source_type": scan.get("sourceType"), "source_origin": scan.get("sourceOrigin"),
        "duration_s": None, "errors": ";".join(errors),
    })
    timeline = engine_timeline(scan)
    general = next((t for t in timeline if t["engine"] == "general"), None)
    row["duration_s"] = (general or {}).get("duration_s") if general else \
        _seconds(scan.get("createdAt"), scan.get("updatedAt"))
    for t in timeline:
        if t["engine"] in _ENGINE_TIMING:
            row[f"{t['engine']}_duration_s"] = t["duration_s"]
    ran = {e.lower() for e in scan.get("engines") or []}
    if meta:
        full = is_full_scan(meta)
        row.update({"sast_loc": meta.get("loc"), "sast_files": meta.get("fileCount"),
                    "preset": meta.get("queryPreset"),
                    "scan_mode": "full" if full else "incremental",
                    "engine_version": version})
        if meta.get("isIncremental") and meta.get("isIncrementalCanceled"):
            row["scan_mode"] = "full (incremental cancelled)"
        if meta.get("baseId"):
            row.update({"base_scan_id": meta.get("baseId"),
                        "files_added": meta.get("addedFilesCount") or 0,
                        "files_changed": meta.get("changedFilesCount") or 0,
                        "files_deleted": meta.get("deletedFilesCount") or 0})
        if meta.get("changePercentage") is not None:
            row["change_pct"] = round(meta["changePercentage"] * 100, 2)   # a ratio, not a percent
    elif "sast" in ran:
        row["scan_mode"] = "no SAST data"
    else:
        row["scan_mode"] = "no SAST"
    if metrics:
        row["sast_scanned_loc"] = metrics.get("total_scanned_loc")
        row["memory_peak_mb"] = metrics.get("memory_peak")
        row["languages"] = ";".join(f"{x['language']}={x['loc_scanned']}"
                                    for x in metrics.get("languages") or [])
        row["languages_not_scanned"] = _pairs(metrics.get("detected_not_scanned"))
    f = (summ_shaped.get("findings") or {})
    if "sast" in ran and f.get("SAST"):
        row.update({"sast_findings": f["SAST"]["total"], "sast_by_severity": _pairs(f["SAST"]["by_severity"]),
                    "sast_by_status": _pairs(f["SAST"]["by_status"])})
    kics = summ_shaped.get("kics") or {}
    if kics and ("kics" in ran or "iac" in ran):
        row.update({"iac_files_scanned": kics.get("files_scanned"), "iac_findings": kics.get("findings"),
                    "iac_by_severity": _pairs(kics.get("by_severity")),
                    "iac_platforms": _pairs(kics.get("platforms"))})
    sca = summ_shaped.get("sca") or {}
    if sca and "sca" in ran:
        row.update({"sca_packages": sca.get("packages"), "sca_outdated": sca.get("outdated_packages"),
                    "sca_vulnerabilities": sca.get("vulnerabilities"),
                    "sca_by_severity": _pairs(sca.get("vulnerabilities_by_severity"))})
    cont = summ_shaped.get("containers") or {}
    if cont and "containers" in ran:
        row.update({"container_packages": cont.get("packages"),
                    "vulnerable_images": cont.get("vulnerable_images"),
                    "container_findings": cont.get("findings")})
    return row


def collect_rows(api, scans: list[dict], *, languages: bool, workers: int):
    """Yield (chunk of rows) as each chunk of 50 scans completes."""
    from ops import scan_info as si
    for start in range(0, len(scans), _CHUNK):
        chunk = scans[start:start + _CHUNK]
        ids = [s["id"] for s in chunk]
        errors: dict[str, list[str]] = {i: [] for i in ids}
        meta = si.sast_metadata_batch(api, ids)
        versions = si.sast_engine_versions(api, ids)
        summaries = si.scan_summaries(api, ids)
        for i in ids:
            if i not in summaries:
                errors[i].append("scan-summary: missing")
        # The batch form omits the incremental delta; fetch it only where it exists.
        deltas = [i for i in ids if meta.get(i) and (meta[i].get("isIncremental")
                                                   or meta[i].get("isIncrementalCanceled"))]
        metric_ids = [i for i in ids if i in meta] if languages else []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            detail = dict(zip(deltas, pool.map(lambda x: si.sast_metadata(api, x), deltas)))
            raw_metrics = dict(zip(metric_ids, pool.map(lambda x: si.sast_metrics(api, x), metric_ids)))
        rows = []
        for scan in chunk:
            sid = scan["id"]
            m = dict(meta.get(sid) or {})
            if detail.get(sid):
                m.update(detail[sid])
            shaped = si._shape_summary(summaries.get(sid), 3)
            metrics = si._shape_metrics(raw_metrics.get(sid)) if raw_metrics.get(sid) else None
            if languages and sid in meta and not metrics:
                errors[sid].append("note: no SAST metrics (engine skipped it as unchanged?)")
            rows.append(_row(scan, m or None, versions.get(sid), shaped, metrics, errors[sid]))
        yield rows


# ---------------------------------------------------------------- output
def _existing_ids(path, fmt: str) -> set[str]:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8", newline="") as handle:
        if fmt == "csv":
            for r in csv.DictReader(handle):
                if r.get("scan_id"):
                    seen.add(r["scan_id"])
        else:
            for line in handle:
                try:
                    seen.add(json.loads(line).get("scan_id"))
                except ValueError:
                    continue
    seen.discard(None)
    return seen


def _fmt_cell(key: str, value) -> str:
    if value is None or value == "":
        return "-"
    if key == "created_at":
        return str(value)[:10]
    if key == "duration_s":
        from ops.scan_info import fmt_duration
        return fmt_duration(value)
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def _table_line(row: dict) -> str:
    return "  ".join(f"{_fmt_cell(k, row.get(k))[:w]:<{w}}" for k, _, w in _TABLE)


def _totals(rows: list[dict]) -> dict:
    latest: dict[tuple, dict] = {}
    for r in sorted(rows, key=lambda r: r.get("created_at") or ""):
        latest[(r.get("project_id"), r.get("branch"))] = r          # newest wins

    def num(key, src):
        return sum(int(r[key]) for r in src if isinstance(r.get(key), (int, float)))
    return {
        "scans": len(rows),
        "scans_with_sast": sum(1 for r in rows if r.get("sast_loc") is not None),
        "incremental": sum(1 for r in rows if str(r.get("scan_mode")) == "incremental"),
        "project_branch_pairs": len(latest),
        "codebase_sast_loc_latest_per_branch": num("sast_loc", latest.values()),
        "iac_files_latest_per_branch": num("iac_files_scanned", latest.values()),
        "sca_packages_latest_per_branch": num("sca_packages", latest.values()),
    }


def cmd_stats(cfg, *, scan_ids, ids_file, names, names_file, all_projects, mode, scope, branch,
              statuses, since, until, engine, languages, fmt, output, fields, summary_only,
              resume, workers) -> int:
    from cxone import ApiClient
    ids = collect_scan_ids(scan_ids, ids_file)
    proj = collect_names(names, names_file)
    chosen = sum(bool(x) for x in (ids, proj, all_projects))
    if chosen != 1:
        print("Select exactly one of: --scan-ids/--scan-ids-file, --project-names/--projects-file, "
              "--all-projects.")
        return 1
    for label, value in (("--since", since), ("--until", until)):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                print(f"{label} must be YYYY-MM-DD.")
                return 1
    cols = [f.strip() for f in (fields or "").split(",") if f.strip()] or list(FIELDS)
    bad = [c for c in cols if c not in FIELDS]
    if bad:
        print(f"Unknown field(s): {', '.join(bad)}. Valid: {', '.join(FIELDS)}")
        return 1
    if fmt is None:
        fmt = "table" if sys.stdout.isatty() else "jsonl"
    target = None
    if output:
        target = output_file(output)
        if target is None:
            print(REFUSED_INSIDE_SKILL, file=sys.stderr)
            return 2
    if resume and not (target and fmt in ("csv", "jsonl")):
        print("--resume needs --output with --format csv or jsonl.")
        return 1

    api = ApiClient(cfg)
    workers = max(1, min(workers, 32))
    scans = select_scans(api, scan_ids=ids, names=proj, all_projects=all_projects, mode=mode,
                         scope=scope, branch=branch, statuses=statuses, since=since, until=until,
                         engine=engine, workers=workers)
    skipped = 0
    if resume:
        done = _existing_ids(target, fmt)
        skipped = sum(1 for s in scans if s["id"] in done)
        scans = [s for s in scans if s["id"] not in done]
    logger.info("%d scan(s) to report%s", len(scans),
                f" ({skipped} already in the output)" if skipped else "")

    every: list[dict] = []
    buffered: list[dict] = []
    appending = bool(resume and target and target.exists() and target.stat().st_size > 0)
    out_cm = open_output(target, "a" if resume else "w", newline="", encoding="utf-8") if target else None
    handle = out_cm.__enter__() if out_cm else sys.stdout
    try:
        writer = None
        if fmt == "table" and not summary_only:
            handle.write("  ".join(f"{h:<{w}}" for _, h, w in _TABLE) + "\n")
        for rows in collect_rows(api, scans, languages=languages, workers=workers):
            every += rows
            if summary_only:
                continue
            if fmt == "json":
                buffered += [{k: r.get(k) for k in cols} for r in rows]
            elif fmt == "jsonl":
                for r in rows:
                    handle.write(json.dumps({k: r.get(k) for k in cols}) + "\n")
            elif fmt == "csv":
                if writer is None:
                    writer = csv.DictWriter(handle, fieldnames=cols, extrasaction="ignore",
                                            lineterminator="\n")
                    if not appending:
                        writer.writeheader()
                writer.writerows(rows)
            else:
                for r in rows:
                    handle.write(_table_line(r) + "\n")
            handle.flush()
        if fmt == "json" and not summary_only:
            if len(buffered) > 5000:
                logger.warning("--format json buffers every row (%d); prefer jsonl for big runs",
                               len(buffered))
            json.dump(buffered, handle, indent=2)
            handle.write("\n")
    finally:
        if out_cm:
            out_cm.__exit__(None, None, None)

    totals = _totals(every)
    failed = sum(1 for r in every if any(not e.startswith("note:")
                                         for e in str(r.get("errors") or "").split(";") if e))
    summary = "\n".join(f"  {k.replace('_', ' ')}: {v:,}" for k, v in totals.items())
    if summary_only:
        print("Totals" + (f" (this run only; {skipped} resumed rows excluded)" if skipped else "")
              + ":\n" + summary)
    else:
        print("\nTotals:\n" + summary, file=sys.stderr)
    if failed:
        print(f"{failed} scan(s) had per-scan errors (see the `errors` column).", file=sys.stderr)
    return 2 if failed else 0
