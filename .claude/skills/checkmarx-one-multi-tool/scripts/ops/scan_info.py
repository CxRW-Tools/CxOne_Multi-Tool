"""
Scan information — lines of code, scan statistics and per-engine detail.

Backs three read-only commands:

  scan info     one scan, everything the platform will say about it: SAST LOC
                and per-language metrics, incremental/full and why, engine
                version, effective configuration, per-engine timing, IaC (KICS)
                files/platforms/categories, SCA packages, containers, secrets,
                and findings by engine x severity. Optionally counts the scanned
                source snapshot itself (``--source-loc``), which is the only way
                to get an IaC line count.
  scan loc      tenant / application / project rollup — one row per project's
                in-scope scan: SAST LOC, files, preset, incremental, the last
                FULL scan's LOC (the sizing number), IaC files scanned, SCA
                packages. Table, JSON or CSV.
  scan history  (in ops/scan_status.py) gains a LOC column from this module.

Where each number comes from (all live endpoints, all read-only):

  GET scans/{id}                       branch, commit, initiator, source, engines,
                                       per-engine start/end (statusDetails)
  GET sast-metadata?scan-ids=a,b,…     loc, fileCount, queryPreset, isIncremental …
                                       up to 50 scans per call (spec maxItems)
  GET sast-metadata/{scan-id}          same, plus base scan + added/changed/
                                       deleted files and change % (incremental)
  GET sast-metadata/{scan-id}/metrics  per-language LOC (scanned OK / failed),
                                       files good/partial/bad, languages detected
                                       but not scanned, DOM objects, memory peak
  GET sast-metadata/engine-version     SAST engine version per scan
  GET scan-summary?scan-ids=…          per-engine counters: severities, statuses,
                                       KICS filesScanned/platforms/categories,
                                       SCA packages/outdated/licenses, containers
  GET kics-results?scan-id=…           IaC findings -> files, cloud providers,
                                       resource types
  GET configuration/scan               the configuration that actually ran

Two traps worth knowing (both from the spec's own field descriptions):

* ``scan-summary``'s ``filesScannedCounter`` is "NOT IN USE (always 0)" for
  SAST, SCA packages and micro-engines. It is real only for KICS. SAST's file
  count comes from ``sast-metadata.fileCount`` instead — never print the zero.
* ``sast-metadata.loc`` and ``metrics.totalScannedLoc`` differ slightly (the
  spec's own example: 106,956 vs 106,819). ``loc`` is what CxOne reports as the
  scan's LOC; ``totalScannedLoc`` is the subset parsed successfully. Both are
  shown, labelled, so neither gets mistaken for the other.

Incremental scans: an incremental SAST scan only re-analyses changed files, so
the rollup also finds the most recent FULL scan on the same branch and reports
its LOC as ``last_full_loc``. ``sizing_loc`` is the full-scan figure whenever
one exists — that is the number to quote for "how big is this codebase".
"""

from __future__ import annotations

import csv
import json
import logging
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("cxone.scaninfo")

_BATCH = 50                     # sast-metadata `scan-ids` maxItems per the spec
_KICS_PAGE = 1000
_FULL_SCAN_LOOKBACK = 25        # older scans checked per project for a full scan
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

ENGINE_LABELS = {
    "sast": "SAST", "sca": "SCA", "kics": "IaC (KICS)", "containers": "Containers",
    "microengines": "Secrets/Scorecard", "apisec": "API Security",
    "aisc": "AI Supply Chain", "cisec": "CI Security",
}
# scan-summary counter block -> engine label
_SUMMARY_BLOCKS = [
    ("sastCounters", "SAST"),
    ("kicsCounters", "IaC (KICS)"),
    ("scaCounters", "SCA"),
    ("containersCounters", "Containers"),
    ("microEnginesCounters", "Secrets/Scorecard"),
    ("apiSecCounters", "API Security"),
    ("aiscCounters", "AI Supply Chain"),
]
# configuration/scan keys worth surfacing in the text view (JSON carries all).
_CONFIG_PREFIXES = ("scan.config.",)


# =================================================================== fetchers
def _chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _is_body(obj) -> bool:
    """A real JSON object, not the client's empty-body placeholder."""
    return isinstance(obj, dict) and any(not k.startswith("_") for k in obj)


def scan_detail(api, scan_id: str) -> dict | None:
    try:
        s = api.get(f"scans/{scan_id}")
    except Exception as exc:                                  # noqa: BLE001
        logger.warning("Could not read scan %s: %s", scan_id, exc)
        return None
    return dict(s) if _is_body(s) else None


def sast_metadata(api, scan_id: str) -> dict | None:
    """Full SAST metadata for one scan (incl. incremental base/delta), or None
    when the scan has no SAST component."""
    try:
        m = api.get(f"sast-metadata/{scan_id}")
    except Exception as exc:                                  # noqa: BLE001
        logger.debug("sast-metadata unavailable for %s: %s", scan_id, exc)
        return None
    return dict(m) if _is_body(m) else None


def sast_metadata_batch(api, scan_ids: list[str]) -> dict[str, dict]:
    """{scan_id: metadata} for many scans, 50 per request.

    Scans without SAST are simply absent (the API lists them under `missing`).
    If a batch call fails outright, its scans are retried one by one so one bad
    id can't blank a whole tenant rollup.
    """
    out: dict[str, dict] = {}
    ids = list(dict.fromkeys(i for i in scan_ids if i))
    for chunk in _chunks(ids, _BATCH):
        try:
            resp = api.get("sast-metadata", params={"scan-ids": ",".join(chunk)}) or {}
        except Exception as exc:                              # noqa: BLE001
            logger.debug("batched sast-metadata failed (%s); falling back per scan", exc)
            for sid in chunk:
                m = sast_metadata(api, sid)
                if m:
                    out[sid] = m
            continue
        for row in (resp.get("scans") if isinstance(resp, dict) else None) or []:
            if row.get("scanId"):
                out[row["scanId"]] = dict(row)
    return out


def sast_metrics(api, scan_id: str) -> dict | None:
    try:
        m = api.get(f"sast-metadata/{scan_id}/metrics")
    except Exception as exc:                                  # noqa: BLE001
        logger.debug("sast metrics unavailable for %s: %s", scan_id, exc)
        return None
    return dict(m) if _is_body(m) else None


def sast_engine_versions(api, scan_ids: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    ids = [i for i in dict.fromkeys(scan_ids) if i]
    for chunk in _chunks(ids, _BATCH):
        try:
            rows = api.get("sast-metadata/engine-version",
                           params={"scan-ids": ",".join(chunk)}) or []
        except Exception as exc:                              # noqa: BLE001
            logger.debug("engine-version unavailable: %s", exc)
            continue
        for r in rows if isinstance(rows, list) else []:
            if r.get("scanId") and r.get("engineVersion"):
                out[r["scanId"]] = r["engineVersion"]
    return out


def scan_summaries(api, scan_ids: list[str], *, queries: bool = False,
                   files: bool = False) -> dict[str, dict]:
    """{scan_id: ResultsSummary} — per-engine counters, one entry per scan."""
    out: dict[str, dict] = {}
    ids = [i for i in dict.fromkeys(scan_ids) if i]
    for chunk in _chunks(ids, _BATCH):
        params = {"scan-ids": chunk,
                  "include-queries": "true" if queries else "false",
                  "include-files": "true" if files else "false",
                  "include-severity-status": "true",
                  "include-status-counters": "true"}
        try:
            resp = api.get("scan-summary", params=params) or {}
        except Exception as exc:                              # noqa: BLE001
            logger.debug("scan-summary failed: %s", exc)
            continue
        for s in (resp.get("scansSummaries") if isinstance(resp, dict) else None) or []:
            if s.get("scanId"):
                out[s["scanId"]] = s
    return out


def effective_config(api, project_id: str, scan_id: str) -> list[dict]:
    """The fully-resolved configuration that ran on this scan (see
    references/cxone-api.md, "Scan configuration")."""
    try:
        rows = api.get("configuration/scan",
                       params={"project-id": project_id, "scan-id": scan_id}) or []
    except Exception as exc:                                  # noqa: BLE001
        logger.debug("configuration/scan unavailable for %s: %s", scan_id, exc)
        return []
    return rows if isinstance(rows, list) else []


def kics_results(api, scan_id: str) -> list[dict]:
    try:
        return api.paginate("kics-results", results_key="results",
                            params={"scan-id": scan_id}, limit=_KICS_PAGE)
    except Exception as exc:                                  # noqa: BLE001
        logger.debug("kics-results unavailable for %s: %s", scan_id, exc)
        return []


# ==================================================================== shaping
_FRACTION = re.compile(r"(\.\d{6})\d+")


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    v = _FRACTION.sub(r"\1", value.strip()).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _seconds(start: str | None, end: str | None) -> float | None:
    a, b = _iso(start), _iso(end)
    if not a or not b:
        return None
    return max((b - a).total_seconds(), 0.0)


def fmt_duration(sec: float | None) -> str:
    if sec is None:
        return "—"
    sec = int(round(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _n(v) -> str:
    """Thousands-separated int, or an em dash for missing."""
    if v is None:
        return "—"
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return str(v)


def _counter_map(items, key: str, value: str = "counter") -> dict:
    out: dict = {}
    for it in items or []:
        k = it.get(key)
        if k is None:
            continue
        out[k] = out.get(k, 0) + (it.get(value) or 0)
    return out


def _sev(block: dict | None, field: str = "severityCounters") -> dict[str, int]:
    m = {str(k).upper(): v for k, v in _counter_map((block or {}).get(field), "severity").items()}
    return {s: m.get(s, 0) for s in SEVERITIES if m.get(s)}


def _top(d: dict, n: int) -> list[tuple]:
    return sorted(d.items(), key=lambda kv: -(kv[1] or 0))[:n]


def is_full_scan(meta: dict | None) -> bool | None:
    """True for a full SAST scan (incl. an incremental that was cancelled and
    therefore ran full), False for a true incremental, None without SAST."""
    if not meta:
        return None
    return (not meta.get("isIncremental")) or bool(meta.get("isIncrementalCanceled"))


def engine_timeline(scan: dict) -> list[dict]:
    rows = []
    for d in scan.get("statusDetails") or []:
        row = {
            "engine": d.get("name"),
            "status": d.get("status"),
            "start": d.get("startDate"),
            "end": d.get("endDate"),
            "duration_s": _seconds(d.get("startDate"), d.get("endDate")),
            "details": d.get("details") or "",
        }
        # Not in the published schema, but returned by live tenants for SAST.
        if d.get("loc") is not None:
            row["loc"] = d.get("loc")
        rows.append(row)
    return rows


def _shape_metrics(metrics: dict | None) -> dict | None:
    if not metrics:
        return None
    ok = metrics.get("successfullLocPerLanguage") or {}     # sic: API spelling
    failed = {k: v for k, v in (metrics.get("failedLocPerLanguage") or {}).items()
              if k not in (None, "null") and v}
    files = metrics.get("scannedFilesPerLanguage") or {}
    dom = metrics.get("domObjectsPerLanguage") or {}
    langs = sorted(set(ok) | set(failed) | set(files) | set(dom),
                   key=lambda lang: -((ok.get(lang) or 0) + (failed.get(lang) or 0)))
    per_lang = []
    for lang in langs:
        f = files.get(lang) or {}
        per_lang.append({
            "language": lang,
            "loc_scanned": ok.get(lang) or 0,
            "loc_failed": failed.get(lang) or 0,
            "files_good": f.get("goodFiles") or 0,
            "files_partial": f.get("partiallyGoodFiles") or 0,
            "files_bad": f.get("badFiles") or 0,
            "dom_objects": dom.get(lang) or 0,
        })
    not_scanned = {k: v for k, v in
                   (metrics.get("fileCountOfDetectedButNotScannedLanguages") or {}).items()
                   if k not in (None, "null")}
    return {
        "total_scanned_loc": metrics.get("totalScannedLoc"),
        "total_scanned_files": metrics.get("totalScannedFilesCount"),
        "memory_peak": metrics.get("memoryPeak"),
        "virtual_memory_peak": metrics.get("virtualMemoryPeak"),
        "languages": per_lang,
        "detected_not_scanned": not_scanned,
    }


def _shape_summary(summ: dict | None, top: int) -> dict:
    """Per-engine counters from one ResultsSummary."""
    if not summ:
        return {}
    out: dict = {"findings": {}}
    for block, label in _SUMMARY_BLOCKS:
        b = summ.get(block)
        if not b:
            continue
        total = b.get("totalCounter")
        if total is None:
            total = b.get("apiSecTotal")
        sev = _sev(b)
        if not total and not sev:
            continue
        out["findings"][label] = {
            "total": total if total is not None else sum(sev.values()),
            "by_severity": sev,
            "by_status": _counter_map(b.get("statusCounters"), "status"),
            "by_state": _counter_map(b.get("stateCounters"), "state"),
        }

    sast = summ.get("sastCounters") or {}
    if sast.get("totalCounter"):
        out["sast"] = {
            "findings_by_language": _counter_map(sast.get("languageCounters"), "language"),
            "top_queries": [
                {"query": q.get("queryName"), "severity": q.get("severity"),
                 "count": q.get("counter")}
                for q in sorted(sast.get("queriesCounters") or [],
                                key=lambda q: -(q.get("counter") or 0))[:top]],
            "compliance": dict(_top(_counter_map(sast.get("complianceCounters"),
                                                 "compliance", "count"), top)),
        }

    kics = summ.get("kicsCounters") or {}
    if kics.get("totalCounter") or kics.get("filesScannedCounter"):
        out["kics"] = {
            "files_scanned": kics.get("filesScannedCounter"),
            "findings": kics.get("totalCounter"),
            "by_severity": _sev(kics),
            "platforms": _counter_map(kics.get("platformSummary"), "platform"),
            "categories": _counter_map(kics.get("categorySummary"), "category"),
        }

    pk = summ.get("scaPackagesCounters") or {}
    sca = summ.get("scaCounters") or {}
    if pk.get("totalCounter") or sca.get("totalCounter"):
        out["sca"] = {
            "packages": pk.get("totalCounter"),
            "outdated_packages": pk.get("outdatedCounter"),
            "package_risk_levels": {str(k).upper(): v for k, v in
                                    _counter_map(pk.get("riskLevelCounters"), "riskLevel").items()},
            "licenses": dict(_top(_counter_map(pk.get("licenseCounters"), "package"), top)),
            "vulnerabilities": sca.get("totalCounter"),
            "vulnerabilities_by_severity": _sev(sca),
            "manifest_files": dict(_top(_counter_map(sca.get("sourceFileCounters"), "file"), top)),
        }

    cont = summ.get("containersCounters") or {}
    scac = summ.get("scaContainersCounters") or {}
    if (cont.get("totalCounter") or cont.get("totalPackagesCounter")
            or scac.get("totalPackagesCounter")):
        out["containers"] = {
            "packages": cont.get("totalPackagesCounter") or scac.get("totalPackagesCounter"),
            "vulnerable_images": cont.get("totalVulnerableImages"),
            "findings": cont.get("totalCounter"),
            "by_severity": _sev(cont),
            "malicious_packages": sum(1 for p in cont.get("packageCounters") or []
                                      if p.get("isMalicious")),
        }

    aisc = summ.get("aiscCounters") or {}
    if aisc and (aisc.get("assetsCounter") or aisc.get("totalCounter")):
        out["aisc"] = {
            "assets": aisc.get("assetsCounter"),
            "asset_types": aisc.get("assetTypesCounter"),
            "files_scanned": aisc.get("filesScannedCounter"),
            "findings": aisc.get("totalCounter"),
        }
    return out


def _shape_kics_results(rows: list[dict], top: int) -> dict:
    files: dict[str, int] = {}
    providers: dict[str, int] = {}
    resource_types: dict[str, int] = {}
    platforms: dict[str, int] = {}
    for r in rows:
        if r.get("fileName"):
            files[r["fileName"]] = files.get(r["fileName"], 0) + 1
        for key, bucket in (("cloudProvider", providers), ("resourceType", resource_types),
                            ("platform", platforms)):
            v = r.get(key)
            if v:
                bucket[v] = bucket.get(v, 0) + 1
    return {
        "findings": len(rows),
        "files_with_findings": len(files),
        "top_files": [{"file": f, "findings": n} for f, n in _top(files, top)],
        "cloud_providers": dict(_top(providers, top)),
        "resource_types": dict(_top(resource_types, top)),
        "platforms": platforms,
    }


# ============================================================ scan resolution
def resolve_project(api, name: str) -> dict | None:
    projects = api.paginate("projects", results_key="projects")
    want = name.lower()
    match = next((p for p in projects if (p.get("name") or "") == name), None) or \
        next((p for p in projects if (p.get("name") or "").lower() == want), None)
    if not match:
        from ops.project_resolve import warn_unresolved_projects
        warn_unresolved_projects(logger, [name], projects, set())
    return match


def project_by_id(api, project_id: str) -> dict:
    try:
        p = api.get(f"projects/{project_id}")
        if _is_body(p):
            return dict(p)
    except Exception as exc:                                  # noqa: BLE001
        logger.debug("project %s lookup failed: %s", project_id, exc)
    return {"id": project_id, "name": project_id}


# ================================================================ scan info
def collect_scan_info(api, project: dict, scan_id: str, *, choice=None,
                      top: int = 10, kics_detail: bool = True,
                      source_loc: bool = False, keep_source: str | None = None,
                      workers: int = 6) -> dict | None:
    """Everything known about one scan, as a JSON-friendly dict."""
    scan = scan_detail(api, scan_id)
    if not scan:
        return None
    pid = scan.get("projectId") or project.get("id")
    engines = [str(e).lower() for e in scan.get("engines") or []]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        f_meta = pool.submit(sast_metadata, api, scan_id)
        f_metrics = pool.submit(sast_metrics, api, scan_id)
        f_ver = pool.submit(sast_engine_versions, api, [scan_id])
        f_summ = pool.submit(scan_summaries, api, [scan_id], queries=True)
        f_cfg = pool.submit(effective_config, api, pid, scan_id)
        f_kics = pool.submit(kics_results, api, scan_id) \
            if kics_detail and "kics" in engines else None
        meta, metrics = f_meta.result(), f_metrics.result()
        version = f_ver.result().get(scan_id)
        summary = f_summ.result().get(scan_id)
        config = f_cfg.result()
        kics_rows = f_kics.result() if f_kics else None

    timeline = engine_timeline(scan)
    general = next((t for t in timeline if t["engine"] == "general"), None)
    handler = ((scan.get("metadata") or {}).get("Handler") or {})
    git = handler.get("GitHandler") or {}

    info: dict = {
        "project": {"id": pid, "name": project.get("name") or scan.get("projectName") or pid},
        "scan": {
            "id": scan_id,
            "status": scan.get("status"),
            "branch": scan.get("branch") or git.get("branch"),
            "commit": scan.get("commitId") or git.get("commit"),
            "commit_tag": scan.get("commitTag"),
            "repo_url": git.get("repo_url"),
            "created": scan.get("createdAt"),
            "updated": scan.get("updatedAt"),
            "duration_s": (general or {}).get("duration_s")
            or _seconds(scan.get("createdAt"), scan.get("updatedAt")),
            "initiator": scan.get("initiator"),
            "source_type": scan.get("sourceType"),
            "source_origin": scan.get("sourceOrigin"),
            "user_agent": scan.get("userAgent"),
            "engines": engines,
            "tags": scan.get("tags") or {},
            "requested_config": (scan.get("metadata") or {}).get("configs") or [],
        },
        "branch_scope": {"description": choice.describe(), "drift": choice.drift_note()}
        if choice else None,
        "engine_timeline": [t for t in timeline if t["engine"] != "general"],
    }

    status_loc = next((t.get("loc") for t in timeline if t["engine"] == "sast"
                       and t.get("loc") is not None), None)
    if meta or metrics or status_loc is not None:
        full = is_full_scan(meta)
        info["sast"] = {
            "loc": (meta or {}).get("loc"),
            "file_count": (meta or {}).get("fileCount"),
            "preset": (meta or {}).get("queryPreset"),
            "is_incremental": (meta or {}).get("isIncremental"),
            "incremental_canceled": (meta or {}).get("isIncrementalCanceled"),
            "incremental_cancel_reason": (meta or {}).get("incrementalCancelReason"),
            "ran_as": None if full is None else ("full" if full else "incremental"),
            "base_scan_id": (meta or {}).get("baseId"),
            "added_files": (meta or {}).get("addedFilesCount"),
            "changed_files": (meta or {}).get("changedFilesCount"),
            "deleted_files": (meta or {}).get("deletedFilesCount"),
            "change_percentage": (meta or {}).get("changePercentage"),
            "configuration_changed": (meta or {}).get("hasConfigurationChanged"),
            "engine_version": version,
            "status_details_loc": status_loc,
            "metrics": _shape_metrics(metrics),
        }

    shaped = _shape_summary(summary, top)
    info["findings"] = shaped.pop("findings", {})
    if "sast" in shaped:
        info.setdefault("sast", {}).update({"results": shaped.pop("sast")})
    if "kics" in shaped or kics_rows is not None:
        iac = shaped.pop("kics", {}) or {}
        if kics_rows is not None:
            iac["detail"] = _shape_kics_results(kics_rows, top)
        info["iac"] = iac
    info.update(shaped)                      # sca / containers / aisc
    info["config"] = [
        {"key": c.get("key"), "value": c.get("value"), "origin": c.get("originLevel"),
         "category": c.get("category")}
        for c in config if c.get("key")]

    if source_loc:
        info["source"] = _count_source(api, scan_id, keep_source, top)
    return info


def _count_source(api, scan_id: str, keep_source: str | None, top: int) -> dict:
    from ops.source_fetch import fetch_scan_source
    from ops.source_loc import count_tree
    if keep_source:
        root = fetch_scan_source(api, scan_id, Path(keep_source))
        if not root:
            return {"error": "scanned source unavailable (see warning above)"}
        out = count_tree(root, top_files=top)
        out["kept_at"] = str(root)
        return out
    with tempfile.TemporaryDirectory(prefix="cxone-src-") as tmp:
        root = fetch_scan_source(api, scan_id, Path(tmp))
        if not root:
            return {"error": "scanned source unavailable (see warning above)"}
        return count_tree(root, top_files=top)


# ------------------------------------------------------------- text renderer
def _kv(lines: list[str], key: str, value, note: str = "") -> None:
    if value in (None, "", "—", [], {}):
        return
    lines.append(f"  {key:<24}{value}{('   ' + note) if note else ''}")


def _sev_str(sev: dict) -> str:
    return "  ".join(f"{s[0]}:{sev[s]}" for s in SEVERITIES if sev.get(s))


def _pairs(d: dict, n: int = 10) -> str:
    return ", ".join(f"{k} {_n(v)}" for k, v in _top(d, n))


def render_scan_info(info: dict, *, brief: bool = False, all_config: bool = False) -> str:
    L: list[str] = []
    p, s = info["project"], info["scan"]
    L.append(f"Scan info — {p['name']}  (project {p['id']})")
    if info.get("branch_scope"):
        L.append(f"  {info['branch_scope']['description']}")
        if info["branch_scope"].get("drift"):
            L.append(f"  NOTE: {info['branch_scope']['drift']}")
    L.append("")
    _kv(L, "Scan", s["id"])
    _kv(L, "Status", s["status"])
    commit = (s.get("commit") or "")[:12]
    _kv(L, "Branch", s.get("branch"), f"commit {commit}" if commit else "")
    _kv(L, "Commit tag", s.get("commit_tag"))
    _kv(L, "Repository", s.get("repo_url"))
    _kv(L, "Created", (s.get("created") or "")[:19].replace("T", " "))
    _kv(L, "Duration", fmt_duration(s.get("duration_s")))
    _kv(L, "Initiator", s.get("initiator"))
    src = " / ".join(x for x in (s.get("source_type"), s.get("source_origin")) if x)
    _kv(L, "Source", src, f"user-agent {s['user_agent']}" if s.get("user_agent") else "")
    _kv(L, "Engines", ", ".join(s.get("engines") or []))
    if s.get("tags"):
        _kv(L, "Tags", ", ".join(f"{k}={v}" if v else k for k, v in s["tags"].items()))

    if info.get("engine_timeline"):
        L.append("")
        L.append("Engine timeline")
        for t in info["engine_timeline"]:
            name = ENGINE_LABELS.get(t["engine"], t["engine"])
            start = (t.get("start") or "")[11:19]
            end = (t.get("end") or "")[11:19]
            when = f"{start}→{end}" if start or end else ""
            det = f"  {t['details']}" if t.get("details") else ""
            L.append(f"  {name:<20}{t.get('status') or '?':<11}{fmt_duration(t.get('duration_s')):>9}"
                     f"  {when}{det}")

    sast = info.get("sast")
    if sast:
        L.append("")
        L.append("SAST")
        _kv(L, "Lines of code", _n(sast.get("loc")), "sast-metadata.loc (CxOne's LOC for this scan)")
        m = sast.get("metrics") or {}
        if m.get("total_scanned_loc") is not None:
            _kv(L, "Successfully scanned", f"{_n(m['total_scanned_loc'])} LOC in "
                f"{_n(m.get('total_scanned_files'))} files", "metrics.totalScannedLoc")
        if sast.get("loc") is None and sast.get("status_details_loc") is not None:
            _kv(L, "LOC (status details)", _n(sast["status_details_loc"]))
        _kv(L, "Files", _n(sast.get("file_count")), "sast-metadata.fileCount")
        _kv(L, "Preset", sast.get("preset"))
        mode = sast.get("ran_as")
        if sast.get("is_incremental") and sast.get("incremental_canceled"):
            reason = sast.get("incremental_cancel_reason") or "no reason given"
            mode = f"FULL (incremental requested, cancelled: {reason})"
        elif mode == "incremental":
            delta = (f"+{_n(sast.get('added_files'))} ~{_n(sast.get('changed_files'))} "
                     f"-{_n(sast.get('deleted_files'))} files")
            pct = sast.get("change_percentage")
            if pct is not None:
                delta += f", {pct:.1f}% changed"
            mode = f"INCREMENTAL ({delta}); base scan {sast.get('base_scan_id') or '?'}"
        _kv(L, "Scan mode", mode)
        if sast.get("ran_as") == "incremental":
            L.append("  NOTE: an incremental scan's LOC covers only re-analysed code; "
                     "`scan loc` reports the last full scan's LOC (sizing_loc).")
        if sast.get("configuration_changed") is not None:
            _kv(L, "Config changed vs base", "yes" if sast["configuration_changed"] else "no")
        _kv(L, "Engine version", sast.get("engine_version"))
        if m.get("memory_peak") is not None:
            _kv(L, "Peak memory", f"{_n(m['memory_peak'])} (virtual "
                f"{_n(m.get('virtual_memory_peak'))})", "as reported by the engine (MB)")
        if m.get("languages"):
            L.append("  Per language:")
            L.append(f"    {'Language':<18}{'LOC scanned':>12}{'LOC failed':>12}"
                     f"{'Files ok':>10}{'partial':>9}{'bad':>6}{'DOM objects':>13}")
            for r in m["languages"]:
                L.append(f"    {r['language']:<18}{_n(r['loc_scanned']):>12}"
                         f"{_n(r['loc_failed']):>12}{_n(r['files_good']):>10}"
                         f"{_n(r['files_partial']):>9}{_n(r['files_bad']):>6}"
                         f"{_n(r['dom_objects']):>13}")
        if m.get("detected_not_scanned"):
            _kv(L, "Detected, not scanned", _pairs(m["detected_not_scanned"]) + " file(s)",
                "language not in preset/licence")
        res = sast.get("results") or {}
        if not brief and res.get("top_queries"):
            L.append("  Top queries:")
            for q in res["top_queries"]:
                L.append(f"    {_n(q['count']):>6}  {(q.get('severity') or ''):<9}{q['query']}")
        if not brief and res.get("findings_by_language"):
            _kv(L, "Findings by language", _pairs(res["findings_by_language"]))

    iac = info.get("iac")
    if iac:
        L.append("")
        L.append("IaC (KICS)")
        _kv(L, "Files scanned", _n(iac.get("files_scanned")), "kicsCounters.filesScannedCounter")
        if iac.get("findings") is not None:
            _kv(L, "Findings", _n(iac.get("findings")), _sev_str(iac.get("by_severity") or {}))
        _kv(L, "Platforms (findings)", _pairs(iac.get("platforms") or {}))
        if not brief:
            _kv(L, "Categories", _pairs(iac.get("categories") or {}, 8))
        d = iac.get("detail") or {}
        if d:
            _kv(L, "Files with findings", _n(d.get("files_with_findings")))
            _kv(L, "Cloud providers", _pairs(d.get("cloud_providers") or {}))
            if not brief:
                _kv(L, "Resource types", _pairs(d.get("resource_types") or {}, 8))
                if d.get("top_files"):
                    L.append("  Top files by findings:")
                    for f in d["top_files"]:
                        L.append(f"    {_n(f['findings']):>6}  {f['file']}")
        if not info.get("source"):
            L.append("  (CxOne reports no IaC line count; add --source-loc to count "
                     "IaC lines in the scanned snapshot)")

    sca = info.get("sca")
    if sca:
        L.append("")
        L.append("SCA")
        _kv(L, "Packages", _n(sca.get("packages")),
            f"{_n(sca.get('outdated_packages'))} outdated" if sca.get("outdated_packages") else "")
        if sca.get("package_risk_levels"):
            _kv(L, "Package risk levels", _sev_str(sca["package_risk_levels"]))
        if sca.get("vulnerabilities") is not None:
            _kv(L, "Vulnerabilities", _n(sca["vulnerabilities"]),
                _sev_str(sca.get("vulnerabilities_by_severity") or {}))
        if not brief:
            _kv(L, "Licenses", _pairs(sca.get("licenses") or {}, 8))
            _kv(L, "Manifests (findings)", _pairs(sca.get("manifest_files") or {}, 6))

    cont = info.get("containers")
    if cont:
        L.append("")
        L.append("Containers")
        _kv(L, "Packages", _n(cont.get("packages")))
        _kv(L, "Vulnerable images", _n(cont.get("vulnerable_images")))
        if cont.get("findings") is not None:
            _kv(L, "Findings", _n(cont["findings"]), _sev_str(cont.get("by_severity") or {}))
        if cont.get("malicious_packages"):
            _kv(L, "Malicious packages", _n(cont["malicious_packages"]))

    aisc = info.get("aisc")
    if aisc:
        L.append("")
        L.append("AI Supply Chain")
        _kv(L, "Assets", _n(aisc.get("assets")), f"{_n(aisc.get('asset_types'))} type(s)")
        _kv(L, "Files scanned", _n(aisc.get("files_scanned")))
        _kv(L, "Findings", _n(aisc.get("findings")))

    if info.get("findings"):
        L.append("")
        L.append("Findings by engine")
        L.append(f"  {'Engine':<20}{'Total':>7}{'Crit':>6}{'High':>6}{'Med':>6}{'Low':>6}{'Info':>6}"
                 f"   New/Recurrent/Fixed")
        for label, f in info["findings"].items():
            sev = f.get("by_severity") or {}
            st = f.get("by_status") or {}
            L.append(f"  {label:<20}{_n(f.get('total')):>7}"
                     + "".join(f"{_n(sev.get(x, 0)):>6}" for x in SEVERITIES)
                     + f"   {st.get('NEW', 0)}/{st.get('RECURRENT', 0)}/{st.get('FIXED', 0)}")

    src = info.get("source")
    if src:
        L.append("")
        L.append("Scanned source snapshot (counted locally — cloc-style estimate)")
        if src.get("error"):
            L.append(f"  {src['error']}")
        else:
            t = src["totals"]
            _kv(L, "Files in snapshot", _n(src.get("files_in_snapshot")),
                f"{_n(src.get('unrecognised_files'))} unrecognised")
            _kv(L, "Application code", f"{_n(t['code'])} lines in {_n(t['files'])} files",
                f"+{_n(t['comment'])} comment, {_n(t['blank'])} blank")
            L.append(f"    {'Language':<22}{'Files':>7}{'Code':>10}{'Comment':>9}{'Blank':>8}")
            for lang, b in src["languages"].items():
                L.append(f"    {lang:<22}{_n(b['files']):>7}{_n(b['code']):>10}"
                         f"{_n(b['comment']):>9}{_n(b['blank']):>8}")
            it = src.get("iac_totals") or {}
            if it.get("files"):
                _kv(L, "IaC", f"{_n(it['code'])} code lines in {_n(it['files'])} files",
                    f"{_n(it['code'] + it['comment'] + it['blank'])} total lines")
                L.append(f"    {'Platform':<22}{'Files':>7}{'Code':>10}{'Comment':>9}{'Blank':>8}")
                for plat, b in src["iac"].items():
                    L.append(f"    {plat:<22}{_n(b['files']):>7}{_n(b['code']):>10}"
                             f"{_n(b['comment']):>9}{_n(b['blank']):>8}")
                if not brief and src.get("iac_files"):
                    L.append("  Largest IaC files:")
                    for f in src["iac_files"]:
                        L.append(f"    {_n(f['code']):>7}  {f['platform']:<16} {f['file']}")
            else:
                L.append("  No IaC files recognised in the snapshot.")
            if src.get("kept_at"):
                _kv(L, "Source kept at", src["kept_at"])

    cfg = info.get("config") or []
    if cfg and not brief:
        shown = [c for c in cfg if (all_config or str(c["key"]).startswith(_CONFIG_PREFIXES))
                 and c.get("value") not in (None, "")]
        if shown:
            L.append("")
            L.append("Effective configuration for this scan (configuration/scan)")
            for c in sorted(shown, key=lambda c: c["key"]):
                val = str(c["value"])
                val = val if len(val) <= 70 else val[:67] + "..."
                L.append(f"  {c['key']:<48} {val}  [{c.get('origin') or '?'}]")
    return "\n".join(L)


# ================================================================ LOC rollup
ROLLUP_FIELDS = [
    "project", "project_id", "branch", "scan_id", "scan_date", "engines",
    "sast_loc", "sast_files", "preset", "scan_mode", "last_full_loc",
    "last_full_scan_id", "last_full_scan_date", "sizing_loc",
    "iac_files_scanned", "iac_platforms", "iac_findings",
    "sca_packages", "container_packages", "languages",
]


def loc_rollup(api, projects: list[dict], *, scope: str = "primary",
               branch: str | None = None, languages: bool = False,
               workers: int = 10) -> list[dict]:
    """One row per project for its in-scope scan. See ROLLUP_FIELDS."""
    from ops.branch_scope import BranchResolver
    resolver = BranchResolver(api)
    workers = max(1, workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        choices = list(pool.map(lambda p: resolver.resolve(p, scope=scope, branch=branch),
                                projects))

    chosen: dict[str, dict] = {}                 # project id -> chosen scan row
    for p, c in zip(projects, choices):
        if c.scan_id:
            scan = next((s for s in resolver.completed_scans(p.get("id") or "")
                         if s.get("id") == c.scan_id), {"id": c.scan_id})
            chosen[p["id"]] = scan

    ids = [s["id"] for s in chosen.values()]
    meta = sast_metadata_batch(api, ids)
    summaries = scan_summaries(api, ids)

    # Incremental chosen scans: look back on the same branch for a full scan.
    lookback: dict[str, list[str]] = {}
    for pid, scan in chosen.items():
        m = meta.get(scan["id"])
        if m and is_full_scan(m) is False:
            history = resolver.completed_scans(pid)
            idx = next((i for i, s in enumerate(history) if s.get("id") == scan["id"]), -1)
            older = [s.get("id") for s in history[idx + 1:]
                     if s.get("branch") == scan.get("branch")][:_FULL_SCAN_LOOKBACK]
            lookback[pid] = older
    older_meta = sast_metadata_batch(api, [i for ids_ in lookback.values() for i in ids_])

    metrics: dict[str, dict] = {}
    if languages:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            sids = [s for s in ids if s in meta]
            for sid, m in zip(sids, pool.map(lambda x: sast_metrics(api, x), sids)):
                if m:
                    metrics[sid] = m

    rows = []
    for p, c in zip(projects, choices):
        pid = p.get("id")
        row = {k: None for k in ROLLUP_FIELDS}
        row.update({"project": p.get("name"), "project_id": pid})
        scan = chosen.get(pid)
        if not scan:
            row["scan_mode"] = "no completed scan in scope"
            rows.append(row)
            continue
        sid = scan["id"]
        m = meta.get(sid)
        row.update({
            "branch": scan.get("branch") or c.branch,
            "scan_id": sid,
            "scan_date": (scan.get("createdAt") or "")[:10] or None,
            "engines": ",".join(scan.get("engines") or []),
        })
        if m:
            full = is_full_scan(m)
            row.update({
                "sast_loc": m.get("loc"),
                "sast_files": m.get("fileCount"),
                "preset": m.get("queryPreset"),
                "scan_mode": "full" if full else "incremental",
            })
            if full:
                row.update({"last_full_loc": m.get("loc"), "last_full_scan_id": sid,
                            "last_full_scan_date": row["scan_date"]})
            else:
                hist = {s.get("id"): s for s in resolver.completed_scans(pid)}
                for oid in lookback.get(pid, []):
                    om = older_meta.get(oid)
                    if om and is_full_scan(om):
                        row.update({
                            "last_full_loc": om.get("loc"), "last_full_scan_id": oid,
                            "last_full_scan_date": (hist.get(oid, {}).get("createdAt") or "")[:10]
                            or None})
                        break
            row["sizing_loc"] = row["last_full_loc"] if row["last_full_loc"] is not None \
                else m.get("loc")
        else:
            row["scan_mode"] = "no SAST"
        summ = summaries.get(sid) or {}
        kics = summ.get("kicsCounters") or {}
        if kics:
            row["iac_files_scanned"] = kics.get("filesScannedCounter")
            row["iac_findings"] = kics.get("totalCounter")
            plats = _counter_map(kics.get("platformSummary"), "platform")
            row["iac_platforms"] = ";".join(k for k, _ in _top(plats, 10)) or None
        pk = summ.get("scaPackagesCounters") or {}
        if pk.get("totalCounter") is not None:
            row["sca_packages"] = pk.get("totalCounter")
        cont = summ.get("containersCounters") or {}
        if cont.get("totalPackagesCounter") is not None:
            row["container_packages"] = cont.get("totalPackagesCounter")
        if sid in metrics:
            ok = metrics[sid].get("successfullLocPerLanguage") or {}
            row["languages"] = ";".join(f"{k}={v}" for k, v in
                                        sorted(ok.items(), key=lambda kv: -(kv[1] or 0)))
        rows.append(row)
    return rows


def rollup_totals(rows: list[dict]) -> dict:
    def tot(key):
        return sum(r[key] for r in rows if isinstance(r.get(key), int))
    return {
        "projects": len(rows),
        "projects_with_sast": sum(1 for r in rows if r.get("sast_loc") is not None),
        "incremental_latest": sum(1 for r in rows if r.get("scan_mode") == "incremental"),
        "incremental_without_full": sum(1 for r in rows if r.get("scan_mode") == "incremental"
                                        and r.get("last_full_scan_id") is None),
        "sast_loc": tot("sast_loc"),
        "sizing_loc": tot("sizing_loc"),
        "sast_files": tot("sast_files"),
        "iac_files_scanned": tot("iac_files_scanned"),
        "iac_findings": tot("iac_findings"),
        "sca_packages": tot("sca_packages"),
        "container_packages": tot("container_packages"),
    }


def render_rollup(rows: list[dict], totals: dict, *, header: str) -> str:
    L = [header, ""]
    L.append(f"  {'Project':<34}{'Branch':<16}{'Scan date':<11}{'SAST LOC':>11}{'Files':>7}"
             f"  {'Mode':<15}{'Sizing LOC':>11}{'IaC files':>10}{'SCA pkgs':>9}  Preset")
    for r in sorted(rows, key=lambda r: -(r.get("sizing_loc") or -1)):
        name = (r.get("project") or "?")
        name = name if len(name) <= 33 else name[:30] + "..."
        br = (r.get("branch") or "—")
        br = br if len(br) <= 15 else br[:12] + "..."
        mode = r.get("scan_mode") or "—"
        if mode == "incremental" and r.get("last_full_scan_id") is None:
            mode = "incr (no full)"
        L.append(f"  {name:<34}{br:<16}{r.get('scan_date') or '—':<11}"
                 f"{_n(r.get('sast_loc')):>11}{_n(r.get('sast_files')):>7}  {mode[:15]:<15}"
                 f"{_n(r.get('sizing_loc')):>11}{_n(r.get('iac_files_scanned')):>10}"
                 f"{_n(r.get('sca_packages')):>9}  {r.get('preset') or ''}")
    L.append("  " + "-" * 123)
    L.append(f"  {'TOTAL (' + str(totals['projects']) + ' projects)':<61}"
             f"{_n(totals['sast_loc']):>11}{_n(totals['sast_files']):>7}  {'':<15}"
             f"{_n(totals['sizing_loc']):>11}{_n(totals['iac_files_scanned']):>10}"
             f"{_n(totals['sca_packages']):>9}")
    L.append("")
    L.append(f"  Projects with SAST: {totals['projects_with_sast']} of {totals['projects']}.  "
             f"Sizing LOC uses each project's last FULL SAST scan on the same branch.")
    if totals["incremental_latest"]:
        L.append(f"  {totals['incremental_latest']} project(s) have an incremental latest scan"
                 + (f"; {totals['incremental_without_full']} with no full scan in history "
                    f"(their sizing LOC is the incremental figure — an undercount)"
                    if totals["incremental_without_full"] else "") + ".")
    if any(r.get("languages") for r in rows):
        L.append("")
        L.append("  Per-language SAST LOC:")
        agg: dict[str, int] = {}
        for r in rows:
            for part in (r.get("languages") or "").split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    try:
                        agg[k] = agg.get(k, 0) + int(v)
                    except ValueError:
                        pass
        for k, v in _top(agg, 50):
            L.append(f"    {k:<20}{_n(v):>12}")
    return "\n".join(L)


def write_csv(path: str, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ROLLUP_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in ROLLUP_FIELDS})


# ======================================================================= CLI
def cmd_info(cfg, *, project: str | None, scan_id: str | None, scope: str,
             branch: str | None, as_json: bool, brief: bool, all_config: bool,
             source_loc: bool, keep_source: str | None, top: int,
             no_kics_detail: bool) -> int:
    from cxone import ApiClient
    api = ApiClient(cfg)
    choice = None
    if scan_id:
        scan = scan_detail(api, scan_id)
        if not scan:
            logger.error("Scan %s not found (or not visible to this key).", scan_id)
            return 1
        proj = project_by_id(api, scan.get("projectId") or "")
    else:
        proj = resolve_project(api, project or "")
        if not proj:
            return 1
        from ops.branch_scope import BranchResolver
        choice = BranchResolver(api).resolve(proj, scope=scope, branch=branch)
        if not choice.scan_id:
            logger.warning("%s: no completed scan in scope (%s). Pass --scan-id for a "
                           "Partial/Failed scan, or try --scope latest.",
                           proj.get("name"), branch or scope)
            return 1
        scan_id = choice.scan_id
    info = collect_scan_info(api, proj, scan_id, choice=choice, top=top,
                             kics_detail=not no_kics_detail, source_loc=source_loc,
                             keep_source=keep_source, workers=min(cfg.workers, 6))
    if not info:
        return 1
    if as_json:
        print(json.dumps(info, indent=2, default=str))
    else:
        print(render_scan_info(info, brief=brief, all_config=all_config))
    return 0


def cmd_loc(cfg, *, names: list[str] | None, app: str | None, scope: str,
            branch: str | None, languages: bool, as_json: bool,
            csv_path: str | None) -> int:
    from cxone import ApiClient
    from results import ResultsManager
    api = ApiClient(cfg)
    projects = ResultsManager(api)._resolve_projects(names, app)
    if not projects:
        logger.warning("No matching projects.")
        return 1
    logger.info("Collecting LOC for %d project(s) (branch scope: %s)...",
                len(projects), f"--branch {branch}" if branch else scope)
    rows = loc_rollup(api, projects, scope=scope, branch=branch,
                      languages=languages, workers=cfg.workers)
    totals = rollup_totals(rows)
    if csv_path:
        write_csv(csv_path, rows)
        logger.info("CSV: %d row(s) written to %s", len(rows), csv_path)
    if as_json:
        print(json.dumps({"scope": branch or scope, "totals": totals, "projects": rows},
                         indent=2, default=str))
    else:
        what = f"application '{app}'" if app else (
            f"{len(projects)} project(s)" if names else "all projects")
        print(render_rollup(rows, totals,
                            header=f"Lines of code — {what}, branch scope: "
                                   f"{'--branch ' + branch if branch else scope}"))
    return 0
