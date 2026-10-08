"""
`scan workflow` and `scan log`: the two per-scan diagnostics CxOne exposes.

* **Workflow** (`GET /api/scans/{id}/workflow`): the timestamped task events the
  platform recorded for a scan (created, source pulled, engines started and
  finished, completed). Rows are `Timestamp`, `Source`, `Info`.
* **Engine log** (`GET /api/logs/{scan-id}/{engine}`): the raw engine log. The
  endpoint answers with a redirect to a storage URL, which `requests` follows.
  Only SAST (`sast`) and IaC (`kics`) keep a log; other engines return 404, and
  so does a scan whose log has aged out.

Both are read-only against the tenant. They write local files, always into the
user's own directory (never the skill folder).
"""

from __future__ import annotations

import csv
import json
import logging
import sys

from ops.scan_inputs import (REFUSED_INSIDE_SKILL, collect_scan_ids, open_output,
                             output_dir, split_csv)

logger = logging.getLogger("cxone.scanlogs")

LOG_ENGINES = ("sast", "kics")
_COLUMNS = ["Timestamp", "Source", "Info"]


def fetch_workflow(api, scan_id: str) -> list[dict] | None:
    """Workflow events, oldest first, or None when the scan can't be read."""
    try:
        rows = api.get(f"scans/{scan_id}/workflow")
    except Exception as exc:                                       # noqa: BLE001
        logger.warning("Could not read the workflow for %s: %s", scan_id, exc)
        return None
    rows = [dict(r) for r in rows] if isinstance(rows, list) else []
    return sorted(rows, key=lambda r: str(r.get("Timestamp") or ""))


def render_workflow(rows: list[dict]) -> str:
    width = max([len(str(r.get("Source") or "")) for r in rows] + [6])
    lines = [f"  {'Timestamp':<31} {'Source':<{width}}  Info"]
    for r in rows:
        lines.append(f"  {str(r.get('Timestamp') or ''):<31} {str(r.get('Source') or ''):<{width}}  "
                     f"{r.get('Info') or ''}")
    return "\n".join(lines)


def cmd_workflow(cfg, *, scan_ids: list[str], ids_file: str | None, out: str | None,
                 as_json: bool) -> int:
    from cxone import ApiClient
    ids = collect_scan_ids(scan_ids, ids_file)
    if not ids:
        print("Nothing selected: pass --scan-id (repeatable) or --scan-ids-file.")
        return 2
    target = None
    if out or len(ids) > 1:
        target = output_dir(out, default_name="scan-workflows")
        if target is None:
            print(REFUSED_INSIDE_SKILL, file=sys.stderr)
            return 2
    api = ApiClient(cfg)
    failed = 0
    for sid in ids:
        rows = fetch_workflow(api, sid)
        if rows is None:
            failed += 1
            continue
        if target is None:                                  # one scan, print it
            print(json.dumps(rows, indent=2) if as_json else render_workflow(rows))
            continue
        path = target / (f"{sid}.json" if as_json else f"{sid}.csv")
        with open_output(path, "w", newline="", encoding="utf-8") as handle:
            if as_json:
                json.dump(rows, handle, indent=2)
            else:
                writer = csv.DictWriter(handle, fieldnames=_COLUMNS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
        logger.info("Workflow for %s: %d event(s) -> %s", sid, len(rows), path)
    if target is not None:
        print(f"Wrote {len(ids) - failed} workflow file(s) to {target}"
              + (f"; {failed} scan(s) failed." if failed else "."))
    return 1 if failed else 0


def fetch_engine_log(api, scan_id: str, engine: str) -> tuple[str, bytes | None]:
    """('ok'|'missing'|'error', body). 404 means no log exists for this engine."""
    try:
        resp = api._session.get(f"{api.config.base_url.rstrip('/')}/api/logs/{scan_id}/{engine}",
                                headers=api._headers(), timeout=300)
    except Exception as exc:                                       # noqa: BLE001
        logger.warning("Engine log request failed for %s/%s: %s", scan_id, engine, exc)
        return "error", None
    if resp.status_code == 404:
        return "missing", None
    if not resp.ok:
        logger.warning("Engine log for %s/%s returned HTTP %s", scan_id, engine, resp.status_code)
        return "error", None
    return "ok", resp.content


def cmd_log(cfg, *, scan_ids: list[str], ids_file: str | None, engines: str | None,
            out: str | None) -> int:
    from cxone import ApiClient
    ids = collect_scan_ids(scan_ids, ids_file)
    if not ids:
        print("Nothing selected: pass --scan-id (repeatable) or --scan-ids-file.")
        return 2
    wanted = [e.lower() for e in split_csv(engines)] or list(LOG_ENGINES)
    unknown = [e for e in wanted if e not in LOG_ENGINES]
    if unknown:
        print(f"Unsupported engine(s): {', '.join(unknown)}. Only {', '.join(LOG_ENGINES)} keep "
              f"an engine log.")
        return 2
    target = output_dir(out, default_name="scan-logs")
    if target is None:
        print(REFUSED_INSIDE_SKILL, file=sys.stderr)
        return 2
    api = ApiClient(cfg)
    saved = missing = errors = 0
    for sid in ids:
        for engine in wanted:
            status, body = fetch_engine_log(api, sid, engine)
            if status == "ok":
                path = target / f"{sid}-{engine}.txt"
                with open_output(path, "wb") as handle:
                    handle.write(body)
                saved += 1
                logger.info("Saved %s log for %s (%d bytes) -> %s", engine, sid, len(body), path)
            elif status == "missing":
                missing += 1
                logger.info("No %s log for %s (not run, or aged out)", engine, sid)
            else:
                errors += 1
    print(f"Saved {saved} log(s) to {target}; {missing} not available"
          + (f"; {errors} failed." if errors else "."))
    return 1 if errors else 0
