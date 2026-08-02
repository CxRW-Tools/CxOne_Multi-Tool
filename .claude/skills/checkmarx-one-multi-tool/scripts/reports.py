"""
Report generation for Checkmarx One (AST plane).

Two async, poll-then-download flows:

  generate  PDF / JSON / CSV scan reports via the Improved Reports Service:
              POST /api/reports            -> {reportId}
              GET  /api/reports/{id}        -> {status, url}  (poll until completed)
              GET  /api/reports/{id}/download (or the returned url)
  sbom      CycloneDX / SPDX SBOM by reusing the SCA export 3-step already in
            ApiClient (post_sca_export / poll_sca_export / download_sca_export).

PDF is the CISO-friendly default; JSON is machine-readable for pipelines. Reports
target the latest Completed/Partial scan of a project unless a scan id is given.
`send-report-email` is a separate permission; we omit email unless asked.
"""

from __future__ import annotations

import sys
import json
import time
import logging
import argparse

import requests

from cxone import CxConfig, ApiClient
from cxone.api_client import USER_AGENT

logger = logging.getLogger("cxone.reports")

_POLL_INTERVAL = 5
# Termination is driven by the report STATUS, not the clock: _poll returns as soon
# as the report is `completed` and fails fast on `failed`. _TIMEOUT is only a
# backstop for the pathological case where the service never reaches a terminal
# status — set generously (60 min) so legitimately slow, findings-heavy renders
# (large PDFs especially) are never cut off prematurely.
_TIMEOUT = 3600
# Valid sections for the improved-scan-report (the API rejects anything else):
# scan-information, results-overview, scan-results, resolved-results, categories,
# vulnerability-details.
DEFAULT_SECTIONS = ["scan-information", "results-overview", "scan-results",
                    "categories", "vulnerability-details"]
# The report API expects capitalized scanner names from this exact set; apisec is
# not a supported report scanner. Map common aliases -> the accepted name.
REPORT_SCANNERS = ["SAST", "SCA", "KICS", "Microengines", "Containers"]
SCANNER_MAP = {"sast": "SAST", "sca": "SCA", "kics": "KICS", "iac": "KICS",
               "containers": "Containers", "container": "Containers",
               "microengines": "Microengines", "secrets": "Microengines",
               "secret": "Microengines"}
# fileFormat values the Improved Reports Service accepts.
FORMAT_MAP = {"pdf": "pdf", "json": "json", "csv": "csv"}
SBOM_FORMATS = {"cyclonedxjson": "CycloneDxJson", "cyclonedxxml": "CycloneDxXml",
                "spdxjson": "SpdxJson"}


class ReportsManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config

    # --------------------------------------------------- project/scan helpers
    def _find_project(self, name: str) -> dict | None:
        for p in self.api.paginate("projects", results_key="projects"):
            if p.get("name") == name:
                return p
        return None

    def _latest_scan(self, project_id: str) -> dict | None:
        return self.api.get_latest_scan_for_project(
            project_id, statuses=["Completed", "Partial"])

    # --------------------------------------------------------------- generate
    def generate(self, project_name: str, *, file_format: str = "pdf",
                 scan_id: str | None = None, scanners: list[str] | None = None,
                 sections: list[str] | None = None, output: str | None = None) -> str | None:
        proj = self._find_project(project_name)
        if not proj:
            logger.error("Project '%s' not found", project_name)
            return None
        pid = proj["id"]
        branch = proj.get("mainBranch")
        if not scan_id:
            scan = self._latest_scan(pid)
            if not scan:
                logger.error("No completed scan for '%s' to report on.", project_name)
                return None
            scan_id = scan["id"]
            branch = scan.get("branch") or branch

        fmt = FORMAT_MAP.get(file_format.lower())
        if not fmt:
            logger.error("Unsupported format '%s' (use pdf/json/csv)", file_format)
            return None

        # Normalize requested scanners to the report API's accepted, capitalized set
        # (dropping anything unsupported, e.g. apisec, with a warning).
        if scanners:
            mapped, dropped = [], []
            for s in scanners:
                name = SCANNER_MAP.get(s.lower())
                (mapped if name else dropped).append(name or s)
            if dropped:
                logger.warning("Ignoring scanners not supported by reports: %s", dropped)
            report_scanners = mapped or REPORT_SCANNERS
        else:
            report_scanners = REPORT_SCANNERS

        payload = {
            "reportName": "improved-scan-report",
            "reportType": "ui",
            "fileFormat": fmt,
            "data": {
                "scanId": scan_id,
                "projectId": pid,
                "branchName": branch,
                "sections": sections or DEFAULT_SECTIONS,
                "scanners": report_scanners,
                "host": "",
            },
        }
        if self.cfg.dry_run:
            logger.info("[dry-run] would request %s report for '%s' (scan %s): %s",
                        fmt, project_name, scan_id, json.dumps(payload))
            return None

        resp = self.api.post("reports", json_body=payload) or {}
        report_id = resp.get("reportId") or resp.get("id")
        if not report_id:
            logger.error("No reportId in response: %s", resp)
            return None
        logger.info("Report requested (%s) for '%s' — report %s", fmt, project_name, report_id)

        url = self._poll(report_id)
        if not url:
            return None
        out_path = output or f"{project_name.replace('/', '_')}-report.{fmt}"
        self._download(report_id, url, out_path)
        logger.info("Saved report to %s", out_path)
        return out_path

    def _poll(self, report_id: str) -> str | None:
        deadline = time.time() + _TIMEOUT
        while time.time() < deadline:
            status_resp = self.api.get(f"reports/{report_id}",
                                       params={"returnUrl": "true"}) or {}
            status = (status_resp.get("status") or "").lower()
            if status == "completed":
                return status_resp.get("url") or f"reports/{report_id}/download"
            if status == "failed":
                logger.error("Report %s failed: %s", report_id, status_resp)
                return None
            time.sleep(_POLL_INTERVAL)
        logger.error("Report %s timed out after %ds", report_id, _TIMEOUT)
        return None

    def _download(self, report_id: str, url: str, out_path: str) -> None:
        """Reports are binary (pdf/csv) or JSON; fetch raw bytes with auth and write
        to disk rather than going through ApiClient.get (which assumes JSON).

        The Authorization header is attached ONLY when the download host matches
        the configured AST host. The status endpoint may hand back a pre-signed
        URL on a different host (CDN/object storage); sending the bearer token
        there would leak the access token to a third party — pre-signed URLs
        carry their own auth and need no header.
        """
        from urllib.parse import urlsplit
        full = url if url.startswith("http") else f"{self.api._ast_base}/{url.lstrip('/')}"
        headers = {"Accept": "*/*", "User-Agent": USER_AGENT}
        own_host = urlsplit(self.api.config.base_url).hostname
        dl_host = urlsplit(full).hostname
        if dl_host and dl_host == own_host:
            headers["Authorization"] = f"Bearer {self.api.auth.token()}"
        else:
            logger.debug("Report %s download host %s differs from AST host %s; "
                         "fetching without Authorization (pre-signed URL).",
                         report_id, dl_host, own_host)
        r = requests.get(full, headers=headers, timeout=120)
        r.raise_for_status()
        with open(out_path, "wb") as fh:
            fh.write(r.content)

    # ------------------------------------------------------------------- sbom
    def sbom(self, project_name: str, *, sbom_format: str = "CycloneDxJson",
             scan_id: str | None = None, output: str | None = None) -> str | None:
        proj = self._find_project(project_name)
        if not proj:
            logger.error("Project '%s' not found", project_name)
            return None
        if not scan_id:
            scan = self._latest_scan(proj["id"])
            if not scan:
                logger.error("No completed scan for '%s' to build an SBOM from.", project_name)
                return None
            scan_id = scan["id"]
        fmt = SBOM_FORMATS.get(sbom_format.lower(), sbom_format)
        if self.cfg.dry_run:
            logger.info("[dry-run] would request %s SBOM for '%s' (scan %s)",
                        fmt, project_name, scan_id)
            return None
        # Reuse the SCA export 3-step; SBOM is one of its file formats. Pass the
        # same 60-min backstop so a large SBOM isn't cut off at the SCA-export
        # default (poll_sca_export also fails fast on a failed/error status).
        export_id = self.api.post_sca_export(scan_id, file_format=fmt)
        url = self.api.poll_sca_export(export_id, timeout=_TIMEOUT)
        data = self.api.download_sca_export(url)
        out_path = output or f"{project_name.replace('/', '_')}-sbom.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2) if isinstance(data, (dict, list)) else fh.write(str(data))
        logger.info("Saved SBOM to %s", out_path)
        return out_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="report")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="PDF/JSON/CSV scan report")
    g.add_argument("--project", required=True)
    g.add_argument("--format", default="pdf", choices=["pdf", "json", "csv"])
    g.add_argument("--scan-id", default=None, help="defaults to latest completed scan")
    g.add_argument("--scanners", default=None, help="comma-separated; default all")
    g.add_argument("--output", default=None)

    s = sub.add_parser("sbom", help="CycloneDX / SPDX SBOM (reuses SCA export)")
    s.add_argument("--project", required=True)
    s.add_argument("--format", default="CycloneDxJson",
                   choices=["CycloneDxJson", "CycloneDxXml", "SpdxJson"])
    s.add_argument("--scan-id", default=None)
    s.add_argument("--output", default=None)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    mgr = ReportsManager(ApiClient(cfg))

    if args.cmd == "generate":
        scanners = [s.strip() for s in (args.scanners or "").split(",") if s.strip()] or None
        out = mgr.generate(args.project, file_format=args.format, scan_id=args.scan_id,
                           scanners=scanners, output=args.output)
        return 0 if out or cfg.dry_run else 1
    if args.cmd == "sbom":
        out = mgr.sbom(args.project, sbom_format=args.format, scan_id=args.scan_id,
                       output=args.output)
        return 0 if out or cfg.dry_run else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
