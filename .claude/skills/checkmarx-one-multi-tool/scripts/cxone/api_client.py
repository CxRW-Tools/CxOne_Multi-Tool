"""
Checkmarx One API client (unified).

One client serves every module in the Multi-Tool. It addresses two API planes:

- AST / resource plane:  {base_url}/api/{endpoint}                  (use_iam=False)
- IAM / Keycloak admin:  {iam}/auth/admin/realms/{tenant}/{endpoint} (use_iam=True)

IAM holds users, groups, roles, memberships. AST holds projects, applications,
scans, results, configuration, repos-manager (onboarding), SCA export.

Features: bearer auth with auto-refresh, retry/backoff on transient errors,
offset/limit pagination, and the small set of resource helpers the scan and
triage engines rely on (project config, latest scan, repo lookup, SCM scan
trigger, and the 3-step async SCA export).
"""

from __future__ import annotations

import time
import logging
from typing import Any

import requests

from .config import CxConfig
from .auth import AuthManager

logger = logging.getLogger("cxone.api")

_RETRYABLE = {429, 500, 502, 503}
_MAX_RETRIES = 3
_BASE_BACKOFF = 1.0
_PAGE_LIMIT = 100
_SCA_POLL_INTERVAL = 5
# Generous backstop for async export generation. Termination is driven by the
# export STATUS (completed -> return; failed/error -> raise); this wall-clock cap
# only guards the pathological "never reaches a terminal status" case, so it is
# set high (60 min) to avoid cutting off legitimately slow exports. Kept in sync
# with reports._TIMEOUT — see that module's note.
_SCA_TIMEOUT = 3600

# `offset` does not mean the same thing on every CxOne endpoint:
#   - Most (projects, applications, scans): offset = number of *results* to skip.
#   - GET /api/results: offset = number of *pages* to skip (page index), with the
#     page size set by `limit`. (Confirmed in the OpenAPI spec param descriptions.)
# So for page-indexed endpoints we must step offset by 1 per page, not by `limit`;
# stepping by `limit` skips `limit` whole pages and returns nothing after page 0 —
# which silently truncates results to the first page. These are page-indexed:
_PAGE_INDEXED_ENDPOINTS = {"results"}
_RESULTS_MAX_LIMIT = 10000  # GET /api/results caps `limit` at 10000 per the spec

# CxOne records the request User-Agent as a scan's `userAgent` ("origin"). Override
# the requests default so scans are attributed to this tool, not `python-requests/x`.
USER_AGENT = "cxone-multitool"


class ApiResult(dict):
    """A response body that also remembers its HTTP status code.

    Many CxOne writes answer with an EMPTY body, so the body alone cannot tell
    you what happened: a 200, a 201 and a 204 all arrive here as the same dict.
    That is not hypothetical — SCA triage writes return `201 Created` with no
    content, and reading only the body led to a multi-turn misdiagnosis in which
    working writes were reported as a product defect (see spec/CLEANUP_NOTES.md,
    2026-08-01).

    This is a plain `dict` subclass, so every existing caller (`resp.get(...)`,
    `isinstance(resp, dict)`, `json.dumps`, `==` against a plain dict) behaves
    exactly as before. The status is carried alongside, as an attribute:

        resp = api.post("...")
        logger.info("write -> HTTP %s", resp.status_code)

    For bodies that are NOT dicts (a JSON list or scalar), there is nothing to
    attach an attribute to — use `with_status=True` to get `(body, status)`.
    """

    __slots__ = ("status_code",)

    def __init__(self, body: dict | None = None, status_code: int = 0):
        super().__init__(body or {})
        self.status_code = status_code


class ApiClient:
    def __init__(self, config: CxConfig, auth: AuthManager | None = None):
        self.config = config
        self.auth = auth or AuthManager(config)
        self._ast_base = config.base_url.rstrip("/") + "/api"
        self._iam_admin_base = (
            f"{config.resolved_iam_base_url}/auth/admin/realms/{config.tenant_name}"
        )
        # One pooled Session per client: scan/triage fan out across
        # CXONE_WORKERS threads, and per-request connections were paying a full
        # TLS handshake each call. requests.Session is thread-safe for
        # concurrent .request() use; per-request headers are passed explicitly
        # (below), never mutated on the session.
        self._session = requests.Session()

    # ------------------------------------------------------------------ URLs
    def _url(self, endpoint: str, use_iam: bool) -> str:
        ep = endpoint.lstrip("/")
        return f"{self._iam_admin_base}/{ep}" if use_iam else f"{self._ast_base}/{ep}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.auth.token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

    # ------------------------------------------------------------------ verbs
    @staticmethod
    def _body(r: requests.Response) -> Any:
        """Parse a response into its body, preserving the status code where possible.

        Dict bodies (and empty ones) come back as `ApiResult`, which carries
        `.status_code`. Lists and scalars are returned as-is — nothing to attach
        an attribute to; callers needing the status there pass `with_status=True`.
        """
        if not r.content:
            # Empty body: the status IS the entire result. `_location` carries the
            # created resource URL when the service sends one (the 201 pattern).
            return ApiResult({"_location": r.headers.get("Location", "")}, r.status_code)
        try:
            parsed = r.json()
        except ValueError:
            return ApiResult({"_raw": r.text}, r.status_code)
        return ApiResult(parsed, r.status_code) if isinstance(parsed, dict) else parsed

    def get(self, endpoint: str, params: dict | None = None, use_iam: bool = False,
            extra_headers: dict | None = None, with_status: bool = False) -> Any:
        r = self._request("GET", endpoint, use_iam, params=params,
                          extra_headers=extra_headers)
        body = self._body(r) if r.content else None
        return (body, r.status_code) if with_status else body

    def post(self, endpoint: str, json_body: Any = None, params: dict | None = None,
             use_iam: bool = False, extra_headers: dict | None = None,
             idempotent: bool = False, with_status: bool = False) -> Any:
        """POST. Retries only on 429 by default (a rate-limited request was not
        processed). Pass idempotent=True ONLY for endpoints where a replay
        converges (e.g. bulk predicate/state setters that write absolute values);
        creations and scan triggers must never set it.

        The result carries `.status_code` when it is a dict (see `ApiResult`);
        pass with_status=True to get an explicit `(body, status)` tuple."""
        r = self._request("POST", endpoint, use_iam, json=json_body, params=params,
                          extra_headers=extra_headers, idempotent=idempotent)
        body = self._body(r)
        return (body, r.status_code) if with_status else body

    def put(self, endpoint: str, json_body: Any = None, use_iam: bool = False,
            with_status: bool = False) -> Any:
        r = self._request("PUT", endpoint, use_iam, json=json_body)
        body = self._body(r)
        return (body, r.status_code) if with_status else body

    def patch(self, endpoint: str, json_body: Any = None, params: dict | None = None,
              use_iam: bool = False, with_status: bool = False) -> Any:
        r = self._request("PATCH", endpoint, use_iam, json=json_body, params=params)
        body = self._body(r)
        return (body, r.status_code) if with_status else body

    def delete(self, endpoint: str, use_iam: bool = False,
               with_status: bool = False) -> Any:
        r = self._request("DELETE", endpoint, use_iam)
        return r.status_code if with_status else None

    # ------------------------------------------------------------ pagination
    def paginate(self, endpoint: str, results_key: str, params: dict | None = None,
                 limit: int = _PAGE_LIMIT) -> list[Any]:
        page_indexed = endpoint.split("?", 1)[0].strip("/") in _PAGE_INDEXED_ENDPOINTS
        if page_indexed:
            limit = min(limit, _RESULTS_MAX_LIMIT)
        items: list[Any] = []
        offset = 0
        base = dict(params or {})
        while True:
            base.update({"limit": limit, "offset": offset})
            page = self.get(endpoint, params=base) or {}
            chunk = page.get(results_key) if isinstance(page, dict) else []
            chunk = chunk or []  # endpoint may return the key with a null value when empty
            items.extend(chunk)
            if len(chunk) < limit:
                break
            # page-indexed endpoints (results) advance one page at a time; the rest
            # treat offset as a record count and skip `limit` records per page.
            offset += 1 if page_indexed else limit
        return items

    def fetch_results(self, scan_id: str, *, result_type: str | None = None,
                      severities: list[str] | None = None,
                      states: list[str] | None = None) -> list[Any]:
        """All findings for a scan from GET /api/results, paged correctly (this
        endpoint's `offset` is a page index — see paginate / _PAGE_INDEXED_ENDPOINTS).

        NOTE: on this endpoint `type` is a *sort* option, not a filter, so we
        filter by each result's own `type` field client-side. severities/states
        are accepted as documented query filters.
        """
        params: dict = {"scan-id": scan_id}
        if severities:
            params["severity"] = severities
        if states:
            params["state"] = states
        results = self.paginate("results", results_key="results", params=params)
        if result_type:
            wanted = result_type.lower()
            results = [r for r in results if (r.get("type") or "").lower() == wanted]
        return results

    # -------------------------------------------------- project config helpers
    def get_project_configuration(self, project_id: str) -> list[dict]:
        """GET /api/configuration/project — flat list of {key,name,category,value,...}."""
        return self.get("configuration/project", params={"project-id": project_id}) or []

    def patch_project_configuration(self, project_id: str, params: list[dict]) -> None:
        """PATCH /api/configuration/project — set items, originLevel='Project'."""
        self._request("PATCH", "configuration/project", False,
                      json=params, params={"project-id": project_id})

    # --------------------------------------------------------- scan helpers
    def get_latest_scan_for_project(self, project_id: str, sort: str = "-created_at",
                                    limit: int = 1, statuses: list[str] | None = None) -> dict | None:
        params: dict = {"project-id": project_id, "sort": sort, "limit": limit,
                        "statuses": statuses if statuses is not None else ["Completed", "Partial"]}
        data = self.get("scans", params=params) or {}
        scans = data.get("scans") or []
        return scans[0] if scans else None

    def get_repo_by_id(self, repo_id: str | int, project_id: str) -> dict | None:
        try:
            return self.get(f"repos-manager/repo/{repo_id}", params={"projectId": project_id})
        except Exception:
            return None

    def post_project_scan_scm(self, scm_id: str | int, repo_org: str,
                              project_id: str, body: dict) -> Any:
        """POST /api/repos-manager/scms/{scmId}/orgs/{org}/repo/projectScan."""
        path = f"repos-manager/scms/{scm_id}/orgs/{repo_org}/repo/projectScan"
        return self.post(path, json_body=body, params={"projectId": project_id})

    # ----------------------------------------------------- SCA export (3-step)
    def post_sca_export(self, scan_id: str, file_format: str = "ScanReportJson") -> str:
        resp = self.post("sca/export/requests",
                         json_body={"ScanId": scan_id, "FileFormat": file_format}) or {}
        export_id = (resp.get("exportId") or resp.get("ExportId")
                     or resp.get("id") or resp.get("Id"))
        if not export_id:
            raise ValueError(f"No exportId in SCA export response: {resp}")
        return export_id

    def poll_sca_export(self, export_id: str, timeout: int = _SCA_TIMEOUT,
                        interval: int = _SCA_POLL_INTERVAL) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.get("sca/export/requests", params={"exportId": export_id}) or {}
            status = (resp.get("exportStatus") or resp.get("status") or "").lower()
            if status == "completed":
                url = resp.get("fileUrl")
                if not url:
                    raise ValueError(f"SCA export completed but no fileUrl: {resp}")
                return url
            if status in ("failed", "error"):
                raise RuntimeError(f"SCA export {export_id} failed: {resp}")
            time.sleep(interval)
        raise TimeoutError(f"SCA export {export_id} timed out after {timeout}s")

    def download_sca_export(self, file_url: str) -> Any:
        """Fetch a completed SCA export. Same-host URLs go through the client
        (bearer auth); a foreign host means a pre-signed URL, which carries its
        own auth — fetch it bare rather than leaking the token or mangling it
        onto the AST base."""
        from urllib.parse import urlsplit
        if file_url.startswith("http"):
            own_host = urlsplit(self.config.base_url).hostname
            if urlsplit(file_url).hostname != own_host:
                r = requests.get(file_url, timeout=120,
                                 headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
                r.raise_for_status()
                try:
                    return r.json()
                except ValueError:
                    return r.text
        path = file_url.split("/api/", 1)[1] if "/api/" in file_url else file_url.lstrip("/")
        return self.get(path)

    # ------------------------------------------------------- analytics KPIs
    def query_analytics_kpi(self, kpi: str, *, start_date: str | None = None,
                            end_date: str | None = None, **filters: Any) -> Any:
        """POST /api/data_analytics/analyticsAPI/v1 — server-side aggregated
        KPIs (severity/state/status distributions, aging, most-common, etc.)
        across the whole tenant in one call, instead of walking every
        project's /api/results client-side. See references/cxone-api.md for
        the KPI catalog and the gotchas below.

        Two required-in-practice fields the docs describe as optional:
          - endDate: the API 400s with "endDate cannot be null" without it,
            despite the spec defaulting it to "now". We default it here.
          - startDate: must be within the last year, or a 400 follows
            ("startDate must not be less than 1 year from today's date").
            We default it to 364 days back; pass start_date explicitly for a
            narrower window.
        Also note Content-Type must be 'application/json; version=1.0', not
        the client's default 'application/json' — set below.
        """
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        body: dict[str, Any] = {
            "kpi": kpi,
            "startDate": start_date or (now - timedelta(days=364)).strftime("%Y-%m-%dT%H:%M:%S"),
            "endDate": end_date or now.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        body.update({k: v for k, v in filters.items() if v is not None})
        return self.post(
            "data_analytics/analyticsAPI/v1",
            json_body=body,
            extra_headers={"Content-Type": "application/json; version=1.0"},
            idempotent=True,  # read-only query; safe to retry on 5xx
        )

    # --------------------------------------------------------- internals
    # Verbs the server processes idempotently (safe to blind-retry on 5xx or a
    # dropped connection). PATCH is included because every PATCH in this tool
    # sets absolute values (project config items), so a replay converges.
    # POST is NOT here: a 500/timeout can arrive AFTER the server created the
    # resource or queued the scan, so a blind retry double-creates. POST retries
    # only on 429 (rate-limited = provably not processed), unless the caller
    # passes idempotent=True for endpoints known to tolerate replay.
    _IDEMPOTENT_METHODS = {"GET", "PUT", "DELETE", "PATCH"}

    def _request(self, method: str, endpoint: str, use_iam: bool, **kwargs) -> requests.Response:
        url = self._url(endpoint, use_iam)
        # Some services (micro-engines, containers/triage) require a versioned Accept
        # header; callers pass extra_headers to override/extend the defaults.
        extra_headers = kwargs.pop("extra_headers", None)
        idempotent = kwargs.pop("idempotent", method.upper() in self._IDEMPOTENT_METHODS)
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("%s %s%s", method, "IAM:" if use_iam else "", endpoint)
                resp = self._session.request(method, url, headers=headers, timeout=60, **kwargs)
                if logger.isEnabledFor(logging.DEBUG):
                    # Log the STATUS, not just the request. An empty 201 body is
                    # otherwise invisible, and "did this write land?" has to be
                    # answerable from --debug output alone.
                    logger.debug("%s %s%s -> HTTP %d%s", method, "IAM:" if use_iam else "",
                                 endpoint, resp.status_code,
                                 "" if resp.content else " (empty body)")
                retryable = resp.status_code == 429 or (
                    idempotent and resp.status_code in _RETRYABLE)
                if retryable and attempt < _MAX_RETRIES - 1:
                    wait = _BASE_BACKOFF * (2 ** attempt)
                    logger.warning("HTTP %d on %s %s; retry in %.1fs",
                                   resp.status_code, method, endpoint, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                # A definitive HTTP status is not worth replaying: the retryable
                # codes already `continue`d above, so anything raising here
                # (404/400/403/...) will answer identically on a replay. Without
                # this, every 404 on an idempotent GET costs 3 requests and ~3s of
                # backoff — and 404 is a NORMAL state for the AI Assist reads
                # ("no analysis for this group yet"), which poll in a loop.
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status is not None and status not in _RETRYABLE:
                    raise
                # A dropped connection / timeout on a non-idempotent request may
                # have been processed server-side — surface it instead of replaying.
                if idempotent and attempt < _MAX_RETRIES - 1:
                    time.sleep(_BASE_BACKOFF * (2 ** attempt))
                else:
                    raise
        raise last_exc  # type: ignore[misc]
