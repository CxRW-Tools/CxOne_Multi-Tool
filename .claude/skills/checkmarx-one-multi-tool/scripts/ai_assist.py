"""
Checkmarx Assist — AI Triage Assist and AI Remediation Assist (AST plane).

Two agentic services, each on its own gateway prefix:

    POST   /api/ai-triage/triage                              initiate triage
    GET    /api/ai-triage/v2/triage/{project_id}/{group_id}   read result (V2)
    GET    /api/ai-triage/triage/{project_id}/{group_id}      read result (V1)
    POST   /api/ai-triage/triage/{project_id}/{group_id}/discard
    POST   /api/remediation/remediate                         initiate remediation
    GET    /api/remediation/remediation-details/{scan_id}/{result_id}
    GET    /api/remediation/remediation-details/{scan_id}?result_ids=...

Both are asynchronous: the POST returns 202 and the GET is polled until the
analysis lands (``--wait`` does the polling for you).

Selection is the hard part, not the HTTP. Both POSTs are keyed by scan id +
result id, and triage reads back by project id + group id — none of which are
visible in the UI. ``ops/findings.FindingResolver`` turns "the SQLi finding in
project X" into those ids; see that module for the four live-verified traps it
absorbs (``alternateId`` vs ``id``, path encoding, initiate/retrieve key
asymmetry, and SAST grouping mode). ``ai-assist find`` prints the resolved ids for eyeballing.

**These endpoints consume AI credits per finding** (HTTP 402 when exhausted),
so initiating requires an explicit selection and is capped by ``--limit``
(default 10). Whole-scan submission is possible but must be asked for by name
with ``--all``.
"""

from __future__ import annotations

import sys
import json
import time
import logging
import argparse

import requests

from cxone import CxConfig, ApiClient
from ops.findings import (
    FindingRef, FindingResolver, buckets_from, encode_path_segment, AI_ENGINES,
)

logger = logging.getLogger("cxone.ai_assist")

# Both services are versioned through the Accept header, and only v1.0 exists.
# The live FastAPI apps tolerate a plain application/json, but the documented
# contract asks for this and costs nothing to honor.
AI_HEADERS = {"Accept": "*/*; version=1.0"}

# Credit-consuming calls are capped unless the caller opts out explicitly.
DEFAULT_LIMIT = 10

# Credit cost per Assist action, DERIVED from live consumption data rather than
# published anywhere: on 2026-07-31 this tenant's `GET /api/credits/consumption`
# reported 424 triage + 72 remediation transactions against 640 credits used,
# and `creditsUsed == 1*triage + 3*remediation` held for all 38 users
# individually. Treat as an empirical model, not a contract — re-derive with
# `ai-assist credits --by-user` if totals ever stop reconciling.
CREDIT_COST = {"triage": 1, "remediation": 3}

# UNRESOLVED, and it matters for any estimate: consumption reports "transactions"
# without saying whether one transaction is one FINDING or one REQUEST. A single
# POST carries many resultIDs, so per-finding billing costs len(findings) x the
# per-action cost while per-request billing costs exactly one. Estimates below are
# therefore printed as an upper bound (per-finding) with the lower bound named.
# Settle it by running one small live action and diffing `used` before/after.

# Polling for --wait. Agentic analysis is slow (minutes), so the interval is
# generous and the ceiling is high; termination is driven by status, not time.
_POLL_INTERVAL = 15
_POLL_TIMEOUT = 900

_TRIAGE_TERMINAL = {"VULNERABLE", "PROPOSED_NOT_EXPLOITABLE", "UNCERTAIN",
                    "RISK_ACCEPTED", "NOT_TRIAGED", "FAILED"}
_JOB_PENDING = {"IN_PROGRESS"}


def _http_hint(exc: requests.exceptions.HTTPError) -> str:
    """Turn the two AI-specific status codes into an actionable sentence.

    402 and 403 are the ones an SE will actually hit, and neither is obvious
    from the raw body — 402 is tenant AI credit exhaustion (not a bad request),
    403 means the capability is switched off for the tenant rather than a
    permissions problem with the API key.
    """
    resp = exc.response
    code = resp.status_code if resp is not None else None
    body = ""
    if resp is not None:
        try:
            body = json.dumps(resp.json())
        except ValueError:
            body = (resp.text or "")[:300]
    if code == 402:
        return ("HTTP 402 — insufficient AI consumption credits on this tenant. "
                "Checkmarx Assist bills per finding analyzed; top up or reduce "
                f"the selection. Body: {body}")
    if code == 403:
        return ("HTTP 403 — Checkmarx Assist is not enabled for this tenant (or "
                "the API key's roles do not permit it). This is a tenant "
                f"feature flag, not a bad request. Body: {body}")
    if code == 400:
        return (f"HTTP 400 — the service rejected the selection. The usual cause is a "
                f"result id that is not in this scan for that engine, or an `id` "
                f"passed where `alternateId` was required. Body: {body}")
    if code == 404:
        return f"HTTP 404 — no analysis exists for that project/group (or scan/result) yet. Body: {body}"
    return f"HTTP {code}. Body: {body}"


class AiAssistManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config
        self.resolver = FindingResolver(api)

    # --------------------------------------------------------------- helpers
    def _select(self, project: str, args, *, require_selector: bool) -> list[FindingRef] | None:
        """Resolve the CLI's selection flags into FindingRefs, enforcing the cap.

        Returns None (not []) when the caller must stop — no selector given on a
        credit-consuming verb, or the project/scan could not be resolved.
        """
        explicit_ids = [s.strip() for s in (args.result_ids or "").split(",") if s.strip()]
        selectors = [args.match, args.severity, args.state, args.engine or None,
                     explicit_ids or None, getattr(args, "all", False) or None]
        if require_selector and not any(selectors):
            logger.error(
                "Refusing to submit every finding in the scan implicitly. Narrow it "
                "(--match / --severity / --engine / --result-ids) or say so explicitly "
                "with --all. Each finding consumes AI credits.")
            return None

        refs = self.resolver.find(
            project,
            engine=args.engine,
            match=args.match,
            severities=[s.strip() for s in (args.severity or "").split(",") if s.strip()] or None,
            states=[s.strip() for s in (args.state or "").split(",") if s.strip()] or None,
            result_ids=explicit_ids or None,
            scan_id=getattr(args, "scan_id", None),
        )
        if not refs:
            logger.info("No matching SAST/SCA findings (Checkmarx Assist supports %s only).",
                        "/".join(e.upper() for e in AI_ENGINES))
            return []

        cap = getattr(args, "limit", DEFAULT_LIMIT)
        if cap is not None and len(refs) > cap:
            logger.warning("%d findings matched; submitting the %d most severe (--limit %d). "
                           "Raise --limit to include more.", len(refs), cap, cap)
            refs = refs[:cap]
        return refs

    # --------------------------------------------------------------- credits
    def credits_info(self) -> dict | None:
        """GET /api/credits/info — tenant AI credit balance and enforcement.

        Shape: {available, total, used, actionsAvailable, actionsPerformed,
        enforcement:{state, consumptionPct, warningThresholdPct,
        cutoffThresholdPct}}. Undocumented anywhere (found by probing the
        gateway); read-only, so a failure here must never block the caller.
        """
        try:
            return self.api.get("credits/info")
        except requests.exceptions.RequestException as exc:
            logger.debug("credits/info unavailable: %s", exc)
            return None

    def credits_consumption(self) -> list[dict]:
        """GET /api/credits/consumption — per-user credits and action counts."""
        items: list[dict] = []
        page = 1
        while True:
            body = self.api.get("credits/consumption", params={"page": page}) or {}
            items.extend(body.get("items") or [])
            if page >= (body.get("totalPages") or 1):
                break
            page += 1
        return items

    def _preflight_credits(self, refs: list[FindingRef], action: str) -> dict | None:
        """Report the balance and this action's cost BEFORE spending anything.

        Printed on dry-runs too, so the confirmation the user gives is informed
        by the price. Returns the info dict (or None when unavailable).
        """
        unit = CREDIT_COST.get(action, 1)
        upper = unit * len(refs)
        info = self.credits_info()
        if info is None:
            logger.warning("Could not read the credit balance (GET /api/credits/info) — "
                           "proceeding blind. Estimated cost: up to %d credit(s) "
                           "(%d finding(s) x %d for %s).", upper, len(refs), unit, action)
            return None
        available = info.get("available")
        logger.info("AI credits: %s available of %s (%s%% used). This %s: up to %d "
                    "credit(s) — %d finding(s) x %d if billed per finding, %d if the "
                    "whole request bills as one.",
                    available, info.get("total"),
                    (info.get("enforcement") or {}).get("consumptionPct"),
                    action, upper, len(refs), unit, unit)
        if isinstance(available, (int, float)) and upper > available:
            logger.warning("Estimated cost (%d) EXCEEDS the %s credits available — the "
                           "service will return HTTP 402 once the balance runs out. "
                           "Reduce --limit or top up first.", upper, available)
        return info

    def credits(self, args) -> int:
        """Show the tenant's AI credit balance and what has consumed it."""
        info = self.credits_info()
        if info is None:
            logger.error("Could not read GET /api/credits/info on this tenant.")
            return 1
        if args.json:
            out = {"info": info}
            if args.by_user:
                out["consumption"] = self.credits_consumption()
            print(json.dumps(out, indent=2))
            return 0
        enf = info.get("enforcement") or {}
        logger.info("AI credits (Checkmarx Assist)")
        logger.info("  available : %s", info.get("available"))
        logger.info("  used      : %s of %s (%s%%)", info.get("used"), info.get("total"),
                    enf.get("consumptionPct"))
        logger.info("  actions   : %s performed, %s available (the platform's own "
                    "estimate, which assumes a blended ~5 credits/action)",
                    info.get("actionsPerformed"), info.get("actionsAvailable"))
        logger.info("  enforcement: state=%s warning=%s%% cutoff=%s%%",
                    enf.get("state"), enf.get("warningThresholdPct"),
                    enf.get("cutoffThresholdPct"))
        logger.info("  unit cost : %s", ", ".join(f"{k}={v}" for k, v in CREDIT_COST.items())
                    + " (derived from live consumption, not published)")
        items = self.credits_consumption()
        totals: dict[str, int] = {}
        for item in items:
            for act in (item.get("actionsPerformed") or {}).get("actions") or []:
                totals[act.get("actionType")] = (totals.get(act.get("actionType")) or 0) \
                    + (act.get("transactionCount") or 0)
        if totals:
            logger.info("  consumed by action type: %s",
                        ", ".join(f"{k}={v}" for k, v in sorted(totals.items())))
        logger.info("  %d user(s) have consumed credits", len(items))
        if args.by_user:
            # Names/emails are only printed on explicit request — this is
            # per-person activity data, not something to spray into a log.
            for item in sorted(items, key=lambda i: -(i.get("creditsUsed") or 0)):
                acts = {a.get("actionType"): a.get("transactionCount")
                        for a in (item.get("actionsPerformed") or {}).get("actions") or []}
                logger.info("    %-40s %4s credits  %s",
                            item.get("userEmail") or item.get("name"),
                            item.get("creditsUsed"), acts)
        return 0

    def _report_spend(self, before: dict | None, action: str) -> None:
        """State what the call actually cost, by re-reading the balance.

        Measure with `available`, NOT `used`. Live on 2026-07-31 a 4-finding
        triage dropped `available` 360 -> 356 immediately while `used` stayed at
        640 and `actionsPerformed` stayed at 496 — the platform reserves the
        credits up front and only settles `used`/`actionsPerformed` later. Diffing
        `used` (the first version of this) therefore reported "0 credits spent"
        for a call that had just cost 4.
        """
        if not before:
            return
        after = self.credits_info()
        if not after:
            return
        avail_before, avail_after = before.get("available"), after.get("available")
        if isinstance(avail_before, (int, float)) and isinstance(avail_after, (int, float)):
            logger.info("Credits reserved for this %s: %s (available %s -> %s of %s).",
                        action, avail_before - avail_after, avail_before, avail_after,
                        after.get("total"))
        used_delta = (after.get("used") or 0) - (before.get("used") or 0)
        if used_delta:
            logger.info("  settled `used`: +%s", used_delta)
        else:
            logger.debug("`used` unchanged (%s) — settles asynchronously; `available` "
                         "is the live figure.", after.get("used"))

    @staticmethod
    def _print_refs(refs: list[FindingRef], as_json: bool = False) -> None:
        if as_json:
            print(json.dumps([r.to_dict() for r in refs], indent=2))
            return
        for ref in refs:
            logger.info(ref.describe())

    # ------------------------------------------------------------------ find
    def find(self, project: str, args) -> int:
        """Read-only: show the ids the Assist APIs need for matching findings."""
        refs = self._select(project, args, require_selector=False)
        if refs is None:
            return 1
        if not refs:
            return 0
        logger.info("%d finding(s) in '%s' (scan %s):",
                    len(refs), refs[0].project_name, refs[0].scan_id)
        self._print_refs(refs, args.json)
        return 0

    # ---------------------------------------------------------------- triage
    def triage(self, project: str, args) -> int:
        refs = self._select(project, args, require_selector=True)
        if refs is None:
            return 1
        if not refs:
            return 0
        scan_id = refs[0].scan_id
        buckets = buckets_from(refs)
        payload: dict = {"scanID": scan_id, "projectID": refs[0].project_id,
                         "buckets": buckets}
        if args.force:
            payload["force"] = True

        logger.info("AI Triage Assist — project '%s', scan %s", refs[0].project_name, scan_id)
        for ref in refs:
            logger.info("  [%s] %s %s", ref.severity, ref.engine.upper(), ref.label)
        before_credits = self._preflight_credits(refs, "triage")
        if self.cfg.dry_run:
            logger.info("[dry-run] would POST /api/ai-triage/triage: %s", json.dumps(payload))
            return 0

        try:
            resp = self.api.post("ai-triage/triage", payload,
                                 extra_headers=AI_HEADERS) or {}
        except requests.exceptions.HTTPError as exc:
            logger.error("AI Triage request failed. %s", _http_hint(exc))
            return 1
        if resp.get("published") is False:
            logger.info("Duplicate request — an identical triage is already %s "
                        "(nothing new was enqueued; pass --force to re-run).",
                        resp.get("existingTriageState") or "in flight")
        else:
            logger.info("Accepted: triageID=%s (%d finding(s) submitted)",
                        resp.get("triageID") or "?", len(refs))
            self._report_spend(before_credits, "triage")
        if args.wait:
            return self._wait_triage(refs, args)
        logger.info("Read results with: ai-assist triage-status --project \"%s\"%s",
                    refs[0].project_name, f" --match \"{args.match}\"" if args.match else "")
        return 0

    def _wait_triage(self, refs: list[FindingRef], args) -> int:
        """Poll the submitted findings' groups until their verdicts land.

        One analysis covers a whole group, so duplicate group ids are collapsed
        — polling the same group once per member would just multiply the reads.
        """
        seen: set[str] = set()
        for ref in refs:
            if not ref.group_id or ref.group_id in seen:
                continue
            seen.add(ref.group_id)
            body = self._wait_for(
                lambda: self._get_triage_any(ref.project_id, ref.group_candidates(),
                                             v1=args.v1),
                self._triage_done, True, args.timeout, ref.label)
            if body is None:
                logger.info("%s: no analysis returned yet (group %s)", ref.label, ref.group_id)
            elif args.json:
                print(json.dumps(body, indent=2))
            else:
                self._print_triage(ref.label, body)
        return 0

    def _get_triage_any(self, project_id: str, group_ids: list[str], *,
                        v1: bool = False) -> dict | None:
        """Try each candidate group id until one returns an analysis.

        SAST group ids depend on the tenant's grouping mode and a wrong one 404s
        exactly like "still running" (this cost a full 10-minute poll live before
        it was understood). Reads are free, so try both rather than trust
        detection.
        """
        for gid in group_ids:
            body = self._get_triage(project_id, gid, v1=v1)
            if body is not None:
                return body
        return None

    def _get_triage(self, project_id: str, group_id: str, *, v1: bool = False) -> dict | None:
        """GET one triage result. V2 by default, transparently falling back to V1.

        V2 is undocumented in the published Stoplight YAMLs but live on the
        tenant and returns a richer reasoning trace; V1 is the documented shape.
        A 404 means "no analysis yet", which is normal while a job is running.
        """
        pid, gid = encode_path_segment(project_id), encode_path_segment(group_id)
        paths = [f"ai-triage/triage/{pid}/{gid}"] if v1 else [
            f"ai-triage/v2/triage/{pid}/{gid}", f"ai-triage/triage/{pid}/{gid}"]
        for i, path in enumerate(paths):
            try:
                return self.api.get(path, extra_headers=AI_HEADERS)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404 and i == len(paths) - 1:
                    return None
                if status == 404:
                    logger.debug("V2 triage read 404'd; falling back to V1")
                    continue
                logger.error("Triage read failed. %s", _http_hint(exc))
                return None
        return None

    def triage_status(self, project: str, args) -> int:
        """Read AI triage verdicts back, by group id (derived or explicit)."""
        if args.group_id:
            project_id = args.project_id
            if not project_id:
                proj = self.resolver.resolve_project(project) if project else None
                if not proj:
                    logger.error("--group-id needs a project: pass --project or --project-id.")
                    return 1
                project_id = proj["id"]
            pairs = [(project_id, [args.group_id], args.group_id)]
        else:
            refs = self._select(project, args, require_selector=False)
            if refs is None:
                return 1
            if not refs:
                return 0
            pairs = []
            seen = set()
            for ref in refs:
                if not ref.group_candidates():
                    logger.warning("No group id derivable for %s (%s) — cannot read its "
                                   "triage.", ref.label, ref.engine)
                    continue
                if ref.group_id in seen:      # one analysis covers the whole group
                    continue
                seen.add(ref.group_id)
                pairs.append((ref.project_id, ref.group_candidates(), ref.label))

        if not pairs:
            return 0
        rc = 0
        for project_id, group_ids, label in pairs:
            body = self._wait_for(
                lambda: self._get_triage_any(project_id, group_ids, v1=args.v1),
                self._triage_done, args.wait, args.timeout, label)
            if body is None:
                logger.info("%s: no AI triage analysis found yet (group %s)",
                            label, ", ".join(group_ids))
                rc = rc or 0
                continue
            if args.json:
                print(json.dumps(body, indent=2))
            else:
                self._print_triage(label, body)
        return rc

    @staticmethod
    def _triage_done(body: dict | None) -> bool:
        if not body:
            return False
        job = (body.get("jobStatus") or "").upper()
        if job in _JOB_PENDING:
            return False
        status = (body.get("triageStatus") or "").upper()
        return bool(status) or job == "FAILED"

    @staticmethod
    def _print_triage(label: str, body: dict) -> None:
        job = (body.get("jobStatus") or "").upper()
        if job in _JOB_PENDING or (job and not body.get("triageStatus")):
            logger.info("%s: %s", label, job or "IN_PROGRESS")
            return
        analysis = body.get("analysis") or {}
        conf = (analysis.get("confidence") or {})
        logger.info("%s", label)
        logger.info("  verdict       : %s", body.get("triageStatus"))
        logger.info("  reachability  : %s", body.get("reachabilityStatus"))
        logger.info("  exploitability: %s", body.get("exploitabilityStatus"))
        if body.get("attackabilityStatus"):
            logger.info("  attackability : %s", body.get("attackabilityStatus"))
        if conf.get("score") is not None:
            logger.info("  confidence    : %s", conf.get("score"))
        if body.get("summary"):
            logger.info("  summary       : %s", str(body["summary"]).replace("\n", " ")[:400])
        if body.get("triagedAt"):
            logger.info("  triaged at    : %s", body["triagedAt"])

    def discard(self, project: str, args) -> int:
        """Discard an AI triage result for a group (mutating)."""
        proj = self.resolver.resolve_project(project) if project else None
        project_id = args.project_id or (proj["id"] if proj else None)
        if not project_id or not args.group_id:
            logger.error("discard needs --group-id and a project (--project or --project-id).")
            return 1
        path = (f"ai-triage/triage/{encode_path_segment(project_id)}/"
                f"{encode_path_segment(args.group_id)}/discard")
        if self.cfg.dry_run:
            logger.info("[dry-run] would POST /api/%s (discard AI triage for group %s)",
                        path, args.group_id)
            return 0
        try:
            self.api.post(path, extra_headers=AI_HEADERS)
        except requests.exceptions.HTTPError as exc:
            logger.error("Discard failed. %s", _http_hint(exc))
            return 1
        logger.info("Discarded AI triage for group %s", args.group_id)
        return 0

    # ----------------------------------------------------------- remediation
    def remediate(self, project: str, args) -> int:
        refs = self._select(project, args, require_selector=True)
        if refs is None:
            return 1
        if not refs:
            return 0
        scan_id = refs[0].scan_id
        payload = {"scanID": scan_id, "projectID": refs[0].project_id,
                   "buckets": buckets_from(refs)}

        logger.info("AI Remediation Assist — project '%s', scan %s",
                    refs[0].project_name, scan_id)
        for ref in refs:
            logger.info("  [%s] %s %s", ref.severity, ref.engine.upper(), ref.label)
        before_credits = self._preflight_credits(refs, "remediation")
        if self.cfg.dry_run:
            logger.info("[dry-run] would POST /api/remediation/remediate: %s", json.dumps(payload))
            return 0

        try:
            resp = self.api.post("remediation/remediate", payload,
                                 extra_headers=AI_HEADERS) or {}
        except requests.exceptions.HTTPError as exc:
            logger.error("AI Remediation request failed. %s", _http_hint(exc))
            return 1
        if resp.get("published") is False:
            logger.info("Duplicate request — identical remediation already %s.",
                        resp.get("existingState") or "in flight")
        else:
            logger.info("Accepted: remediationJobId=%s (%d finding(s) submitted)",
                        resp.get("remediationJobId") or "?", len(refs))
            self._report_spend(before_credits, "remediation")
        if args.wait:
            return self.remediation_details(project, args)
        logger.info("Read results with: ai-assist remediation-details --project \"%s\"%s",
                    refs[0].project_name, f" --match \"{args.match}\"" if args.match else "")
        return 0

    def _get_remediation(self, scan_id: str, result_id: str) -> dict | None:
        path = (f"remediation/remediation-details/{encode_path_segment(scan_id)}/"
                f"{encode_path_segment(result_id)}")
        try:
            return self.api.get(path, extra_headers=AI_HEADERS)
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status == 404:
                return None
            logger.error("Remediation read failed. %s", _http_hint(exc))
            return None

    def remediation_details(self, project: str, args) -> int:
        explicit_ids = [s.strip() for s in (args.result_ids or "").split(",") if s.strip()]
        if getattr(args, "scan_id", None) and explicit_ids:
            targets = [(args.scan_id, rid, rid) for rid in explicit_ids]
        else:
            refs = self._select(project, args, require_selector=False)
            if refs is None:
                return 1
            if not refs:
                return 0
            targets = [(r.scan_id, r.result_id, r.label) for r in refs]

        for scan_id, result_id, label in targets:
            body = self._wait_for(lambda: self._get_remediation(scan_id, result_id),
                                  self._remediation_done, args.wait, args.timeout, label)
            if body is None:
                logger.info("%s: no remediation found yet (result %s)", label, result_id)
                continue
            if args.json:
                print(json.dumps(body, indent=2))
            else:
                self._print_remediation(label, body)
        return 0

    @staticmethod
    def _remediation_done(body: dict | None) -> bool:
        if not body:
            return False
        for item in body.get("results") or []:
            if (item.get("jobStatus") or "").upper() in _JOB_PENDING:
                return False
            if item.get("data"):
                return True
        return bool(body.get("results"))

    @staticmethod
    def _print_remediation(label: str, body: dict) -> None:
        logger.info("%s (scan %s)", label, body.get("scanID"))
        for item in body.get("results") or []:
            job = (item.get("jobStatus") or "").upper()
            if job:
                logger.info("  status: %s", job)
                continue
            data = item.get("data") or {}
            analysis = data.get("analysis") or {}
            if data.get("summary"):
                logger.info("  summary : %s", str(data["summary"]).replace("\n", " ")[:400])
            for key in ("what", "why", "how"):
                if analysis.get(key):
                    logger.info("  %-8s: %s", key, str(analysis[key]).replace("\n", " ")[:300])
            if data.get("pr_title"):
                logger.info("  PR title: %s", data["pr_title"])
            changes = data.get("file_changes") or []
            if changes:
                logger.info("  %d file change(s):", len(changes))
                for ch in changes:
                    logger.info("    - %s", ch.get("file_path"))
            tests = (data.get("test_creation") or {}).get("total_tests_created")
            if tests:
                logger.info("  tests generated: %s", tests)
            auto_pr = item.get("autoPr") or {}
            if auto_pr.get("url"):
                logger.info("  pull request: %s", auto_pr["url"])
            if data.get("error"):
                logger.warning("  error: %s", data["error"])

    # ---------------------------------------------------------------- polling
    @staticmethod
    def _wait_for(fetch, done, wait: bool, timeout: int | None, label: str):
        """Call ``fetch`` once, or poll it until ``done`` when ``wait`` is set."""
        body = fetch()
        if not wait or done(body):
            return body
        deadline = time.time() + (timeout or _POLL_TIMEOUT)
        while time.time() < deadline:
            time.sleep(_POLL_INTERVAL)
            body = fetch()
            if done(body):
                return body
            logger.info("  %s: still processing…", label)
        logger.warning("%s: timed out after %ss — the job may still be running; "
                       "re-run the same command to check again.",
                       label, timeout or _POLL_TIMEOUT)
        return body


def _add_selection_flags(sp, *, with_limit: bool = True) -> None:
    sp.add_argument("--project", help="project name (exact, or unique substring)")
    sp.add_argument("--match", default=None,
                    help="case-insensitive substring of the finding name/description, "
                         "e.g. --match \"SQL Injection\"")
    sp.add_argument("--engine", default=None, choices=["sast", "sca"],
                    help="Checkmarx Assist supports SAST and SCA only")
    sp.add_argument("--severity", default=None, help="comma-separated: Critical,High,Medium,Low")
    sp.add_argument("--state", default=None, help="comma-separated triage states")
    sp.add_argument("--result-ids", default=None,
                    help="comma-separated result ids (the alternateId values)")
    sp.add_argument("--scan-id", default=None, help="override the latest-scan default")
    sp.add_argument("--json", action="store_true", help="emit raw JSON")
    if with_limit:
        sp.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"cap on findings submitted (default {DEFAULT_LIMIT}); "
                             "each one consumes AI credits")
        sp.add_argument("--all", action="store_true",
                        help="explicitly act on every matching finding (still capped "
                             "by --limit unless you raise it)")


def _add_wait_flags(sp) -> None:
    sp.add_argument("--wait", action="store_true", help="poll until the analysis completes")
    sp.add_argument("--timeout", type=int, default=_POLL_TIMEOUT,
                    help=f"seconds to poll with --wait (default {_POLL_TIMEOUT})")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ai-assist",
        description="Checkmarx Assist: AI Triage Assist and AI Remediation Assist.")
    p.add_argument("--env", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("find", help="show the scan/result/group ids for matching findings")
    _add_selection_flags(f, with_limit=False)
    f.add_argument("--limit", type=int, default=25)

    t = sub.add_parser("triage", help="initiate AI Triage Assist (consumes AI credits)")
    _add_selection_flags(t)
    t.add_argument("--force", action="store_true",
                   help="bypass idempotency and re-run an identical triage")
    t.add_argument("--v1", action="store_true",
                   help="read results back with the documented V1 shape (with --wait)")
    _add_wait_flags(t)

    ts = sub.add_parser("triage-status", help="retrieve AI triage verdicts")
    _add_selection_flags(ts, with_limit=False)
    ts.add_argument("--limit", type=int, default=25)
    ts.add_argument("--group-id", default=None, help="read one group directly")
    ts.add_argument("--project-id", default=None, help="project UUID (with --group-id)")
    ts.add_argument("--v1", action="store_true",
                    help="use the documented V1 shape instead of V2")
    _add_wait_flags(ts)

    r = sub.add_parser("remediate", help="initiate AI Remediation Assist (consumes AI credits)")
    _add_selection_flags(r)
    _add_wait_flags(r)

    rd = sub.add_parser("remediation-details", help="retrieve AI remediation output")
    _add_selection_flags(rd, with_limit=False)
    rd.add_argument("--limit", type=int, default=25)
    _add_wait_flags(rd)

    c = sub.add_parser("credits", help="tenant AI credit balance and consumption")
    c.add_argument("--by-user", action="store_true",
                   help="also list per-user consumption (prints user emails)")
    c.add_argument("--json", action="store_true")

    d = sub.add_parser("discard", help="discard an AI triage result for a group")
    d.add_argument("--project", default=None)
    d.add_argument("--project-id", default=None)
    d.add_argument("--group-id", required=True)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    mgr = AiAssistManager(ApiClient(cfg))

    if args.cmd == "credits":
        return mgr.credits(args)

    project = getattr(args, "project", None)
    if args.cmd != "discard" and not project and not getattr(args, "scan_id", None):
        logger.error("--project is required (or --scan-id with --result-ids).")
        return 2

    if args.cmd == "find":
        return mgr.find(project, args)
    if args.cmd == "triage":
        return mgr.triage(project, args)
    if args.cmd == "triage-status":
        return mgr.triage_status(project, args)
    if args.cmd == "remediate":
        return mgr.remediate(project, args)
    if args.cmd == "remediation-details":
        return mgr.remediation_details(project, args)
    if args.cmd == "discard":
        return mgr.discard(project, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
