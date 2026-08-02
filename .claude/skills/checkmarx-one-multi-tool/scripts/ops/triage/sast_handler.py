"""
SAST triage handler — dual grouping modes.

CxOne tenants group SAST triage one of two ways, and each mode's endpoint HARD
REJECTS the other (400, code 4002, "Account is configured to use ..."):

  * Similarity ID mode (classic): one decision per similarity group, applied
    via POST /api/sast-results-predicates (array of per-simid predicates).
  * Attack Vector mode (SAST_ADVANCED_GROUPING_ENABLED): one decision covers
    ALL similarity groups sharing an attack pattern, applied via
    POST /api/sast-results-predicates/attack-vector. The realism unit follows:
    ONE dice roll per vector (keyed by attackVectorId, coverage from the
    group's max severity), one budget unit per vector, one comment.

Mode selection (`sast_grouping` in triage_rules.yaml / CXONE_SAST_GROUPING):
  * auto (default): start in simid; the first 4002 rejection names the required
    mode in its message, so the handler flips a process-wide per-tenant cache
    and refunds the pass's budget (nothing landed). The one failed pass
    self-corrects on the next pass; every later pass in the process uses the
    detected mode directly.
  * simid / attack-vector: explicit, no detection, 4002 surfaces as an error.

Attack-vector posts go ONE VECTOR PER REQUEST (single-element array) because
the API only returns honest per-item codes (409/404) for single-element
arrays — multi-element requests are always 201 with failures visible only in
server logs. A 409 (mixed states across the vector's similarity groups) is
handled per `mixed_state_policy`: filtered (default — Mode 2 updates for the
untriaged groups, the human "resolve one at a time" behavior), skip, or
override (allowInconsistentStates: true).
"""

import os
import logging
from typing import Any

import requests

from .base_handler import BaseTriageHandler, TriageSummary
from cxone import ApiClient
from cxone import CxConfig as Config
from ops.state_normalize import (
    sast_iac_state_to_api,
    sast_iac_state_to_display,
    severity_to_api_sast_iac,
)

_PREDICATE_ENDPOINT = "sast-results-predicates"
_AV_ENDPOINT = "sast-results-predicates/attack-vector"
# Tenant-level SAST configuration; carries scan.config.sast.advancedTriageMode
# ("Similarity ID" | "Attack Vector ID") — the authoritative mode read.
_SAST_CONFIG_ENDPOINT = "sast-configuration"
_MODE_CONFIG_KEY = "scan.config.sast.advancedTriageMode"
# The sast-configuration endpoint enforces an allowlisted X-Source caller
# identity (403/4003 "Invalid or missing X-Source header" otherwise). This is
# the value the CxOne UI itself sends on that call (captured live from browser
# devtools on cnf26) and verified to be accepted — used as the built-in default
# so the authoritative mode read works out of the box. Override via config
# (sast_grouping.config_xsource) or env (CXONE_SAST_CONFIG_XSOURCE) if a future
# platform build changes it.
_DEFAULT_SAST_CONFIG_XSOURCE = "sast-results-viewer"
# The sast-results service listing (has state + resultHash; per the Enrichment
# design it does NOT carry attack-vector ids — no listing does).
_SAST_RESULTS_ENDPOINT = "sast-results/"
# Hash -> similar-group id resolver. In Attack Vector mode the returned group
# id IS the attack vector id; the response also carries per-group state
# consistency (informs Mode 1 vs Mode 2 up front) and the tenant's effective
# groupingMode (an in-band mode detector needing no X-Source header).
_SIMILAR_RESULTS_ENDPOINT = "sast-results/similar-results"
_SIMILAR_RESULTS_CHUNK = 200   # maxResultHashForGroupIdRequest per the design
# Fallback id source: compare against itself with the enrichment-columns
# switch (spelling per the Enrichment design: include-, not add-).
_COMPARE_ENDPOINT = "sast-results/compare"
_RESULTS_TYPE = "sast"

# Severity rank for "coverage rolls on the vector's worst finding".
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Detected grouping mode, process-wide, keyed (tenant, project_id) because the
# config entry is tenant-origin with allowOverride: true — a project CAN
# differ. "" project key = tenant default. The agent detects once per project
# and every subsequent pass uses it directly.
_MODE_CACHE: dict[tuple[str, str], str] = {}
# Projects where a config read was attempted and failed — don't hammer the
# endpoint; fall back to assume-simid + 4002-driven correction.
_MODE_READ_FAILED: set[tuple[str, str]] = set()


def _api_error(exc: Exception) -> tuple[int | None, int | None, str]:
    """(http_status, app_code, message) from a requests.HTTPError, else blanks."""
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        status = exc.response.status_code
        try:
            body = exc.response.json() or {}
        except ValueError:
            body = {}
        return status, body.get("code"), str(body.get("message") or "")
    return None, None, ""


class SASTHandler(BaseTriageHandler):

    ENGINE = "sast"

    def __init__(self, *args, grouping: dict | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        g = grouping or {}
        self._mode_setting = (os.environ.get("CXONE_SAST_GROUPING")
                              or g.get("mode") or "auto").lower()
        # Default matches the live sast-results service spelling (capital ID);
        # the fetch normalizer exposes both casings so either config value works.
        self._av_field = g.get("attack_vector_field", "attackVectorID")
        self._mixed_policy = g.get("mixed_state_policy", "filtered")
        # X-Source for the sast-configuration read: config override wins, else
        # env, else the verified built-in default (see _DEFAULT_SAST_CONFIG_XSOURCE).
        self._config_xsource = g.get("config_xsource") or None

    # ------------------------------------------------------------- mode logic
    def _cache_key(self) -> tuple[str, str]:
        project_id = (getattr(self, "_ctx_key", ("",)) or ("",))[0]
        return (self.config.tenant_name, project_id or "")

    def _effective_mode(self) -> str:
        if self._mode_setting in ("simid", "attack-vector"):
            return self._mode_setting
        key = self._cache_key()
        cached = _MODE_CACHE.get(key)
        if cached:
            return cached
        # Authoritative read: the tenant's SAST configuration names the mode
        # outright, so a one-shot CLI run gets the right answer BEFORE acting
        # (no sacrificial 4002 pass). Failure falls back to assume-simid with
        # the 4002 handlers as the correction mechanism.
        if key not in _MODE_READ_FAILED:
            detected = self._read_mode_from_config()
            if detected:
                _MODE_CACHE[key] = detected
                if detected != "simid":
                    self.logger.info(
                        "[SAST] Tenant SAST configuration: grouping mode = %s.",
                        detected)
                return detected
            _MODE_READ_FAILED.add(key)
        return "simid"

    def _read_mode_from_config(self) -> str | None:
        """scan.config.sast.advancedTriageMode from GET sast-configuration:
        'Similarity ID' -> simid, 'Attack Vector ID' -> attack-vector.
        None on any failure (endpoint absent/permission/unknown value)."""
        try:
            # The endpoint enforces an allowlisted X-Source caller identity
            # (403/4003 "Invalid or missing X-Source header" otherwise). We send
            # the value the CxOne UI itself uses by default; override via config
            # (sast_grouping.config_xsource) or env (CXONE_SAST_CONFIG_XSOURCE)
            # if a platform build ever changes it. If this read still fails,
            # detection falls back to the 4002 layer, which also works.
            xsource = (os.environ.get("CXONE_SAST_CONFIG_XSOURCE")
                       or self._config_xsource
                       or _DEFAULT_SAST_CONFIG_XSOURCE)
            entries = self.api.get(
                _SAST_CONFIG_ENDPOINT,
                extra_headers={"X-Source": xsource} if xsource else None) or []
            if isinstance(entries, dict):
                entries = (entries.get("configurations")
                           or entries.get("configuration") or [])
            for e in entries:
                if (e or {}).get("key") == _MODE_CONFIG_KEY:
                    value = str(e.get("value") or "").strip().lower()
                    if "attack" in value:
                        return "attack-vector"
                    if "similarity" in value:
                        return "simid"
                    self.logger.debug("[SAST] Unrecognized %s value: %r",
                                      _MODE_CONFIG_KEY, e.get("value"))
                    return None
            self.logger.debug("[SAST] %s not present in sast-configuration.",
                              _MODE_CONFIG_KEY)
        except Exception as exc:
            self.logger.debug("[SAST] sast-configuration read failed (%s); "
                              "falling back to 4002-driven detection.", exc)
        return None

    def _switch_mode(self, detected: str, message: str) -> None:
        _MODE_CACHE[self._cache_key()] = detected
        self.logger.warning(
            "[SAST] Tenant grouping mode detected via rejection: %s (server "
            "said: %s). Retrying this pass in %s mode.",
            detected, message.strip() or "4002", detected)

    def _refund_pass_budget(self) -> None:
        if self.budget is not None and self._budget_taken:
            self.budget.give_back(self._budget_taken)
            self._budget_taken = 0

    def _retry_pass_in_detected_mode(self, project_id: str,
                                     summary: TriageSummary) -> None:
        """Re-run THIS pass (refetch -> re-match -> re-apply) after a 4002
        mode flip, so one-shot CLI invocations recover in the same process
        instead of detect-refund-exit looping. Refetch is mandatory, not an
        optimization: the two modes read different surfaces (unified
        /api/results vs the sast-results service), and only the latter carries
        attackVectorID. Guarded to a single retry per pass."""
        if getattr(self, "_mode_retry_done", False):
            self.logger.error(
                "[SAST] Grouping mode flipped twice within one pass — the "
                "tenant configuration is changing mid-run; giving up this pass.")
            return
        self._mode_retry_done = True
        scan_id = (getattr(self, "_ctx_key", ("", "")) + ("", ""))[1]
        self._deferred = 0
        summary.results_skipped = 0  # counters from the abandoned attempt
        try:
            results = self.fetch_results(project_id, scan_id)
            summary.results_fetched = len(results)
            matched = self.match_rules(results)
            summary.results_matched = len(matched)
            self.apply_triage(project_id, matched, summary)
        except Exception as exc:
            msg = f"Retry in {self._effective_mode()} mode failed: {exc}"
            self.logger.error("[SAST] %s", msg)
            summary.errors.append(msg)

    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        if self._effective_mode() == "attack-vector":
            return self._fetch_sast_results_av(scan_id)
        return self._get_results_page(scan_id, _RESULTS_TYPE)

    def _fetch_sast_results_av(self, scan_id: str) -> list[dict]:
        """AV-mode fetch pipeline (per the Enrichment design, NO results
        listing carries the vector id — it must be resolved):
          1. list results from GET sast-results/ (state + resultHash present),
             filter client-side to To-Verify;
          2. resolve resultHash -> similar-group id via
             POST sast-results/similar-results (chunked); in Attack Vector
             mode the group id IS the attack vector id, and the response also
             yields per-group state consistency (Mode 1 vs Mode 2 up front)
             and the tenant's effective groupingMode (in-band mode detection);
          3. if similar-results is unavailable, fall back to
             GET sast-results/compare?include-additional-columns=true
             (self-compare) which carries attackVectorID per result.
        Records are annotated in place: _av_id, _av_inconsistent."""
        from ops.state_normalize import is_to_verify
        out: list[dict] = []
        offset, limit = 0, 100
        while True:
            page = self.api.get(_SAST_RESULTS_ENDPOINT,
                                params={"scan-id": scan_id,
                                        "limit": limit, "offset": offset}) or {}
            results = page.get("results") or []
            for r in results:
                sim = r.get("similarityID")
                out.append({
                    "type": "sast",
                    "id": r.get("ID") or r.get("id"),
                    "similarityId": str(sim) if sim is not None else None,
                    "resultHash": r.get("resultHash"),
                    "state": r.get("state") or "",
                    "severity": r.get("severity") or "",
                    # Kept for the last-resort direct-field path/config override.
                    "attackVectorID": r.get("attackVectorID") or r.get("attackVectorId"),
                    "attackVectorId": r.get("attackVectorID") or r.get("attackVectorId"),
                    "queryName": r.get("queryName"),
                    "languageName": r.get("languageName"),
                })
            total = page.get("totalCount")
            offset += len(results)
            if not results or (isinstance(total, int) and offset >= total):
                break
        to_verify = [r for r in out if is_to_verify(r.get("state") or "")]
        self.logger.debug("[SAST] sast-results fetch: %d result(s), %d To-Verify.",
                          len(out), len(to_verify))
        if to_verify:
            self._resolve_vector_ids(scan_id, to_verify)
        return to_verify

    def _resolve_vector_ids(self, scan_id: str, results: list[dict]) -> None:
        """Annotate results with _av_id/_av_inconsistent via similar-results;
        set self._detected_grouping_mode from the response. Falls back to the
        compare endpoint, then to a direct field on the results."""
        self._detected_grouping_mode = None
        by_hash = {r["resultHash"]: r for r in results if r.get("resultHash")}
        hashes = list(by_hash)
        if hashes:
            try:
                inconsistent_ids: set[str] = set()
                for i in range(0, len(hashes), _SIMILAR_RESULTS_CHUNK):
                    chunk = hashes[i:i + _SIMILAR_RESULTS_CHUNK]
                    resp = self.api.post(
                        _SIMILAR_RESULTS_ENDPOINT,
                        json_body={"scanId": scan_id, "resultsHash": chunk},
                        idempotent=True) or {}  # pure read despite POST
                    gm = str(resp.get("groupingMode") or "").lower()
                    if gm:
                        self._detected_grouping_mode = (
                            "attack-vector" if "attack" in gm else "simid")
                    for item in resp.get("similarResults") or []:
                        r = by_hash.get(item.get("resultHash"))
                        gid = item.get("id")
                        if r is not None and gid:
                            r["_av_id"] = str(gid)
                            r["_av_inconsistent"] = bool(
                                item.get("isStateInconsistent"))
                            if r["_av_inconsistent"]:
                                inconsistent_ids.add(str(gid))
                    # An in-flight predicate update makes the service return an
                    # EMPTY set (design example 3) — nothing to annotate, the
                    # missing-id guard downstream reports it.
                resolved = sum(1 for r in results if r.get("_av_id"))
                self.logger.debug(
                    "[SAST] similar-results resolved %d/%d hash(es); "
                    "groupingMode=%s; %d inconsistent group(s).",
                    resolved, len(hashes), self._detected_grouping_mode,
                    len(inconsistent_ids))
                if resolved:
                    return
            except Exception as exc:
                status, code, message = _api_error(exc)
                if status == 405 and code == 4005:
                    # SAST_ADVANCED_GROUPING_ENABLED off — remember for the
                    # matcher, which flips to simid in auto mode.
                    self._detected_grouping_mode = "simid"
                    self.logger.info(
                        "[SAST] similar-results: advanced grouping flag is off "
                        "(%s).", message or "405/4005")
                    return
                self.logger.debug("[SAST] similar-results unavailable (%s); "
                                  "trying the compare fallback.", exc)
        # Fallback: self-compare with the enrichment-columns switch.
        try:
            offset, limit = 0, 100
            got_any = False
            while True:
                page = self.api.get(
                    _COMPARE_ENDPOINT,
                    params={"scan-id": scan_id, "base-scan-id": scan_id,
                            "include-additional-columns": "true",
                            "include-nodes": "false",
                            "limit": limit, "offset": offset}) or {}
                rows = page.get("results") or []
                for row in rows:
                    r = by_hash.get(row.get("resultHash"))
                    av = row.get("attackVectorID") or row.get("attackVectorId")
                    if r is not None and av:
                        r["_av_id"] = str(av)
                        got_any = True
                total = page.get("totalCount")
                offset += len(rows)
                if not rows or (isinstance(total, int) and offset >= total):
                    break
            if got_any:
                self.logger.debug("[SAST] compare fallback resolved vector ids.")
                return
        except Exception as exc:
            self.logger.debug("[SAST] compare fallback unavailable (%s).", exc)
        # Last resort: a direct field on the results (config override path).
        for r in results:
            av = r.get(self._av_field)
            if av:
                r["_av_id"] = str(av)

    # -------------------------------------------------------- decision stage
    def match_rules(self, results: list[dict]) -> list[dict]:
        """In attack-vector mode the human decision unit is the VECTOR, so the
        dice roll once per vector, not per result. Simid mode (and legacy
        no-realism) keeps the base per-result behavior."""
        if self._effective_mode() == "attack-vector":
            # In-band detection: similar-results reported the tenant's
            # EFFECTIVE grouping mode during fetch. If it says Similarity ID,
            # the config/cache view is stale — in auto mode, flip and process
            # this very pass per-result (the fetched records are shape-
            # compatible), so recovery costs nothing at all.
            detected = getattr(self, "_detected_grouping_mode", None)
            if detected == "simid" and self._mode_setting == "auto":
                self._switch_mode("simid",
                                  "similar-results groupingMode=Similarity ID")
                return super().match_rules(results)
            return self._match_by_vector(results)
        return super().match_rules(results)

    def _match_by_vector(self, results: list[dict]) -> list[dict]:
        groups: dict[str, list[dict]] = {}
        missing = 0
        for r in results:
            av = r.get("_av_id") or r.get(self._av_field)
            if not av:
                missing += 1
                continue
            r["_av_id"] = str(av)
            groups.setdefault(str(av), []).append(r)
        if missing == len(results) and results:
            # Attack-vector ids are computed only for scans run after the
            # feature was enabled — a fully-empty field on real results almost
            # always means the scan predates the tenant's mode flip.
            raise RuntimeError(
                f"Attack-vector mode is active but no vector id could be "
                f"resolved for any of the {len(results)} fetched SAST results "
                "(similar-results, the compare fallback, and a direct field "
                "all came up empty). Most likely the tenant's account setting "
                "is Attack Vector mode while vector ids are NOT being computed "
                "— the SAST_ADVANCED_GROUPING_STORE_ATTACK_VECTOR_ENABLED "
                "flag is off (ids are only calculated and stored when it's "
                "on), so no scan old or new will have them and the CxOne UI "
                "cannot vector-triage either. Also possible: a predicate "
                "update is currently running (similar-results returns an "
                "empty set while one is in flight) — retry shortly. If it "
                "persists: switch the tenant back to Similarity ID mode (or "
                "force sast_grouping.mode: simid) and report the flag "
                "mismatch to Checkmarx.")
        if missing:
            self.logger.warning(
                "[SAST] %d result(s) lack '%s' and can't be vector-triaged.",
                missing, self._av_field)

        matched: list[dict] = []
        vectors_decided = 0
        # Vectors ordered by their worst finding — top-down, so the per-pass
        # budget spends on the most severe attack patterns first.
        def worst(members):
            return min(_SEV_ORDER.get((m.get("severity") or "").lower(), 9)
                       for m in members)
        for av_id in sorted(groups, key=lambda a: (worst(groups[a]), a)):
            members = groups[av_id]
            severity = min(
                ((m.get("severity") or "").lower() for m in members),
                key=lambda s: _SEV_ORDER.get(s, 9))
            # ONE draw per vector, keyed by the vector id: a seed reproduces
            # the same vector decisions regardless of result arrival order.
            rng = self._rng_for(*getattr(self, "_ctx_key", ()), "av", av_id)
            if self.realism is not None and getattr(self.realism, "enabled", False):
                triage, state = self.realism.decide(
                    severity, self.ENGINE, self.diligence, self.intensity, rng)
                rule = ({"state": state,
                         "comment": self.realism.comment_for(state, rng, self.ENGINE)}
                        if triage and state else None)
            else:
                rule = self._find_matching_rule(severity)
            if not rule:
                continue
            if self.budget is not None and not self.budget.take():
                self._deferred += len(members)
                continue
            self._budget_taken += 1
            vectors_decided += 1
            for m in members:
                m = dict(m)
                m["_matched_rule"] = dict(rule)
                m["_av_id"] = av_id
                m["_av_severity"] = severity
                matched.append(m)
        if vectors_decided:
            self.logger.info(
                "[SAST] %d attack-vector decision(s) covering %d result(s).",
                vectors_decided, len(matched))
        if self._deferred:
            self.logger.info(
                "[SAST] per-pass triage budget reached — %d result(s) across "
                "undecided vectors stay To Verify for a later pass.",
                self._deferred)
        return matched

    def apply_triage(
        self,
        project_id: str,
        matched_results: list[dict],
        summary: TriageSummary,
    ) -> None:
        if not matched_results:
            return
        if self._effective_mode() == "attack-vector":
            self._apply_triage_av(project_id, matched_results, summary)
            return

        predicates_to_apply = []

        for result in matched_results:
            rule = result["_matched_rule"]
            similarity_id = result.get("similarityId")
            if not similarity_id:
                summary.errors.append(f"Missing similarityId for result {result.get('id')}")
                continue

            target_state_api = sast_iac_state_to_api(rule.get("state", ""))

            # Idempotency: skip if already in the target state
            if self._already_triaged(similarity_id, project_id, target_state_api):
                self.logger.debug(
                    "[SAST] Skipping %s — already in state '%s'",
                    similarity_id, sast_iac_state_to_display(target_state_api),
                )
                summary.results_skipped += 1
                continue

            predicates_to_apply.append({
                "similarityId": similarity_id,
                "projectId": project_id,
                "severity": severity_to_api_sast_iac(result.get("severity", "")),
                "state": target_state_api,
                "comment": rule.get("comment", ""),
            })

        if not predicates_to_apply:
            return

        if self.dry_run:
            for p in predicates_to_apply:
                self.logger.info(
                    "[DRY-RUN][SAST] Would triage similarityId=%s state=%s",
                    p["similarityId"], sast_iac_state_to_display(p["state"]),
                )
            summary.results_applied += len(predicates_to_apply)
            return

        # POST as an array (bulk)
        try:
            self.api.post(_PREDICATE_ENDPOINT, json_body=predicates_to_apply,
                          idempotent=True)  # predicates set absolute states; replay converges
            summary.results_applied += len(predicates_to_apply)
            self.logger.debug(
                "[SAST] Applied %d predicates for project %s",
                len(predicates_to_apply), project_id,
            )
        except Exception as exc:
            status, code, message = _api_error(exc)
            if status == 400 and code == 4002 and "attack vector" in message.lower():
                # Tenant is in Attack Vector mode — SimID writes are hard-
                # rejected. In auto mode: flip, refund, and RETRY this same
                # pass in the detected mode (a one-shot CLI has no next pass).
                if self._mode_setting == "auto":
                    self._refund_pass_budget()
                    self._switch_mode("attack-vector", message)
                    self._retry_pass_in_detected_mode(project_id, summary)
                    return
                msg = ("SAST predicates rejected: tenant uses Attack Vector "
                       "grouping but sast_grouping.mode is forced to 'simid'. "
                       f"Server: {message}")
                self.logger.error(msg)
                summary.errors.append(msg)
                return
            msg = f"Failed to apply SAST predicates: {exc}"
            self.logger.error(msg)
            summary.errors.append(msg)

    # ------------------------------------------------------- attack-vector apply
    def _apply_triage_av(
        self,
        project_id: str,
        matched_results: list[dict],
        summary: TriageSummary,
    ) -> None:
        scan_id = (getattr(self, "_ctx_key", ("", "")) + ("", ""))[1]
        # Regroup the flattened matched results by vector; every member of a
        # vector carries the same rule (drawn once in _match_by_vector).
        vectors: dict[str, list[dict]] = {}
        for m in matched_results:
            vectors.setdefault(m["_av_id"], []).append(m)

        for av_id, members in vectors.items():
            rule = members[0]["_matched_rule"]
            # similar-results told us up front whether this vector's groups
            # have mixed states — choose Mode 1/Mode 2 informed instead of
            # try-and-catch-409. The 409 handler stays as the authoritative
            # fallback (the server can know things the earlier read didn't).
            known_inconsistent = any(m.get("_av_inconsistent") for m in members)
            payload = {
                "attackVectorId": av_id,
                "projectId": project_id,
                "scanId": scan_id,
                "state": sast_iac_state_to_api(rule.get("state", "")),
                "severity": severity_to_api_sast_iac(members[0].get("_av_severity", "")),
                "comment": rule.get("comment", ""),
            }
            # The UI design doc includes language/queryName in the write body
            # (the similar-results grouping is Query Group/Language + Query
            # Name + AV id); harmless if the API ignores them, needed if not.
            if members[0].get("languageName"):
                payload["language"] = members[0]["languageName"]
            if members[0].get("queryName"):
                payload["queryName"] = members[0]["queryName"]
            if self.dry_run:
                self.logger.info(
                    "[DRY-RUN][SAST] Would triage attackVectorId=%s (%d result(s), "
                    "%d similarity group(s)) state=%s",
                    av_id, len(members), len(self._sim_ids(members)),
                    sast_iac_state_to_display(payload["state"]))
                summary.results_applied += len(members)
                continue
            if known_inconsistent:
                if self._mixed_policy == "skip":
                    self.logger.info(
                        "[SAST] AV %s skipped: similar-results reports mixed "
                        "states (mixed_state_policy=skip).", av_id)
                    summary.results_skipped += len(members)
                    continue
                if self._mixed_policy == "filtered":
                    self._apply_mode2_filtered(av_id, members, payload, summary,
                                               reason="similar-results")
                    continue
                # override: proceed with Mode 1 but pre-authorize.
                payload["allowInconsistentStates"] = True
            # ONE VECTOR PER REQUEST: only single-element arrays return honest
            # per-item error codes (409/404); multi-element is always 201 with
            # failures visible solely in server logs.
            try:
                self.api.post(_AV_ENDPOINT, json_body=[payload], idempotent=True)
                summary.results_applied += len(members)
                self.logger.debug("[SAST] AV %s triaged (%d results).",
                                  av_id, len(members))
            except Exception as exc:
                self._handle_av_error(exc, av_id, members, payload, summary,
                                      project_id)

    def _apply_mode2_filtered(self, av_id: str, members: list[dict],
                              payload: dict, summary: TriageSummary,
                              reason: str) -> None:
        """Mode 2: resolve the untriaged groups one at a time — our fetched
        set is To-Verify-only, so the sim ids we hold are exactly the
        unresolved groups. Still ONE human decision (one budget unit)."""
        base = {k: v for k, v in payload.items()
                if k != "allowInconsistentStates"}
        ok = 0
        for sim_id in self._sim_ids(members):
            try:
                self.api.post(_AV_ENDPOINT,
                              json_body=[{**base,
                                          "filterBySimilarityId": sim_id}],
                              idempotent=True)
                ok += len([m for m in members
                           if str(m.get("similarityId")) == sim_id])
            except Exception as exc:
                summary.errors.append(
                    f"AV {av_id} filtered update {sim_id} failed: {exc}")
        summary.results_applied += ok
        if ok:
            self.logger.info(
                "[SAST] AV %s has mixed states (per %s) — applied Mode 2 "
                "filtered updates to %d To-Verify result(s).",
                av_id, reason, ok)

    def _sim_ids(self, members: list[dict]) -> list[str]:
        return sorted({str(m.get("similarityId")) for m in members
                       if m.get("similarityId")})

    def _handle_av_error(self, exc: Exception, av_id: str, members: list[dict],
                         payload: dict, summary: TriageSummary,
                         project_id: str = "") -> None:
        status, code, message = _api_error(exc)
        if status == 409:
            # Mixed states across the vector's similarity groups — expected
            # over time, since earlier passes triage some groups and not others.
            policy = self._mixed_policy
            if policy == "override":
                try:
                    self.api.post(_AV_ENDPOINT,
                                  json_body=[{**payload,
                                              "allowInconsistentStates": True}],
                                  idempotent=True)
                    summary.results_applied += len(members)
                except Exception as exc2:
                    msg = f"AV {av_id} override update failed: {exc2}"
                    self.logger.error(msg)
                    summary.errors.append(msg)
                return
            elif policy == "filtered":
                self._apply_mode2_filtered(av_id, members, payload, summary,
                                           reason="409")
                return
            else:  # skip
                self.logger.info(
                    "[SAST] AV %s skipped: mixed states across similarity "
                    "groups (mixed_state_policy=skip).", av_id)
                summary.results_skipped += len(members)
                return
        if status == 400 and code == 4002 and "similarity" in message.lower():
            if self._mode_setting == "auto":
                self._refund_pass_budget()
                self._switch_mode("simid", message)
                self._retry_pass_in_detected_mode(project_id, summary)
                return
            summary.errors.append(
                "AV predicates rejected: tenant uses Similarity ID grouping "
                f"but sast_grouping.mode is forced to 'attack-vector'. Server: {message}")
            return
        flag_off_403 = (status == 403 and code == 4002
                        and "featureunavailable" in message.lower())
        if status == 405 or flag_off_403:
            msg = ("Attack Vector triage feature is disabled on this tenant "
                   "(SAST_ADVANCED_GROUPING_ENABLED off). "
                   + ("Falling back to simid on the next pass."
                      if self._mode_setting == "auto" else
                      "Force sast_grouping.mode: simid."))
            self.logger.error("[SAST] %s", msg)
            if self._mode_setting == "auto":
                self._refund_pass_budget()
                self._switch_mode("simid", message or ("405" if status == 405 else "403"))
                self._retry_pass_in_detected_mode(project_id, summary)
            else:
                summary.errors.append(msg)
            return
        if status == 404:
            self.logger.warning(
                "[SAST] AV %s: no results found server-side (404) — skipped.",
                av_id)
            summary.results_skipped += len(members)
            return
        msg = f"AV {av_id} predicate post failed: {exc}"
        self.logger.error(msg)
        summary.errors.append(msg)

    def _already_triaged(
        self, similarity_id: str, project_id: str, target_state: str
    ) -> bool:
        """Return True if the most recent predicate already matches the target state."""
        try:
            response = self.api.get(
                f"{_PREDICATE_ENDPOINT}/{similarity_id}",
                params={"project-ids": project_id},
            )
            for project_history in response.get("predicateHistoryPerProject", []):
                if project_history.get("projectId") == project_id:
                    predicates = project_history.get("predicates", [])
                    if predicates:
                        current = predicates[0].get("state", "")
                        return current.upper() == target_state.upper()
        except Exception as exc:
            self.logger.debug(
                "Could not check existing SAST predicate for %s: %s",
                similarity_id, exc,
            )
        return False
