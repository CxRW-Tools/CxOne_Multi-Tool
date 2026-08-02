"""
Secrets (Secret Detection / SSCS) triage handler.

Secret-detection findings surface in /api/results with type
'sscs-secret-detection' (the 2ms micro-engine). They are triaged through the
micro-engines predicate API, which — unlike SAST/IaC — requires a versioned
Accept header and takes a flat array of predicates:

  POST /api/micro-engines/write/predicates   (Accept: */*; version=1.0)
  [{similarityId, projectId, severity, state, comment}]

state  ∈ TO_VERIFY, NOT_EXPLOITABLE, PROPOSED_NOT_EXPLOITABLE, CONFIRMED, URGENT
severity ∈ CRITICAL, HIGH, MEDIUM, LOW, INFO  (same UPPER_SNAKE form as SAST/IaC)

similarityId here is a hash, and the endpoint accepts it as-is.
"""

import logging

from .base_handler import BaseTriageHandler, TriageSummary
from ops.state_normalize import (
    sast_iac_state_to_api,
    sast_iac_state_to_display,
    severity_to_api_sast_iac,
    severity_normalize_for_match,
)

_RESULTS_TYPE = "sscs-secret-detection"
_PREDICATE_ENDPOINT = "micro-engines/write/predicates"
_VERSION_HEADER = {"Accept": "*/*; version=1.0"}


class SecretsHandler(BaseTriageHandler):

    ENGINE = "sscs-secret-detection"   # matches the /api/results `type` field

    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        return self._get_results_page(scan_id, _RESULTS_TYPE)

    def apply_triage(self, project_id, matched_results, summary) -> None:
        if not matched_results:
            return
        predicates = []
        for result in matched_results:
            rule = result["_matched_rule"]
            similarity_id = result.get("similarityId")
            if not similarity_id:
                summary.errors.append(f"Missing similarityId for secret {result.get('id')}")
                continue
            target_state = sast_iac_state_to_api(rule.get("state", ""))
            # Free idempotency: the result carries its current state.
            if severity_normalize_for_match(result.get("state") or "") == severity_normalize_for_match(target_state):
                summary.results_skipped += 1
                continue
            predicates.append({
                "similarityId": str(similarity_id),
                "projectId": project_id,
                "severity": severity_to_api_sast_iac(result.get("severity", "")),
                "state": target_state,
                "comment": rule.get("comment", ""),
            })
        if not predicates:
            return
        if self.dry_run:
            for p in predicates:
                self.logger.info("[DRY-RUN][Secrets] Would triage similarityId=%s state=%s",
                                 p["similarityId"], sast_iac_state_to_display(p["state"]))
            summary.results_applied += len(predicates)
            return
        try:
            self.api.post(_PREDICATE_ENDPOINT, json_body=predicates, extra_headers=_VERSION_HEADER,
                          idempotent=True)  # predicates set absolute states; replay converges
            summary.results_applied += len(predicates)
        except Exception as exc:
            msg = f"Failed to apply secret predicates: {exc}"
            self.logger.error(msg)
            summary.errors.append(msg)
