"""
IaC Security (KICS) triage handler.

Fetches results from GET /api/results (type=kics), checks existing predicates
for idempotency, then bulk-applies via POST /api/kics-results-predicates/.
"""

from .base_handler import BaseTriageHandler, TriageSummary
from ops.state_normalize import (
    sast_iac_state_to_api,
    sast_iac_state_to_display,
    severity_to_api_sast_iac,
)

_PREDICATE_ENDPOINT = "kics-results-predicates"
_RESULTS_TYPE = "kics"


class IaCHandler(BaseTriageHandler):

    ENGINE = "iac"

    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        return self._get_results_page(scan_id, _RESULTS_TYPE)

    def apply_triage(
        self,
        project_id: str,
        matched_results: list[dict],
        summary: TriageSummary,
    ) -> None:
        if not matched_results:
            return

        predicates_to_apply = []

        for result in matched_results:
            rule = result["_matched_rule"]
            similarity_id = result.get("similarityId")
            if not similarity_id:
                summary.errors.append(f"Missing similarityId for result {result.get('id')}")
                continue

            target_state_api = sast_iac_state_to_api(rule.get("state", ""))

            if self._already_triaged(similarity_id, project_id, target_state_api):
                self.logger.debug(
                    "[IaC] Skipping %s — already in state '%s'",
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
                    "[DRY-RUN][IaC] Would triage similarityId=%s state=%s",
                    p["similarityId"], sast_iac_state_to_display(p["state"]),
                )
            summary.results_applied += len(predicates_to_apply)
            return

        try:
            self.api.post(_PREDICATE_ENDPOINT, json_body=predicates_to_apply,
                          idempotent=True)  # predicates set absolute states; replay converges
            summary.results_applied += len(predicates_to_apply)
            self.logger.debug(
                "[IaC] Applied %d predicates for project %s",
                len(predicates_to_apply), project_id,
            )
        except Exception as exc:
            msg = f"Failed to apply IaC predicates: {exc}"
            self.logger.error(msg)
            summary.errors.append(msg)

    def _already_triaged(
        self, similarity_id: str, project_id: str, target_state: str
    ) -> bool:
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
                "Could not check existing IaC predicate for %s: %s",
                similarity_id, exc,
            )
        return False
