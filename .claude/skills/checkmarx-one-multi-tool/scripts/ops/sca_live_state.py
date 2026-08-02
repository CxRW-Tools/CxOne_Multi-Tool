"""
Current SCA triage state — because the scan-time state is not it.

**SCA scans are immutable.** Triage applied after a scan does not rewrite that
scan; the value only becomes the scan's `state` on the next scan or
recalculation. So every obvious read path reports as-of-scan data:

| Surface | Regular / configuration / Usage | Supply-chain |
|---|---|---|
| ``GET /api/results`` ``state``          | scan-time (STALE) | scan-time |
| SCA export ``RiskState``                | scan-time (STALE) | scan-time |
| ``GET /api/risks`` ``state``            | current           | never reflects it |
| GQL ``vulnerabilitiesRisksByScanId``    | ``pendingState`` = CURRENT | not returned |
| GQL ``searchPackageSupplyChainRisk…``   | —                 | CURRENT |

Live example, one minute after triaging a CVE::

    CVE-2015-7501    state=ToVerify    pendingState=ProposedNotExploitable

This module is the single place that knows how to get the CURRENT state, which
is what the tool treats as real everywhere: results listings, "is this already
triaged?" decisions, and write verification. Nothing else should read `state`
off a scan and call it current.

Both queries are undocumented GraphQL (``POST /api/sca/graphql/graphql``) — the
published REST reference exposes no way to read current SCA triage state.
"""

from __future__ import annotations

import re
import logging

logger = logging.getLogger("cxone.sca_state")

SCA_GRAPHQL = "sca/graphql/graphql"

# Per-scan risk view. Covers Regular / configuration / Usage types; supply-chain
# risks are NOT included and need the action-store query below.
_VULN_RISKS_QUERY = (
    "query ($take: Int!, $skip: Int!, $scanId: UUID!, $isExploitablePathEnabled: Boolean!) "
    "{ vulnerabilitiesRisksByScanId (take: $take, skip: $skip, scanId: $scanId, "
    "isExploitablePathEnabled: $isExploitablePathEnabled) { totalCount, items "
    "{ cve, state, pendingState, pendingChanges, isIgnored, type } } }")

_SUPPLY_CHAIN_ACTIONS_QUERY = (
    "query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, "
    "$packageName: String, $packageVersion: String, $packageManager: String, "
    "$supplyChainRiskId: String) "
    "{ searchPackageSupplyChainRiskStateAndScoreActions (scanId: $scanId, "
    "projectId: $projectId, isLatest: $isLatest, packageName: $packageName, "
    "packageVersion: $packageVersion, packageManager: $packageManager, "
    "supplyChainRiskId: $supplyChainRiskId) { actions { actionType, actionValue, "
    "createdAt } } }")

# The service caps page size at 100 (`HC0051: maximum allowed items per page`).
# Asking for more returns a GraphQL error with data=null — which, if you only
# look at `data`, is indistinguishable from "no results".
_PAGE = 100


def _graphql(api, query: str, variables: dict, what: str) -> dict | None:
    """POST a GraphQL query and surface errors instead of swallowing them.

    A GraphQL error comes back as HTTP 200 with `errors` populated and `data`
    null. Treating that as an empty result is the exact silent-failure mode this
    module exists to prevent, so log it loudly and return None (= unknown).
    """
    try:
        resp = api.post(SCA_GRAPHQL, json_body={"query": query, "variables": variables},
                        idempotent=True) or {}
    except Exception as exc:                           # noqa: BLE001
        logger.warning("SCA %s query failed: %s", what, exc)
        return None
    errors = resp.get("errors")
    if errors:
        logger.warning("SCA %s query returned errors: %s", what,
                       "; ".join(str(e.get("message")) for e in errors)[:300])
        return None
    return resp.get("data") or {}


def live_vuln_states(api, scan_id: str) -> dict[str, str]:
    """``{advisory_id: current_state}`` for non-supply-chain SCA risks.

    Prefers ``pendingState`` (current) over ``state`` (scan-time). Returns an
    empty dict on failure — callers must treat that as "unknown", never as
    "nothing is triaged".
    """
    out: dict[str, str] = {}
    skip = 0
    while True:
        data = _graphql(api, _VULN_RISKS_QUERY,
                        {"take": _PAGE, "skip": skip, "scanId": scan_id,
                         "isExploitablePathEnabled": True}, "risk-state")
        if data is None:
            return out
        node = data.get("vulnerabilitiesRisksByScanId") or {}
        items = node.get("items") or []
        for item in items:
            key = str(item.get("cve") or "")
            if key:
                out[key] = str(item.get("pendingState") or item.get("state") or "")
        skip += len(items)
        if not items or skip >= (node.get("totalCount") or 0):
            return out


def risk_uuid_map(api, project_id: str) -> dict[str, str]:
    """``{short_id: full_uuid}`` for a project's risks.

    The SCA export/results carry a SHORTENED advisory id (``Cx43050644-3add``).
    Writes accept it, but the supply-chain GraphQL read does NOT — given the
    short form it returns zero actions, which looks exactly like "never
    triaged". The full UUID is the first ``#-#`` segment of the risk's
    ``groupId`` in ``GET /api/risks``.
    """
    out: dict[str, str] = {}
    try:
        from ops.findings import FindingResolver
        for row in FindingResolver(api).risks(project_id):
            name, gid = str(row.get("riskName") or ""), str(row.get("groupId") or "")
            if name and gid:
                out[name] = gid.split("#-#")[0]
    except Exception as exc:                           # noqa: BLE001
        logger.debug("risk uuid lookup failed: %s", exc)
    return out


def supply_chain_state(api, scan_id: str, project_id: str, *, package_name: str,
                       package_version: str, package_manager: str,
                       risk_uuid: str) -> str | None:
    """Current state of one supply-chain risk, or None if never triaged."""
    data = _graphql(api, _SUPPLY_CHAIN_ACTIONS_QUERY,
                    {"scanId": scan_id, "projectId": project_id, "isLatest": True,
                     "packageName": package_name, "packageVersion": package_version,
                     "packageManager": package_manager, "supplyChainRiskId": risk_uuid},
                    "supply-chain state")
    if data is None:
        return None
    node = data.get("searchPackageSupplyChainRiskStateAndScoreActions") or {}
    actions = [a for a in (node.get("actions") or [])
               if a.get("actionType") == "ChangeState"]
    if not actions:
        return None
    actions.sort(key=lambda a: a.get("createdAt") or "")
    return actions[-1].get("actionValue")


def to_result_state(graphql_state: str) -> str:
    """`ProposedNotExploitable` -> `PROPOSED_NOT_EXPLOITABLE`.

    GraphQL answers in camelCase; `/api/results` (and everything that renders it)
    uses UPPER_SNAKE. Without this the UI prints "Proposednotexploitable".
    """
    if not graphql_state:
        return ""
    if "_" in graphql_state:
        return graphql_state.upper()
    return re.sub(r"(?<!^)(?=[A-Z])", "_", graphql_state).upper()


def enrich_results(api, scan_id: str, project_id: str, results: list[dict]) -> int:
    """Rewrite each SCA result's ``state`` to the CURRENT one, in place.

    Returns how many rows were updated. Non-SCA results are untouched (SAST /
    IaC / Secrets / Containers report current state on ``/api/results``
    already). Supply-chain rows need one query each, so they are only queried
    when the bulk view doesn't cover them — typically a handful per scan.
    """
    sca = [r for r in results if (r.get("type") or "").lower() == "sca"]
    if not sca:
        return 0
    bulk = live_vuln_states(api, scan_id)
    uuids = None
    changed = 0
    for row in sca:
        advisory = str(row.get("id") or "")
        state = bulk.get(advisory)
        if state is None:
            # Not in the bulk view => supply-chain risk; resolve its UUID and ask.
            if uuids is None:
                uuids = risk_uuid_map(api, project_id)
            data = row.get("data") or {}
            package = str(data.get("packageIdentifier") or "")
            # packageIdentifier is "<Manager>-<name>-<version>"
            manager = package.split("-", 1)[0] if package else ""
            state = supply_chain_state(
                api, scan_id, project_id,
                package_name=data.get("packageName") or _package_name(package, manager),
                package_version=_package_version(package),
                package_manager=manager,
                risk_uuid=uuids.get(advisory, advisory))
        normalized = to_result_state(state or "")
        if normalized and normalized != str(row.get("state") or "").upper():
            row["state"] = normalized
            changed += 1
    if changed:
        logger.debug("Updated %d SCA result(s) to their current triage state.", changed)
    return changed


def _package_name(package_identifier: str, manager: str) -> str:
    """`Npm-momnet-2.29.1` -> `momnet` (strip manager prefix and version suffix)."""
    body = package_identifier[len(manager) + 1:] if manager else package_identifier
    return body.rsplit("-", 1)[0] if "-" in body else body


def _package_version(package_identifier: str) -> str:
    return package_identifier.rsplit("-", 1)[-1] if "-" in package_identifier else ""
