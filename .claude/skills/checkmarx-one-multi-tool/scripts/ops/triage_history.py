"""
Past triage information — who set a finding's state, when, and why.

**This module is THE way to answer "who triaged this and what did they say".
Never use the audit trail (`audit` verb) for it.** Audit events are an
append-only activity stream that is never reconciled against live state: they
reference results that may since have been re-scanned (a new scan mints new
result identifiers) or deleted, they carry no comment text for most engines,
and deduping them to "latest event per result" does NOT reproduce the current
state. The per-engine predicate/action endpoints below are the system of
record — they return the CURRENT state plus the full change history, comments
and usernames included, straight from the service that owns the triage.

Each engine exposes its own read path, all live-verified on cnf26 2026-08-03:

| Engine | Read path | Key |
|---|---|---|
| SAST | ``GET sast-results-predicates/{similarityId}`` | similarityId |
| IaC/KICS | ``GET kics-results-predicates/{similarityId}`` | similarityId |
| Secrets | ``GET micro-engines/read/predicates/{similarityId}`` | similarityId |
| Containers | ``POST containers/triage/triage/triage-history/{projectId}/{scanId}`` | packageId + cveId |
| SCA | ``POST sca/graphql/graphql`` (GraphQL) | project + package + advisory |

Three traps, each of which cost a live debugging round:

* **`Accept: application/json; version=1.0` is required** on the three
  predicate GETs. The client's default ``Accept: application/json`` is not
  enough — same pattern as the audit-events endpoint.
* **SAST uses the similarityId even on Attack-Vector tenants.** Unlike the
  *write* path (``ops/triage/sast_handler.py``), which must use the attack
  vector id when the tenant groups that way, the predicate read is keyed by
  similarityId in BOTH modes. Passing a vector id here returns nothing.
* **The SCA GraphQL queries require ``projectId``.** Omitting it is not an
  error — the query returns ``actions: []``, which is indistinguishable from
  "never triaged". This is the same silent-empty failure mode documented in
  ``ops/sca_live_state.py``; that module reads state only, this one adds the
  comment and username from the same actions.

SCA additionally splits by risk type, exactly as ``ops/sca_live_state`` does:
regular vulnerabilities answer to ``searchPackageVulnerabilityStateAndScoreActions``
and supply-chain (malicious / typosquat) risks to
``searchPackageSupplyChainRiskStateAndScoreActions``. Both are undocumented —
the published REST reference exposes no SCA triage-history endpoint at all.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict

from .findings import encode_path_segment

logger = logging.getLogger("cxone.triage_history")

# The predicate services 400 (or silently under-serve) without an explicit
# versioned Accept. See module docstring.
_VERSION_HEADERS = {"Accept": "application/json; version=1.0"}

_SAST_PREDICATES = "sast-results-predicates"
_KICS_PREDICATES = "kics-results-predicates"
_SECRETS_PREDICATES = "micro-engines/read/predicates"
_CONTAINERS_HISTORY = "containers/triage/triage/triage-history"
_SCA_GRAPHQL = "sca/graphql/graphql"

_SCA_ACTION_FIELDS = ("actions { isComment actionType actionValue enabled createdAt "
                      "previousActionValue comment { id message createdOn userName } }")

_SCA_VULN_ACTIONS_QUERY = (
    "query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, "
    "$packageName: String, $packageVersion: String, $packageManager: String, "
    "$vulnerabilityId: String) "
    "{ searchPackageVulnerabilityStateAndScoreActions (scanId: $scanId, "
    "projectId: $projectId, isLatest: $isLatest, packageName: $packageName, "
    "packageVersion: $packageVersion, packageManager: $packageManager, "
    "vulnerabilityId: $vulnerabilityId) { " + _SCA_ACTION_FIELDS + " } }")

_SCA_SUPPLY_CHAIN_ACTIONS_QUERY = (
    "query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, "
    "$packageName: String, $packageVersion: String, $packageManager: String, "
    "$supplyChainRiskId: String) "
    "{ searchPackageSupplyChainRiskStateAndScoreActions (scanId: $scanId, "
    "projectId: $projectId, isLatest: $isLatest, packageName: $packageName, "
    "packageVersion: $packageVersion, packageManager: $packageManager, "
    "supplyChainRiskId: $supplyChainRiskId) { " + _SCA_ACTION_FIELDS + " } }")


@dataclass(frozen=True)
class TriageEvent:
    """One triage change: what it became, who did it, when, and why."""

    state: str
    severity: str
    comment: str
    user: str
    created_at: str
    previous_state: str = ""
    predicate_id: str = ""
    origin: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def describe(self) -> str:
        who = self.user or "(unknown user)"
        when = (self.created_at or "")[:19].replace("T", " ")
        line = f"{when}  {who:<28} {self.state or '(no state)'}"
        if self.previous_state:
            line = f"{when}  {who:<28} {self.previous_state} -> {self.state}"
        return f"{line}\n      {self.comment}" if self.comment else line


def _norm_state(raw: str) -> str:
    """`ProposedNotExploitable` / `PROPOSED_NOT_EXPLOITABLE` -> `Proposed Not Exploitable`."""
    if not raw:
        return ""
    if "_" in raw:
        return raw.replace("_", " ").title()
    import re
    return re.sub(r"(?<!^)(?=[A-Z])", " ", raw).title()


def _predicate_events(payload: dict) -> list[TriageEvent]:
    """Parse the shared `predicateHistoryPerProject` shape (SAST / KICS / Secrets).

    The three services agree on the envelope but not the case of the predicate
    id key: SAST and KICS emit `ID`, Secrets emits `id`. SAST alone carries
    `commentJSON` (with its own `user`, which is the authoritative one when
    both are present) and `changeOriginName`.
    """
    out: list[TriageEvent] = []
    for project_block in (payload or {}).get("predicateHistoryPerProject") or []:
        for p in project_block.get("predicates") or []:
            comment_json = p.get("commentJSON") or {}
            out.append(TriageEvent(
                state=_norm_state(str(p.get("state") or "")),
                severity=str(p.get("severity") or ""),
                comment=str(comment_json.get("content") or p.get("comment") or ""),
                user=str(comment_json.get("user") or p.get("createdBy") or ""),
                created_at=str(p.get("createdAt") or ""),
                predicate_id=str(p.get("ID") or p.get("id") or ""),
                origin=str(p.get("changeOriginName") or ""),
            ))
    out.sort(key=lambda e: e.created_at, reverse=True)
    return out


def _sca_events(actions: list[dict]) -> list[TriageEvent]:
    """Parse SCA GraphQL actions into events, newest first.

    Only `ChangeState` actions are triage decisions; the same feed also carries
    score overrides and standalone comments (`isComment: true`), which would
    otherwise show up as state changes with an empty state.
    """
    out: list[TriageEvent] = []
    for a in actions or []:
        if a.get("actionType") != "ChangeState":
            continue
        comment = a.get("comment") or {}
        out.append(TriageEvent(
            state=_norm_state(str(a.get("actionValue") or "")),
            severity="",
            comment=str(comment.get("message") or ""),
            user=str(comment.get("userName") or ""),
            created_at=str(a.get("createdAt") or ""),
            previous_state=_norm_state(str(a.get("previousActionValue") or "")),
        ))
    out.sort(key=lambda e: e.created_at, reverse=True)
    return out


def _containers_events(payload: dict) -> list[TriageEvent]:
    """Parse the containers triage-history shape.

    Unlike the predicate services, this one nests the state change inside
    `actions[].events[]` while the comment and user sit on the parent action.
    """
    out: list[TriageEvent] = []
    for action in (payload or {}).get("actions") or []:
        comment = str(action.get("comment") or "")
        user = str(action.get("user") or "")
        when = str(action.get("createDate") or "")
        for ev in action.get("events") or []:
            if ev.get("actionType") != "StateChanged":
                continue
            out.append(TriageEvent(
                state=_norm_state(str(ev.get("newValue") or "")),
                severity="",
                comment=comment,
                user=user,
                created_at=when,
                previous_state=_norm_state(str(ev.get("oldValue") or "")),
                predicate_id=str(ev.get("id") or ""),
            ))
    out.sort(key=lambda e: e.created_at, reverse=True)
    return out


def _predicate_params(project_id: str, comment_json: bool) -> dict:
    params = {"project-ids": project_id}
    if comment_json:
        params["include-comment-json"] = "true"
    return params


def _parse(payload, engine: str) -> list[TriageEvent]:
    return _predicate_events(payload if isinstance(payload, dict) else {})


# The three predicate GETs are written as separate call sites, each interpolating
# its own module-level constant, rather than one helper taking the endpoint as a
# parameter. That keeps every endpoint statically visible to validate_spec.py's
# scraper — behind a parameter they collapse to an unattributable `/api/{}/{}`.
def _sast_predicates(api, similarity_id: str, project_id: str) -> list[TriageEvent]:
    try:
        payload = api.get(f"{_SAST_PREDICATES}/{encode_path_segment(similarity_id)}",
                          params=_predicate_params(project_id, True),
                          extra_headers=_VERSION_HEADERS)
    except Exception as exc:                            # noqa: BLE001
        logger.warning("SAST triage history lookup failed: %s", exc)
        return []
    return _parse(payload, "SAST")


def _kics_predicates(api, similarity_id: str, project_id: str) -> list[TriageEvent]:
    try:
        payload = api.get(f"{_KICS_PREDICATES}/{encode_path_segment(similarity_id)}",
                          params=_predicate_params(project_id, False),
                          extra_headers=_VERSION_HEADERS)
    except Exception as exc:                            # noqa: BLE001
        logger.warning("IaC triage history lookup failed: %s", exc)
        return []
    return _parse(payload, "IaC")


def _secrets_predicates(api, similarity_id: str, project_id: str) -> list[TriageEvent]:
    try:
        payload = api.get(f"{_SECRETS_PREDICATES}/{encode_path_segment(similarity_id)}",
                          params=_predicate_params(project_id, False),
                          extra_headers=_VERSION_HEADERS)
    except Exception as exc:                            # noqa: BLE001
        logger.warning("Secrets triage history lookup failed: %s", exc)
        return []
    return _parse(payload, "Secrets")


def _sca_history(api, result: dict, scan_id: str, project_id: str) -> list[TriageEvent]:
    """Triage history for one SCA finding, across both risk-type queries.

    Regular advisories live in the vulnerability action store; malicious /
    typosquat ones in the supply-chain store. Which applies isn't knowable from
    the result row alone, so try the regular query and fall back — a miss costs
    one extra call and returns `actions: []`, never an error.
    """
    from .sca_live_state import _graphql, risk_uuid_map, _package_name, _package_version

    data = result.get("data") or {}
    package = str(data.get("packageIdentifier") or "")
    manager = package.split("-", 1)[0] if package else ""
    name = str(data.get("packageName") or _package_name(package, manager))
    version = _package_version(package)
    advisory = str(result.get("id") or "")

    base = {"scanId": scan_id, "projectId": project_id, "isLatest": True,
            "packageName": name, "packageVersion": version, "packageManager": manager}

    payload = _graphql(api, _SCA_VULN_ACTIONS_QUERY,
                       {**base, "vulnerabilityId": advisory}, "triage-history")
    actions = ((payload or {}).get("searchPackageVulnerabilityStateAndScoreActions")
               or {}).get("actions") or []
    if actions:
        return _sca_events(actions)

    # Supply-chain risks need the FULL risk uuid; the short `Cx…-…` form in
    # /api/results returns zero actions here (see ops/sca_live_state.risk_uuid_map).
    risk_uuid = risk_uuid_map(api, project_id).get(advisory, advisory)
    payload = _graphql(api, _SCA_SUPPLY_CHAIN_ACTIONS_QUERY,
                       {**base, "supplyChainRiskId": risk_uuid}, "supply-chain triage-history")
    actions = ((payload or {}).get("searchPackageSupplyChainRiskStateAndScoreActions")
               or {}).get("actions") or []
    return _sca_events(actions)


def _containers_history(api, result: dict, scan_id: str, project_id: str) -> list[TriageEvent]:
    from .triage.containers_handler import _PackageIndex

    package_id, cve_id, why = _PackageIndex(api, logger).resolve(scan_id, result)
    if not package_id:
        logger.warning("Containers triage history unavailable: %s", why)
        return []
    try:
        payload = api.post(f"{_CONTAINERS_HISTORY}/{project_id}/{scan_id}",
                           json_body={"packageId": package_id, "cveId": cve_id},
                           idempotent=True, extra_headers=_VERSION_HEADERS)
    except Exception as exc:                            # noqa: BLE001
        logger.warning("Containers triage history lookup failed: %s", exc)
        return []
    return _containers_events(payload if isinstance(payload, dict) else {})


def history_for(api, result: dict, scan_id: str, project_id: str) -> list[TriageEvent]:
    """Every triage change for one finding, newest first.

    `result` is a raw row from ``GET /api/results``. An empty list means the
    finding was never triaged, OR that its engine has no history endpoint
    (API Security). Failures are logged and return empty — a caller must not
    read "no history" as "never triaged" without checking the log.
    """
    engine = (result.get("type") or "").lower()
    similarity_id = str(result.get("similarityId") or "")

    if engine == "sast":
        # similarityId, NOT the attack-vector id, even on AV tenants.
        return _sast_predicates(api, similarity_id, project_id)
    if engine == "kics":
        return _kics_predicates(api, similarity_id, project_id)
    if engine == "sscs-secret-detection":
        return _secrets_predicates(api, similarity_id, project_id)
    if engine == "sca":
        return _sca_history(api, result, scan_id, project_id)
    if engine == "containers":
        return _containers_history(api, result, scan_id, project_id)
    logger.debug("No triage-history endpoint for engine '%s'.", engine)
    return []


def latest_for(api, result: dict, scan_id: str, project_id: str) -> TriageEvent | None:
    """The most recent triage change for one finding, or None if never triaged."""
    events = history_for(api, result, scan_id, project_id)
    return events[0] if events else None
