"""
Container Security triage handler.

Container findings are triaged through the dedicated containers/triage service
(all endpoints require Accept: */*; version=1.0):

  Vulnerability state            POST containers/triage/triage/vulnerability-update
      {state, scanId, projectId, user, group:"vulnerabilities",
       triages:[{packageId, cveId}], comment}
  Package status (mute/snooze)  POST containers/triage/triage/package-update
      {comment, scanId, projectId, packageIds:[], status, snoozeEndDate, user}
  Image status (mute/snooze)    POST containers/triage/triage/image-update
      {comment, scanId, projectId, imageIds:[], status, snoozeEndDate}

state ∈ Confirmed, Urgent, NotExploitable, ProposedNotExploitable, ToVerify
       (PascalCase, NO spaces — see _STATE_TO_CONTAINER)
status ∈ Monitored, Muted, Snoozed  (package/image mute only)

A single vulnerability-update call carries ONE state applied to a list of
(packageId, cveId) triages, so we group findings by target state and post one
call per group. Findings come from /api/results with type 'containers'; on source
projects with no images this is a clean no-op.

We deliberately do NOT send `severity`. The UI's own vulnerability-update carries
no severity field and succeeds without it (captured 2026-07-30), and the endpoint
would treat it as a severity CHANGE — so echoing a severity read from
/api/results risks silently overwriting the scanner's rating whenever the two
sources disagree. Triage here changes state only.

The `packageId` the triage service expects is NOT derivable from /api/results —
it must be read from the containers GraphQL service. See _PackageIndex.
"""

import logging
from collections import defaultdict

from .base_handler import BaseTriageHandler, TriageSummary
from ops.state_normalize import severity_normalize_for_match

_RESULTS_TYPE = "containers"
_VULN_UPDATE = "containers/triage/triage/vulnerability-update"
_VERSION_HEADER = {"Accept": "*/*; version=1.0"}
# `group` marks a PACKAGE-LEVEL group triage — one state applied to several CVEs
# of the SAME packageId, which is how the UI's package-grouped view submits. A
# single-finding triage sends null instead. Three UI captures (2026-07-30):
#   1 CVE                      -> "vulnerabilities"   (a one-CVE package group)
#   1 CVE, with comment        -> null                (individual triage)
#   7 CVEs, one shared package -> "vulnerabilities"   (group triage)
# It does not widen the write in either form: our 20-triage call with this value
# changed exactly those 20 risks and left the other 62 To-Verify (live-checked on
# cnf26). We mirror the UI: batch per package, and label accordingly.
_VULN_GROUP = "vulnerabilities"

# Containers GraphQL ("buffet") — the ONLY authoritative source for packageId.
_GQL_ENDPOINT = "containers/buffet/graphql"
_GQL_PAGE = 100          # imagesVulnerabilities caps around this; page with skip
_VULN_QUERY = """
query GetImagesVulnerabilities($scanId: UUID!, $imageId: String, $take: Int, $skip: Int) {
  imagesVulnerabilities(scanId: $scanId, imageId: $imageId, take: $take, skip: $skip) {
    totalCount
    items {
      packageName
      packageVersion
      type
      distribution
      id
      aggregatedRisks { risksList { cve } }
    }
  }
}
"""

# Realism canonical state -> container API state.
#
# PascalCase, NO SPACES. Live-verified 2026-07-29 on cnf26: the spaced forms
# "Not Exploitable" / "Proposed Not Exploitable" are REJECTED with
# 400 {"errors":[{"message":"Invalid state: Invalid state: Not Exploitable"}]}
# while "NotExploitable" / "ProposedNotExploitable" are accepted.
#
# The public docs are self-contradictory here: the endpoint's "Allowed values"
# list shows the SPACED forms, but its own request example sends
# "state": "NotExploitable". The example is right, the allowed-values list is
# wrong — trust the live API. (Confirmed/Urgent/ToVerify have no space either
# way, which is why only these two states ever failed.)
_STATE_TO_CONTAINER = {
    "CONFIRMED": "Confirmed",
    "URGENT": "Urgent",
    "NOT_EXPLOITABLE": "NotExploitable",
    "PROPOSED_NOT_EXPLOITABLE": "ProposedNotExploitable",
    "TO_VERIFY": "ToVerify",
}

def _acting_user(api, logger: logging.Logger) -> str | None:
    """Display name for the `user` field, e.g. "Ryan Wakeham".

    This is the attribution the UI shows in a finding's triage history; the UI
    sends it explicitly on every write. Read it from the ACCESS token — the API
    key (a refresh token) carries no name claims, while the access token has
    name / given_name+family_name / preferred_username. Each identity mints its
    own access token, so `--as alice.dev` attributes to alice automatically.

    Returns None when no name can be derived; the field is then omitted rather
    than guessed, since a wrong analyst name is worse than a missing one.
    """
    try:
        from cxone.identity_pool import _decode_jwt_claims
        claims = _decode_jwt_claims(api.auth.token())
    except Exception as exc:
        logger.debug("[Containers] could not derive acting user: %s", exc)
        return None
    full = " ".join(p for p in (claims.get("given_name"), claims.get("family_name")) if p)
    return claims.get("name") or full or claims.get("preferred_username") or None



def _image_id(data: dict) -> str | None:
    """The GraphQL imageId for a finding: 'name:tag' exactly as /api/results
    reports it (registry-qualified names included, e.g.
    'gcr.io/distroless/nodejs24-debian13:latest')."""
    name = data.get("imageName")
    if not name:
        return None
    tag = data.get("imageTag")
    return f"{name}:{tag}" if tag else name


class _PackageIndex:
    """Maps a /api/results container finding to the triage service's packageId.

    WHY THIS EXISTS — the packageId cannot be constructed from result data.
    The stored id is a 4-field composite `{type}#-#{name}#-#{version}#-#{distribution}`:

        Npm#-#tar#-#7.5.15#-#debian:12          (npm package inside node:24)
        Oval#-#openssl#-#3.5.6-r0#-#alpine:3.23.4

    /api/results carries only packageName, packageVersion, imageName, imageTag —
    NEITHER `type` NOR `distribution`. `type` varies by ecosystem (Oval for OS
    packages, Npm for npm, etc.) and `distribution` is the image's BASE OS, which
    is not the image tag: node:24 -> debian:12, node:20-alpine -> alpine:3.23.4.

    An earlier version guessed `Oval#-#{name}#-#{version}#-#{image}:{tag}`. Measured
    live on cnf26 (2026-07-30) that matched 0 of 2056 findings across three
    projects — container triage had never resolved a single finding. It appeared to
    work only when checked against a distro-base image (ubuntu:22.04), where the
    image tag coincidentally equals the distribution string. Do not reintroduce a
    constructed packageId; read it from GraphQL.

    Keyed per image, because the same package+version in two images can carry
    different distributions (and therefore different ids).
    """

    def __init__(self, api, logger: logging.Logger):
        self._api = api
        self._logger = logger
        # (scan_id, image_id) -> {(package_name, package_version): (composite_id, {cve, ...})}
        self._cache: dict[tuple[str, str], dict[tuple[str, str], tuple[str, set[str]]]] = {}
        self.failed_images: dict[tuple[str, str], str] = {}

    def _load_image(self, scan_id: str, image_id: str) -> dict:
        key = (scan_id, image_id)
        if key in self._cache:
            return self._cache[key]
        packages: dict[tuple[str, str], tuple[str, set[str]]] = {}
        skip, total = 0, None
        try:
            while total is None or skip < total:
                body = {"query": _VULN_QUERY,
                        "variables": {"scanId": scan_id, "imageId": image_id,
                                      "take": _GQL_PAGE, "skip": skip}}
                resp = self._api.post(_GQL_ENDPOINT, json_body=body, idempotent=True)
                if isinstance(resp, dict) and resp.get("errors"):
                    raise RuntimeError(str(resp["errors"])[:300])
                block = ((resp or {}).get("data") or {}).get("imagesVulnerabilities") or {}
                items = block.get("items") or []
                total = block.get("totalCount") or 0
                for item in items:
                    cves = {risk.get("cve") for risk
                            in ((item.get("aggregatedRisks") or {}).get("risksList") or [])}
                    packages[(item.get("packageName"), item.get("packageVersion"))] = (
                        item.get("id"), {c for c in cves if c})
                if not items:
                    break
                skip += len(items)
        except Exception as exc:
            body_text = (getattr(getattr(exc, "response", None), "text", "") or "")
            self.failed_images[key] = (body_text.strip()[:300] or str(exc))
            self._logger.error("[Containers] packageId lookup failed for image %s: %s",
                               image_id, self.failed_images[key])
            self._cache[key] = {}
            return self._cache[key]
        self._logger.debug("[Containers] indexed %d package(s) for image %s", len(packages), image_id)
        self._cache[key] = packages
        return packages

    def resolve(self, scan_id: str, result: dict) -> tuple[str | None, str | None, str | None]:
        """-> (packageId, cveId, failure_reason). packageId is None iff unresolved."""
        data = result.get("data") or {}
        image_id = _image_id(data)
        cve_id = ((result.get("vulnerabilityDetails") or {}).get("cveName")
                  or result.get("cveId") or data.get("cveId") or result.get("id"))
        if not image_id:
            return None, cve_id, "finding carries no image name"
        packages = self._load_image(scan_id, image_id)
        if (scan_id, image_id) in self.failed_images:
            return None, cve_id, f"GraphQL lookup failed for image {image_id}"
        entry = packages.get((data.get("packageName"), data.get("packageVersion")))
        if not entry:
            return None, cve_id, (f"package {data.get('packageName')}@"
                                  f"{data.get('packageVersion')} not present in {image_id}")
        composite_id, cves = entry
        if cve_id not in cves:
            return None, cve_id, (f"cve {cve_id} not among the stored risks for "
                                  f"{data.get('packageName')}@{data.get('packageVersion')}")
        return composite_id, cve_id, None


class ContainersHandler(BaseTriageHandler):

    ENGINE = "containers"

    def __init__(self, *args, scan_id: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._scan_id = scan_id
        self._index = _PackageIndex(self.api, self.logger)
        self._user: str | None | bool = False   # False = not yet resolved

    @property
    def acting_user(self) -> str | None:
        if self._user is False:
            self._user = _acting_user(self.api, self.logger)
        return self._user

    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        self._scan_id = scan_id
        return self._get_results_page(scan_id, _RESULTS_TYPE)

    def apply_triage(self, project_id, matched_results, summary) -> None:
        if not matched_results:
            return
        # Batch by (state, comment, packageId) — one call per package, mirroring the
        # UI's package-grouped triage. Not one big mixed-package call: the service
        # accepts that, but no human action produces it, and per-package batching is
        # how the screen is actually worked.
        groups: dict[tuple, list[dict]] = defaultdict(list)
        unresolved_reasons: dict[str, int] = defaultdict(int)
        for result in matched_results:
            rule = result["_matched_rule"]
            # Resolution reads GraphQL, so it runs in dry-run too — the preview
            # then reports honestly what would and would not resolve.
            package_id, cve_id, reason = self._index.resolve(self._scan_id, result)
            if not package_id or not cve_id:
                summary.results_unresolved += 1
                unresolved_reasons[reason or "missing packageId/cveId"] += 1
                continue
            state = _STATE_TO_CONTAINER.get(severity_normalize_for_match(rule.get("state", "")))
            if not state:
                continue
            groups[(state, rule.get("comment", ""), package_id)].append(
                {"packageId": package_id, "cveId": cve_id}
            )

        for (state, comment, _package_id), triages in groups.items():
            payload = {
                "state": state,
                "scanId": self._scan_id,
                "projectId": project_id,
                # Group triage when several CVEs of this package share the decision;
                # null for a lone finding — the two shapes the UI produces.
                "group": _VULN_GROUP if len(triages) > 1 else None,
                "triages": triages,
                "comment": comment,
            }
            if self.acting_user:
                payload["user"] = self.acting_user
            if self.dry_run:
                self.logger.info("[DRY-RUN][Containers] Would set %d finding(s) -> %s (as %s, %s)",
                                 len(triages), state, self.acting_user or "unattributed",
                                 "group triage" if len(triages) > 1 else "individual")
                summary.results_applied += len(triages)
                continue
            try:
                self.api.post(_VULN_UPDATE, json_body=payload, extra_headers=_VERSION_HEADER,
                              idempotent=True)  # sets absolute states; replay converges
                summary.results_applied += len(triages)
            except Exception as exc:
                # Classify on the RESPONSE BODY only. A previous version also
                # treated any exception whose text contained "400" as an
                # unresolvable packageId, which silently swallowed unrelated
                # 400s — that catch-all is what hid a real "Invalid state" bug
                # (spaced state values) behind a packageId story for weeks, and
                # counted the losses as benign "skipped". Never widen this back
                # to a bare status-code match.
                body = (getattr(getattr(exc, "response", None), "text", "") or "")
                low = body.lower()
                if "risk not found" in low:
                    # The service rejected an id that GraphQL reported as stored.
                    # Not a construction guess any more, so this now means a real
                    # mismatch worth seeing (e.g. results and GraphQL disagreeing
                    # about a scan) rather than an expected shortfall.
                    summary.results_unresolved += len(triages)
                    unresolved_reasons[
                        "service reported 'risk not found' for a GraphQL-supplied packageId"
                    ] += len(triages)
                else:
                    detail = body.strip()[:300] or str(exc)
                    msg = (f"Container triage rejected (state={state}, "
                           f"{len(triages)} finding(s)): {detail}")
                    self.logger.error(msg)
                    summary.errors.append(msg)

        for reason, count in unresolved_reasons.items():
            self.logger.warning("[Containers] %d finding(s) unresolved — %s. These were NOT "
                                "already triaged; no write was applied.", count, reason)
