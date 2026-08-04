"""
SCA triage handler.

Uses the SCA Export Service (ScanReportJson) for richer structured data than
/api/results provides, then triages via three Management-of-Risk *bulk* endpoints.

IMPORTANT API shape: in every management-of-risk bulk call, `actions` is a
TOP-LEVEL sibling of the item list and applies to ALL items in that call. So we
group items by their target state and make one bulk call per group.

  Vulnerabilities       POST sca/management-of-risk/package-vulnerabilities/bulk
                        {packageVulnerabilitiesProfile:[...], actions:[{actionType,value,comment}]}
  Supply-chain risks    POST sca/management-of-risk/package-supply-chain-risks/bulk
                        {packageSupplyChainRisks:[...], actions:[...]}
  Packages (mute/snooze) POST sca/management-of-risk/packages/bulk
                        {packagesProfile:[...], actions:[{actionType:"Ignore", value:{state,endDate}, comment}]}

We distinguish supply-chain risks from regular vulnerabilities by the export's
`Vulnerabilities[].Type` ("Regular" = vulnerability; anything else = supply-chain).
Risk states: ToVerify, NotExploitable, ProposedNotExploitable, Confirmed, Urgent.
"""

import logging
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .base_handler import BaseTriageHandler, TriageSummary
from cxone import ApiClient
from cxone import CxConfig as Config
from ops.state_normalize import (
    sca_risk_state_to_api,
    sca_risk_state_to_display,
    sca_package_state_to_api,
    severity_normalize_for_match,
    is_to_verify,
)

_VULN_BULK = "sca/management-of-risk/package-vulnerabilities/bulk"
_SUPPLY_CHAIN_BULK = "sca/management-of-risk/package-supply-chain-risks/bulk"
_PACKAGES_BULK = "sca/management-of-risk/packages/bulk"

# Current SCA triage state lives behind GraphQL, not the scan — see
# ops/sca_live_state.py for the full read model. SCA scans are IMMUTABLE, so the
# export's RiskState is as-of-scan and must never be treated as current.
from ops.sca_live_state import (
    live_vuln_states as _live_vuln_states,
    supply_chain_state as _supply_chain_state,
    risk_uuid_map as _risk_uuid_map,
)

# Severities that, when an exploitable path exists, escalate straight to Urgent.
_HIGH_SEVERITIES = {"CRITICAL", "HIGH"}
# Default snooze window for vulnerable packages with no available fix.
_SNOOZE_DAYS = 90

# States that DISMISS a finding. Simulated triage may never apply these to a
# supply-chain risk (malicious / typosquatted / compromised package): the states
# are a fabricated roll, not an analyst's judgement, and "Not Exploitable" on real
# malware is the one wrong answer that actively hides it. Matched pre-API-mapping,
# i.e. against realism/rule output ("Not Exploitable", "Proposed Not Exploitable").
_DISMISSIVE_STATES = {"Not Exploitable", "Proposed Not Exploitable"}


class SCAHandler(BaseTriageHandler):
    """SCA triage: vulnerabilities, supply-chain risks, and package state."""

    ENGINE = "sca"

    def __init__(
        self,
        config: Config,
        api: ApiClient,
        risk_rules: list[dict],
        package_rules: list[dict],
        dry_run: bool = False,
        logger: logging.Logger | None = None,
        realism: "Any | None" = None,
        diligence: float = 1.0,
        intensity: str | float = "moderate",
        seed: int | None = None,
        budget: "Any | None" = None,
    ):
        super().__init__(config, api, risk_rules, dry_run, logger,
                         realism=realism, diligence=diligence, intensity=intensity,
                         seed=seed, budget=budget)
        self.package_rules = package_rules

    # ------------------------------------------------------------------ entry
    def process(self, project_id: str, project_name: str, scan_id: str) -> TriageSummary:
        summary = TriageSummary(engine=self.ENGINE, project_name=project_name,
                                project_id=project_id, scan_id=scan_id)
        self._intended: dict[str, str] = {}
        try:
            report = self._get_sca_report(scan_id, project_name)
            if not report:
                return summary
            vulns = report.get("Vulnerabilities", []) or []
            packages = report.get("Packages", []) or []

            self._apply_live_states(scan_id, project_id, vulns)
            regular = [v for v in vulns if not self._is_supply_chain(v)]
            supply = [v for v in vulns if self._is_supply_chain(v)]
            summary.results_fetched = len(vulns) + len(packages)
            self.logger.info(
                "[SCA] %s — report: %d vulnerabilities, %d supply-chain risks, %d packages",
                project_name, len(regular), len(supply), len(packages),
            )

            # Packages whose vulnerabilities have an exploitable path are real,
            # actionable risks (the vuln triage just escalated them to Urgent/
            # Confirmed). Never mute/snooze such a package — that would suppress the
            # very risks we flagged. Build the exclude-set from ALL vulns.
            exploitable_pkgs = {
                self._pkg_key(v.get("PackageName"), v.get("PackageVersion"))
                for v in vulns if self._is_exploitable(v)
            }
            # Packages carrying a SUPPLY-CHAIN risk must never be muted/snoozed.
            #
            # `IsMalicious` alone does not identify these. Observed live: two npm
            # packages each carrying a ContributorReputation supply-chain risk
            # reported IsMalicious=false, so the flag-based guard let them be
            # muted — hiding the very risk it exists to protect. The risk ENTRIES
            # (Type != 'Regular') are the reliable signal, so derive the set from
            # them, exactly as exploitable_pkgs is derived above.
            supply_chain_pkgs = {
                self._pkg_key(v.get("PackageName"), v.get("PackageVersion"))
                for v in supply
            }
            self._triage_vulnerabilities(project_id, regular, summary)
            self._triage_supply_chain(project_id, supply, summary)
            self._triage_packages(project_id, packages, exploitable_pkgs, summary,
                                  supply_chain_pkgs)
            # A 201 means the request was accepted, not that it matched anything —
            # confirm against current state.
            self.verify_states(project_id, scan_id, self._intended, summary)
        except Exception as exc:
            self.logger.error("[SCA] %s — unhandled error: %s", project_name, exc)
            summary.errors.append(str(exc))
        return summary

    def verify_states(self, project_id: str, scan_id: str, intended: dict[str, str],
                      summary: TriageSummary) -> None:
        """Re-read risk states and un-count anything that did not actually change.

        These endpoints cannot be trusted to report failure: a write that matches
        nothing still answers **201 Created** with an empty body (verified live
        2026-08-01). The status tells you the request was accepted, never that it
        applied to anything. Without this check, a silent no-op is indistinguishable
        from success and gets reported as applied.
        """
        if not intended or self.dry_run:
            return
        import time
        time.sleep(4)
        actual = _live_vuln_states(self.api, scan_id)
        if not actual:
            self.logger.warning("[SCA] Could not read live risk states; counts unconfirmed.")
            return
        bad = [(k, v, actual[k]) for k, v in intended.items()
               if k in actual and actual[k].replace("_", "").lower() != v.replace("_", "").lower()]
        if bad:
            summary.results_applied = max(0, summary.results_applied - len(bad))
            summary.results_unresolved += len(bad)
            msg = (f"{len(bad)} SCA write(s) were accepted (HTTP 200) but did not change "
                   f"state; they remain untriaged.")
            self.logger.error("[SCA] %s", msg)
            summary.errors.append(msg)
            for rid, want, got in bad[:10]:
                self.logger.error("[SCA]     %-22s wanted %-24s still %s", rid, want, got)

    def _apply_live_states(self, scan_id: str, project_id: str, vulns: list[dict]) -> None:
        """Replace each export entry's scan-time RiskState with the CURRENT one.

        Without this, every pass sees `ToVerify` (the scan is immutable) and
        re-triages findings that were already triaged — the agent would flip the
        same risks on every run and re-post comments.
        """
        bulk = _live_vuln_states(self.api, scan_id)
        uuids = None
        updated = 0
        for v in vulns:
            advisory = str(v.get("Id") or "")
            state = bulk.get(advisory)
            if state is None and self._is_supply_chain(v):
                if uuids is None:
                    uuids = _risk_uuid_map(self.api, project_id)
                state = _supply_chain_state(
                    self.api, scan_id, project_id,
                    package_name=v.get("PackageName"), package_version=v.get("PackageVersion"),
                    package_manager=v.get("PackageManager"),
                    risk_uuid=uuids.get(advisory, advisory))
            if state and state != v.get("RiskState"):
                v["RiskState"] = state
                updated += 1
        if updated:
            self.logger.info("[SCA] %d risk(s) already carry a triage state from a previous "
                             "pass (the scan itself still reports them as ToVerify).", updated)

    @staticmethod
    def _is_supply_chain(vuln: dict) -> bool:
        """Supply-chain risk (e.g. Suspected Malware) vs a regular CVE vulnerability.
        The export marks regular vulnerabilities Type='Regular'; other types are
        supply-chain risks, which use a different endpoint and id field."""
        return (str(vuln.get("Type") or "Regular").strip().lower() != "regular")

    @staticmethod
    def _is_exploitable(vuln: dict) -> bool:
        """A reachable/exploitable-path finding — the priority signal."""
        return (vuln.get("ExploitablePath") is True
                or str(vuln.get("ExploitabilityStatus") or "").strip().lower() == "exploitable")

    @staticmethod
    def _pkg_key(name, version) -> tuple:
        return (str(name or "").strip().lower(), str(version or "").strip())

    # --------------------------------------------------- vulnerabilities
    def _decide_vuln_state(self, vuln: dict) -> tuple[str, str] | None:
        """Return (state, comment) for a vulnerability, or None to leave untouched.

        Exploitable-path findings are what a real team prioritizes, so they are
        (almost) always triaged and default to Urgent (Critical/High) or Confirmed
        (Medium and below). Everything else flows through the realism coverage +
        outcome model, leaving a realistic untouched tail.
        """
        severity = severity_normalize_for_match(vuln.get("Severity") or "")
        if self._is_exploitable(vuln):
            state = "Urgent" if severity in _HIGH_SEVERITIES else "Confirmed"
            note = ("Exploitable path confirmed from the application to this dependency — "
                    + ("escalating for an immediate fix." if state == "Urgent"
                       else "confirming as a real, reachable risk."))
            return (state, note)
        # Non-exploitable: let the realism model decide coverage + outcome.
        rule = self._decide_state(severity, str(vuln.get("Id") or ""))  # {state, comment} or None
        if not rule:
            return None
        return (rule.get("state", ""), rule.get("comment", ""))

    def _triage_vulnerabilities(self, project_id, vulns, summary) -> None:
        if not vulns:
            return
        if self.realism is not None and getattr(self.realism, "enabled", False):
            vulns = sorted(vulns, key=self.realism.priority_key)
        # Group by (target state, comment) so each bulk call carries one action set.
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for v in vulns:
            # Only triage untriaged (To-Verify) risks. Once a prior pass has set a
            # state, leave it — otherwise repeated agent passes flip the same
            # finding between states and re-post notes. (Was: skip only if already
            # in the *target* state, which still allowed cross-state churn.)
            if not is_to_verify(v.get("RiskState") or ""):
                summary.results_skipped += 1
                continue
            decided = self._decide_vuln_state(v)
            if not decided:
                continue
            state, comment = decided
            target_api = sca_risk_state_to_api(state)
            if not all([v.get("Id"), v.get("PackageName"), v.get("PackageVersion"), v.get("PackageManager")]):
                summary.errors.append(f"Missing SCA vuln fields for {v.get('Id')}")
                continue
            summary.results_matched += 1
            groups[(target_api, comment)].append(v)
        for (state_api, _c), items in groups.items():
            self._intended.update({str(i.get("Id")): state_api for i in items})
        self._post_risk_groups(_VULN_BULK, "packageVulnerabilitiesProfile",
                               "vulnerabilityId", project_id, groups, summary, "vuln")

    # --------------------------------------------------- supply-chain risks
    def _triage_supply_chain(self, project_id, risks, summary) -> None:
        if not risks:
            return
        if self.realism is not None and getattr(self.realism, "enabled", False):
            risks = sorted(risks, key=self.realism.priority_key)
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for r in risks:
            # Only triage untriaged (To-Verify) supply-chain risks — same rule as
            # vulns, so repeated passes don't re-flip already-triaged risks.
            if not is_to_verify(r.get("RiskState") or ""):
                summary.results_skipped += 1
                continue
            severity = severity_normalize_for_match(r.get("Severity") or "")
            rule = self._decide_state(severity, str(r.get("Id") or ""))
            if not rule:
                continue
            state = rule.get("state", "")
            comment = rule.get("comment", "")
            # HARD FLOOR: simulated triage must never DISMISS a supply-chain risk.
            #
            # These are malicious/typosquatted/compromised packages. The realism
            # model is severity-driven and has no concept of maliciousness, so it
            # happily returned Not Exploitable / Proposed Not Exploitable here —
            # ~30% of Critical supply-chain risks and ~90% of Low ones. Two paths
            # produced it: the `sca_risks` outcome table lists Not Exploitable
            # directly, and the model's exception_rate can emit ANY state via
            # rng.choice(ACTIVE_STATES) regardless of the table.
            #
            # Coverage is left alone on purpose — a realistic team still leaves a
            # tail untriaged, and _decide_state returning None above is untouched.
            # What is clamped is the OUTCOME: if this code triages a supply-chain
            # risk at all, it may only ever affirm it.
            if state in _DISMISSIVE_STATES:
                state = "Confirmed"
                comment = ("Supply-chain risk affirmed: malicious/compromised package "
                           "findings are not dismissed by automated triage.")
            target_api = sca_risk_state_to_api(state)
            if not all([r.get("Id"), r.get("PackageName"), r.get("PackageVersion"), r.get("PackageManager")]):
                summary.errors.append(f"Missing supply-chain fields for {r.get('Id')}")
                continue
            summary.results_matched += 1
            groups[(target_api, comment)].append(r)
        for (state_api, _c), items in groups.items():
            self._intended.update({str(i.get("Id")): state_api for i in items})
        self._post_risk_groups(_SUPPLY_CHAIN_BULK, "packageSupplyChainRisks",
                               "supplyChainRiskId", project_id, groups, summary, "supply-chain")

    def _post_risk_groups(self, endpoint, list_key, id_field, project_id,
                          groups, summary, label) -> None:
        """One bulk POST per (state, comment) group; actions apply to all items."""
        for (state_api, comment), items in groups.items():
            profile = [{
                "packageName": it.get("PackageName"),
                "packageVersion": it.get("PackageVersion"),
                "packageManager": it.get("PackageManager"),
                id_field: it.get("Id"),
                "projectIds": [project_id],
            } for it in items]
            payload = {
                list_key: profile,
                "actions": [{"actionType": "ChangeState", "value": state_api, "comment": comment}],
            }
            if self.dry_run:
                self.logger.info("[DRY-RUN][SCA-%s] Would set %d item(s) -> %s",
                                 label, len(profile), sca_risk_state_to_display(state_api))
                summary.results_applied += len(profile)
                continue
            try:
                # absolute state set. These answer 201 Created with an EMPTY body,
                # so log the status explicitly — the body alone proves nothing, and
                # assuming it does is what made working writes look broken once.
                resp = self.api.post(endpoint, json_body=payload, idempotent=True)
                summary.results_applied += len(profile)
                self.logger.debug("[SCA-%s] set %d -> %s (HTTP %s)", label, len(profile),
                                  state_api, getattr(resp, "status_code", "?"))
            except Exception as exc:
                msg = f"Failed to triage SCA {label} ({state_api}): {exc}"
                self.logger.error(msg)
                summary.errors.append(msg)

    # --------------------------------------------------- packages (mute/snooze)
    def _decide_package_action(self, pkg: dict, exploitable_pkgs: set,
                               supply_chain_pkgs: set | None = None) -> tuple[str, str | None, str] | None:
        """Signal-driven package triage: mute unused packages, snooze vulnerable
        packages with no available fix. Returns (state, endDate_iso|None, comment)
        or None to leave the package Monitored (the default).

        Packages with an exploitable-path vulnerability are excluded — those risks
        are escalated at the vuln level, so muting/snoozing the package would
        contradict (and hide) them.
        """
        if pkg.get("IsMalicious"):
            return None  # real supply-chain risk — never auto-mute
        if (supply_chain_pkgs and
                self._pkg_key(pkg.get("Name"), pkg.get("Version")) in supply_chain_pkgs):
            return None  # carries a supply-chain risk entry — never auto-mute
        if (pkg.get("PackageStateValue") or "None") != "None":
            return None  # already triaged
        has_vulns = (pkg.get("VulnerabilityCount") or 0) > 0
        if not has_vulns:
            return None  # nothing to mute/snooze
        if self._pkg_key(pkg.get("Name"), pkg.get("Version")) in exploitable_pkgs:
            return None  # has an exploitable-path risk — leave it visible & actionable
        usage = str(pkg.get("UsageType") or "").strip().lower()
        no_fix = not pkg.get("LatestVersionWithoutVulnerabilities")

        if usage == "unused":
            return ("Muted", None,
                    "Package is unused in the project (no reachable usage); muting its "
                    "vulnerabilities to focus on exploitable dependencies.")
        if no_fix:
            end = (datetime.now(tz=timezone.utc) + timedelta(days=_SNOOZE_DAYS)).isoformat()
            return ("Snooze", end,
                    f"No fixed version available yet; snoozing for {_SNOOZE_DAYS} days "
                    "while we monitor upstream for a patch.")
        return None

    def _covers_package(self, disc: str = "") -> bool:
        """A realistic team only gets to a subset of packages — scale by diligence
        and intensity so muting/snoozing looks lived-in, not exhaustive.

        Keyed per-package (via `disc`) so the decision is reproducible under a run
        seed regardless of the order packages come back from the API."""
        if self.realism is None:
            return True
        rng = self._rng_for(*getattr(self, "_ctx_key", ()), "covers", disc)
        scale = self.realism.intensity_scale(self.intensity) * float(self.diligence)
        return rng.random() < min(0.9, 0.55 * scale)

    def _triage_packages(self, project_id, packages, exploitable_pkgs, summary,
                         supply_chain_pkgs: set | None = None) -> None:
        if not packages:
            return
        # Group by (state, endDate, comment) — one bulk Ignore action per group.
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for p in packages:
            decision = self._decide_package_action(p, exploitable_pkgs, supply_chain_pkgs)
            if not decision:
                continue
            pkg_disc = str(p.get("Id") or p.get("Name") or p.get("packageName") or "")
            if not self._covers_package(pkg_disc):
                continue
            state, end_date, comment = decision
            name = p.get("Name") or p.get("packageName")
            version = p.get("Version") or p.get("packageVersion")
            manager = p.get("PackageRepository") or p.get("packageManager") or p.get("Manager")
            if not all([name, version, manager]):
                continue
            summary.results_matched += 1
            groups[(sca_package_state_to_api(state), end_date, comment)].append(
                {"projectId": project_id, "packageName": name,
                 "packageVersion": version, "packageManager": manager}
            )
        for (state_api, end_date, comment), profile in groups.items():
            payload = {
                "packagesProfile": profile,
                "actions": [{
                    "actionType": "Ignore",
                    "value": {"state": state_api, "endDate": end_date},
                    "comment": comment,
                }],
            }
            if self.dry_run:
                self.logger.info("[DRY-RUN][SCA-Pkg] Would %s %d package(s)%s",
                                 state_api, len(profile),
                                 f" until {end_date}" if end_date else "")
                summary.results_applied += len(profile)
                continue
            try:
                self.api.post(_PACKAGES_BULK, json_body=payload, idempotent=True)  # absolute state set
                summary.results_applied += len(profile)
                self.logger.debug("[SCA-Pkg] %s %d package(s)", state_api, len(profile))
            except Exception as exc:
                msg = f"Failed to triage SCA packages ({state_api}): {exc}"
                self.logger.error(msg)
                summary.errors.append(msg)

    # --------------------------------------------------- SCA export flow
    def _get_sca_report(self, scan_id: str, project_name: str) -> dict | None:
        self.logger.info("[SCA] %s — requesting SCA export for scan %s", project_name, scan_id)
        try:
            export_id = self.api.post_sca_export(scan_id, file_format="ScanReportJson")
            file_url = self.api.poll_sca_export(export_id)
            return self.api.download_sca_export(file_url)
        except TimeoutError as exc:
            self.logger.error("[SCA] %s — export timed out: %s", project_name, exc)
            return None
        except Exception as exc:
            self.logger.error("[SCA] %s — export error: %s", project_name, exc)
            return None

    # SCA uses the export service, not /api/results.
    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        return []
