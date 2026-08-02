"""
Triage operation orchestrator for the Checkmarx One Multi-Tool.

Resolves project names to IDs, finds the latest qualifying scan per engine,
and dispatches to engine-specific handlers (SAST, IaC, SCA).
"""

import logging
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ops.base import Operation
from ops.project_resolve import warn_unresolved_projects
from .base_handler import TriageSummary
from .sast_handler import SASTHandler
from .iac_handler import IaCHandler
from .sca_handler import SCAHandler
from .secrets_handler import SecretsHandler
from .containers_handler import ContainersHandler
from cxone import CxConfig as Config
from cxone import AuthManager
from cxone import ApiClient
from ops.config_loader import load_yaml_config
from ops.realism import RealismModel
from ops.logger import get_logger

# Mapping from CLI scan-type names to API engine identifiers.
# status_detail_name is the per-engine name in a scan's statusDetails (used to find
# a scan where that engine completed). Secret detection reports under 'microengines'.
_ENGINE_MAP = {
    "sast":       {"result_type": "sast", "status_detail_name": "sast"},
    "iac":        {"result_type": "kics", "status_detail_name": "kics"},
    "sca":        {"result_type": "sca",  "status_detail_name": "sca"},
    "secrets":    {"result_type": "sscs-secret-detection", "status_detail_name": "microengines"},
    "containers": {"result_type": "containers", "status_detail_name": "containers"},
}


class TriageOperation(Operation):
    """Orchestrates the full triage workflow across projects and scan types."""

    def __init__(
        self,
        config: Config,
        auth: AuthManager,
        api: ApiClient,
        logger: logging.Logger,
        identity_selector=None,
    ):
        super().__init__(config, auth, api, logger, identity_selector)
        self._triage_rules: dict = {}
        self._realism: RealismModel | None = None
        self._intensity = "moderate"
        self._seed: int | None = None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def execute(self, args: Namespace) -> int:
        """Returns the number of projects actually resolved and processed —
        0 if none matched (see ScanOperation.execute for why callers need
        this; a no-op must not be recorded as work done)."""
        # Load triage rules
        rules_file = getattr(args, "rules_file", None)
        if rules_file:
            import yaml
            with open(rules_file, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            self._triage_rules = raw.get("triageRules") or raw.get("triage_rules", {})
            self._realism = RealismModel((raw.get("realism") or self._triage_rules.get("realism")))
        else:
            cfg = load_yaml_config("triage_rules.yaml")
            self._triage_rules = cfg.get("triageRules") or cfg.get("triage_rules", {})
            self._realism = RealismModel((cfg.get("realism") or self._triage_rules.get("realism")))

        self._intensity = getattr(args, "intensity", None) or "moderate"

        # Reproducible triage: a seed makes the per-finding decisions deterministic
        # so a dry-run and the live run pick the SAME findings. If none is given,
        # generate one and print it, so the run can always be reproduced/replayed.
        seed = getattr(args, "seed", None)
        if seed is None:
            import random as _r
            seed = _r.SystemRandom().randint(0, 2**31 - 1)
        self._seed = int(seed)
        self.logger.info(
            "Triage seed: %d  (pass --seed %d to reproduce this exact selection)",
            self._seed, self._seed,
        )

        # Parse arguments
        project_names = [n.strip() for n in args.projects.split(",") if n.strip()]
        scan_types = [s.strip().lower() for s in args.scan_types.split(",") if s.strip()]

        unknown_types = [t for t in scan_types if t not in _ENGINE_MAP]
        if unknown_types:
            self.logger.warning(
                "Unknown scan type(s) ignored: %s. Valid: %s",
                unknown_types, list(_ENGINE_MAP.keys()),
            )
            scan_types = [t for t in scan_types if t in _ENGINE_MAP]

        if not scan_types:
            self.logger.error("No valid scan types specified. Aborting.")
            return 0

        # Resolve projects
        projects = self._resolve_projects(project_names)
        if not projects:
            self.logger.warning("No matching projects found.")
            return 0

        self.logger.info(
            "Triaging %d project(s) for engine(s): %s with %d worker(s).",
            len(projects), scan_types, self.config.workers,
        )

        all_summaries: list[TriageSummary] = []

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            futures = {
                pool.submit(
                    self._process_project, project, scan_types
                ): project
                for project in projects
            }
            for future in as_completed(futures):
                project = futures[future]
                try:
                    summaries = future.result()
                    all_summaries.extend(summaries)
                except Exception as exc:
                    name = project.get("name", project.get("id"))
                    self.logger.error("Error processing project '%s': %s", name, exc)

        self._print_summary(all_summaries)
        return len(projects)

    # ------------------------------------------------------------------
    # Project-level processing
    # ------------------------------------------------------------------

    def _process_project(
        self, project: dict, scan_types: list[str]
    ) -> list[TriageSummary]:
        project_id = project["id"]
        project_name = project.get("name", project_id)
        # Automatic --as specs resolve HERE, per project — a real team's projects
        # have different owners. `me` is this project's view of the operation with
        # that identity's client bound; without a selector it is just `self`.
        me, _acting = self.acting_for(project_name)   # logs the owner itself
        return me._process_project_as(project_id, project_name, scan_types)

    def _process_project_as(
        self, project_id: str, project_name: str, scan_types: list[str]
    ) -> list[TriageSummary]:
        summaries = []
        diligence = self._realism.project_diligence(project_id) if self._realism else 1.0
        # One budget per (project, pass), shared across this pass's engine
        # handlers — the human ceiling applies to the pass as a whole. Spent
        # top-down within each engine (highest severities first).
        from ops.realism import PassBudget
        budget = PassBudget(
            self._realism.pass_budget(self._intensity) if self._realism else None)
        if budget.limited:
            self.logger.info(
                "[%s] per-pass triage budget: %d applied decision(s) max "
                "(intensity=%s — human-day ceiling).",
                project_name, budget._limit, self._intensity)

        for scan_type in scan_types:
            engine_info = _ENGINE_MAP[scan_type]
            scan = self._find_latest_scan(project_id, engine_info["status_detail_name"])

            if not scan:
                self.logger.warning(
                    "[%s] %s — no qualifying scan found, skipping.",
                    scan_type.upper(), project_name,
                )
                continue

            scan_id = scan["id"]
            self.logger.info(
                "[%s] %s — using scan %s", scan_type.upper(), project_name, scan_id
            )

            handler = self._build_handler(scan_type, diligence, budget)
            summary = handler.process(project_id, project_name, scan_id)
            summaries.append(summary)

        return summaries

    # ------------------------------------------------------------------
    # Scan resolution
    # ------------------------------------------------------------------

    def _find_latest_scan(
        self, project_id: str, engine_name: str
    ) -> dict | None:
        """
        Find the most recent Completed or Partial scan where the specified
        engine completed successfully.
        """
        try:
            scans = self.api.paginate(
                "scans",
                results_key="scans",
                params={
                    "project-id": project_id,
                    "statuses": "Completed,Partial",
                    "sort": "-created_at",
                },
                limit=50,
            )
        except Exception as exc:
            self.logger.error(
                "Failed to list scans for project %s: %s", project_id, exc
            )
            return None

        # Return the newest scan where THIS engine actually completed. A scan can be
        # Completed overall yet not have run a given engine (e.g. an SCA-only re-scan),
        # so we must verify the engine — not just the overall status — or we triage
        # against a scan that has none of this engine's results.
        for scan in scans:
            if self._scan_ran_engine(scan, engine_name):
                return scan
        return None

    @staticmethod
    def _scan_ran_engine(scan: dict, engine_name: str) -> bool:
        """True if `engine_name` completed on this scan. Prefer per-engine
        statusDetails; fall back to the engines list when details are absent."""
        name = engine_name.lower()
        details = scan.get("statusDetails") or []
        for d in details:
            if (d.get("name") or "").lower() == name:
                return (d.get("status") or "").lower() == "completed"
        # No per-engine detail for this engine — trust the engines list.
        return name in [str(e).lower() for e in (scan.get("engines") or [])]

    # ------------------------------------------------------------------
    # Project resolution
    # ------------------------------------------------------------------

    def _resolve_projects(self, names: list[str]) -> list[dict]:
        self.logger.info("Resolving projects: %s", names)
        try:
            all_projects = self.api.paginate("projects", results_key="projects")
        except Exception as exc:
            self.logger.error("Failed to list projects: %s", exc)
            return []

        name_set = {n.lower() for n in names}
        matched = [p for p in all_projects if p.get("name", "").lower() in name_set]

        found = {p.get("name", "").lower() for p in matched}
        warn_unresolved_projects(self.logger, names, all_projects, found)

        return matched

    # ------------------------------------------------------------------
    # Handler factory
    # ------------------------------------------------------------------

    def _build_handler(self, scan_type: str, diligence: float = 1.0, budget=None):
        dry_run = self.config.dry_run
        ctx = dict(realism=self._realism, diligence=diligence,
                   intensity=self._intensity, seed=self._seed, budget=budget)

        match scan_type:
            case "sast":
                return SASTHandler(
                    config=self.config,
                    api=self.api,
                    rules=self._triage_rules.get("sast", []),
                    dry_run=dry_run,
                    logger=get_logger("triage.sast"),
                    grouping=self._triage_rules.get("sast_grouping"),
                    **ctx,
                )
            case "iac":
                return IaCHandler(
                    config=self.config,
                    api=self.api,
                    rules=self._triage_rules.get("iac", []),
                    dry_run=dry_run,
                    logger=get_logger("triage.iac"),
                    **ctx,
                )
            case "sca":
                return SCAHandler(
                    config=self.config,
                    api=self.api,
                    risk_rules=self._triage_rules.get("scaRisks") or self._triage_rules.get("sca_risks", []),
                    package_rules=self._triage_rules.get("scaPackages") or self._triage_rules.get("sca_packages", []),
                    dry_run=dry_run,
                    logger=get_logger("triage.sca"),
                    **ctx,
                )
            case "secrets":
                return SecretsHandler(
                    config=self.config,
                    api=self.api,
                    rules=self._triage_rules.get("secrets", []),
                    dry_run=dry_run,
                    logger=get_logger("triage.secrets"),
                    **ctx,
                )
            case "containers":
                return ContainersHandler(
                    config=self.config,
                    api=self.api,
                    rules=self._triage_rules.get("containers", []),
                    dry_run=dry_run,
                    logger=get_logger("triage.containers"),
                    **ctx,
                )
            case _:
                raise ValueError(f"Unknown scan type: {scan_type}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _print_summary(self, summaries: list[TriageSummary]) -> None:
        self.logger.info("=" * 60)
        self.logger.info("Triage Summary")
        self.logger.info("=" * 60)

        total_applied = sum(s.results_applied for s in summaries)
        total_skipped = sum(s.results_skipped for s in summaries)
        total_unresolved = sum(s.results_unresolved for s in summaries)
        total_deferred = sum(s.results_deferred for s in summaries)
        total_errors = sum(len(s.errors) for s in summaries)

        self.logger.info("Total applied  : %d", total_applied)
        self.logger.info("Total skipped  : %d (already triaged — nothing attempted)", total_skipped)
        if total_unresolved:
            # Deliberately NOT folded into `skipped`: the write was attempted and
            # REFUSED, so these findings stay untriaged. Reported as a warning
            # because it is a loss, not housekeeping.
            self.logger.warning(
                "Total unresolved: %d (write attempted but the API could not resolve "
                "the finding — still untriaged)", total_unresolved)
        if total_deferred:
            self.logger.info("Total deferred : %d (per-pass human budget reached "
                             "— left To Verify for a later pass)", total_deferred)
        self.logger.info("Total errors   : %d", total_errors)
        self.logger.info("-" * 60)

        for summary in summaries:
            summary.log(self.logger)
