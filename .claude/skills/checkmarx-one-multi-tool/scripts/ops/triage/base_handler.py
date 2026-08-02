"""
Base class and shared utilities for triage engine handlers.

Provides:
- TriageSummary dataclass for accumulating per-engine results.
- BaseTriageHandler abstract class with percentage-based rule matching.
"""

import random
import logging
from dataclasses import dataclass, field
from typing import Any

from cxone import ApiClient
from cxone import CxConfig as Config
from ops.logger import get_logger
from ops.state_normalize import severity_normalize_for_match, is_to_verify


@dataclass
class TriageSummary:
    """Accumulates triage results for a single engine + project run."""
    engine: str
    project_name: str
    project_id: str
    scan_id: str
    results_fetched: int = 0
    results_matched: int = 0
    results_applied: int = 0
    results_skipped: int = 0   # not actionable: ALREADY TRIAGED (not To-Verify). Nothing was attempted.
    # Attempted but the API refused because the finding's id couldn't be resolved
    # (containers: reconstructed packageId matched no stored risk). Distinct from
    # `skipped` on purpose: these are LOSSES, not benign no-ops, and folding them
    # into "already triaged" made a real defect look like normal housekeeping.
    results_unresolved: int = 0
    results_deferred: int = 0  # coverage said "triage it" but the per-pass human budget was spent — stays To Verify for a later pass
    errors: list[str] = field(default_factory=list)

    def log(self, logger: logging.Logger) -> None:
        deferred = f" deferred={self.results_deferred}" if self.results_deferred else ""
        unresolved = f" unresolved={self.results_unresolved}" if self.results_unresolved else ""
        logger.info(
            "[%s] %s — fetched=%d matched=%d applied=%d skipped=%d%s%s errors=%d",
            self.engine.upper(), self.project_name,
            self.results_fetched, self.results_matched,
            self.results_applied, self.results_skipped, unresolved, deferred,
            len(self.errors),
        )
        for err in self.errors:
            logger.warning("  error: %s", err)


class BaseTriageHandler:
    """
    Abstract base for SAST, IaC, and SCA triage handlers.

    Subclasses must implement:
        fetch_results(project_id, scan_id) -> list[dict]
        apply_triage(project_id, results_to_triage, summary) -> None
    """

    ENGINE = "base"

    def __init__(
        self,
        config: Config,
        api: ApiClient,
        rules: list[dict],
        dry_run: bool = False,
        logger: logging.Logger | None = None,
        realism: "Any | None" = None,
        diligence: float = 1.0,
        intensity: str | float = "moderate",
        seed: int | None = None,
        budget: "Any | None" = None,
    ):
        self.config = config
        self.api = api
        self.rules = rules
        self.dry_run = dry_run
        self.logger = logger or get_logger(f"triage.{self.ENGINE}")
        self.realism = realism          # ops.realism.RealismModel | None
        self.diligence = diligence      # per-project diligence factor
        self.intensity = intensity      # coverage intensity (light/some/moderate/thorough/heavy or float)
        self.seed = seed                # base run seed for reproducible triage decisions
        self.budget = budget            # ops.realism.PassBudget | None — shared per-project pass ceiling
        self._deferred = 0              # positive decisions dropped because the budget was spent
        self._budget_taken = 0          # takes this pass — refundable if the writes provably never landed

    def _rng_for(self, *parts: str) -> "random.Random":
        """Build a deterministic RNG from the run seed + a per-context key.

        Keying on (seed, engine, project/scan) gives each project×engine its own
        independent-but-reproducible stream, so a dry-run and a live run with the
        same seed make identical decisions, while different projects don't share a
        stream. With no seed, falls back to non-deterministic randomness.
        """
        if self.seed is None:
            return random.Random()
        key = "|".join((str(self.seed), self.ENGINE, *parts))
        # Hash the composite key to a stable 64-bit integer seed.
        import hashlib
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return random.Random(int(digest[:16], 16))

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def process(
        self,
        project_id: str,
        project_name: str,
        scan_id: str,
    ) -> TriageSummary:
        # Context for deterministic RNG derivation this run (project+scan uniquely
        # identify the finding set, so the same seed reproduces the same decisions).
        self._ctx_key = (project_id, scan_id)
        summary = TriageSummary(
            engine=self.ENGINE,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
        )

        try:
            results = self.fetch_results(project_id, scan_id)
            summary.results_fetched = len(results)
            self.logger.info(
                "[%s] %s — fetched %d results from scan %s",
                self.ENGINE.upper(), project_name, len(results), scan_id,
            )

            self._deferred = 0
            self._budget_taken = 0
            matched = self.match_rules(results)
            summary.results_matched = len(matched)

            self.apply_triage(project_id, matched, summary)
            summary.results_deferred = self._deferred

        except Exception as exc:
            self.logger.error(
                "[%s] %s — unhandled error: %s", self.ENGINE.upper(), project_name, exc
            )
            summary.errors.append(str(exc))

        return summary

    # ------------------------------------------------------------------
    # Rule matching (shared by SAST and IaC; overridden by SCA)
    # ------------------------------------------------------------------

    def match_rules(self, results: list[dict]) -> list[dict]:
        """
        Decide which results to triage and to what state.

        When a RealismModel is attached (default), use the two-stage realistic
        model: process results top-down (highest severity first) and, per result,
        run the coverage stage (whether a real team would have triaged it given
        severity, engine, project diligence, and intensity) and the outcome stage
        (which state). Otherwise fall back to the legacy weighted single-roll over
        the per-severity bands in `self.rules`.
        """
        if self.realism is not None and getattr(self.realism, "enabled", False):
            return self._match_realistic(results)

        matched = []
        for result in results:
            severity = severity_normalize_for_match(result.get("severity") or "")
            virtual_rule = self._find_matching_rule(severity)
            if virtual_rule:
                result = dict(result)
                result["_matched_rule"] = virtual_rule
                matched.append(result)
        return matched

    def _match_realistic(self, results: list[dict]) -> list[dict]:
        """Realism-model matching: top-down ordering + coverage/outcome stages."""
        engine = self.ENGINE  # 'sast' | 'kics' (-> iac alias inside model) | 'sca'
        ordered = sorted(results, key=self.realism.priority_key)
        matched = []
        for result in ordered:
            severity = severity_normalize_for_match(result.get("severity") or "")
            # Per-finding RNG keyed on a stable id, so the same seed reproduces the
            # same decision regardless of the order results arrive from the API.
            disc = str(result.get("similarityId") or result.get("id") or "")
            rng = self._rng_for(*getattr(self, "_ctx_key", ()), disc)
            triage, state = self.realism.decide(
                severity, engine, self.diligence, self.intensity, rng
            )
            if triage and state:
                # Budget gate sits AFTER the draw: per-finding RNG is keyed by
                # the finding id, so consuming the budget never shifts another
                # finding's dice — a given seed reproduces the same decisions,
                # the budget only truncates how many get APPLIED. Results are
                # processed top-down, so the budget is spent on the highest
                # severities first.
                if self.budget is not None and not self.budget.take():
                    self._deferred += 1
                    continue
                self._budget_taken += 1
                result = dict(result)
                result["_matched_rule"] = {
                    "state": state,
                    "comment": self.realism.comment_for(state, rng, self.ENGINE),
                }
                matched.append(result)
        if self._deferred:
            self.logger.info(
                "[%s] per-pass triage budget reached — %d additional finding(s) "
                "the model would have triaged stay To Verify for a later pass "
                "(a human day only holds so many decisions).",
                self.ENGINE.upper(), self._deferred)
        return matched

    def _decide_state(self, severity_raw: str, disc: str = "") -> dict | None:
        """
        Single source of truth for 'should this finding be triaged, and to what
        state' — used by the SCA risk path (which doesn't go through match_rules).
        Uses the realism model when enabled, else the legacy band roll.

        `disc` is a per-finding discriminator (e.g. an id) so each finding gets its
        own reproducible draw under a given run seed, rather than all findings of a
        severity sharing one decision.
        """
        severity = severity_normalize_for_match(severity_raw or "")
        if self.realism is not None and getattr(self.realism, "enabled", False):
            rng = self._rng_for(*getattr(self, "_ctx_key", ()), "risk", severity, disc)
            triage, state = self.realism.decide(
                severity, self.ENGINE, self.diligence, self.intensity, rng
            )
            if triage and state:
                if self.budget is not None and not self.budget.take():
                    self._deferred += 1
                    return None
                self._budget_taken += 1
                return {"state": state,
                        "comment": self.realism.comment_for(state, rng, self.ENGINE)}
            return None
        return self._find_matching_rule(severity)

    def _find_matching_rule(self, severity: str) -> dict | None:
        """Find rule matching severity, then one weighted roll over outcomes; return { state, comment } or None."""
        for rule in self.rules:
            rule_severities = rule.get("severity", [])
            if isinstance(rule_severities, str):
                rule_severities = [rule_severities]
            rule_severities = [severity_normalize_for_match(s) for s in rule_severities]

            if severity not in rule_severities:
                continue

            outcomes = rule.get("outcomes")
            if not outcomes:
                continue

            roll = random.randint(1, 100)
            cumulative = 0
            for outcome in outcomes:
                pct = outcome.get("percentage", 0)
                cumulative += pct
                if roll <= cumulative:
                    return {
                        "state": outcome.get("state", ""),
                        "comment": outcome.get("comment", rule.get("comment", "")),
                    }
            return None
        return None

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    def fetch_results(self, project_id: str, scan_id: str) -> list[dict]:
        raise NotImplementedError

    def apply_triage(
        self,
        project_id: str,
        matched_results: list[dict],
        summary: TriageSummary,
    ) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _get_results_page(
        self, scan_id: str, result_type: str, limit: int = 10000,
        only_to_verify: bool = True,
    ) -> list[dict]:
        """Paginate /api/results for a scan and return only this engine's findings
        that are still To-Verify (untriaged), unless `only_to_verify=False`.

        Two filters, by design:

        * ENGINE — `type` on `GET /api/results` is only a *sort* option, NOT a
          filter (the documented filters are limit/offset/sort/severity/state/
          status). Passing `type=` is silently ignored, so the unified feed mixes
          every engine's results — SAST (numeric similarityId), KICS/IaC (hash),
          SCA (CVE id). Posting another engine's finding to this engine's predicate
          endpoint 400s the whole bulk call, so we always filter by the `type`
          field each result carries.

        * STATE — we ask the API to return only To-Verify via the `state` filter
          (server-side, so we page less data), AND re-check each result's state
          client-side. Belt-and-suspenders: the server filter is the primary
          mechanism, but its reliability on this endpoint hasn't been guaranteed
          across engines, so the client check is authoritative. This is what keeps
          repeated agent passes from re-triaging a finding a prior pass already
          moved out of To-Verify (which otherwise flips its state and re-posts
          notes on every pass).
        """
        params = {"scan-id": scan_id, "type": result_type}
        if only_to_verify:
            # SAST/IaC results use UPPER_SNAKE state on this endpoint.
            params["state"] = "TO_VERIFY"
        results = self.api.paginate(
            "results",
            results_key="results",
            params=params,
            limit=limit,
        )
        wanted = (result_type or "").lower()
        out = [r for r in results if (r.get("type") or "").lower() == wanted]
        if only_to_verify:
            if not out:
                # Canary: zero results under the server-side state filter is
                # ambiguous — genuinely nothing To-Verify, OR the server enum
                # didn't match this engine's stored state spelling and it
                # silently filtered out UNTRIAGED findings (a loss the client
                # check below can never recover, since it only narrows).
                # Refetch once WITHOUT the state param and let the client
                # filter decide; one extra call, only in the suspicious case.
                del params["state"]
                refetched = self.api.paginate(
                    "results", results_key="results", params=params, limit=limit)
                out = [r for r in refetched
                       if (r.get("type") or "").lower() == wanted]
                if any(is_to_verify(r.get("state") or "") for r in out):
                    self.logger.warning(
                        "[%s] server-side state=TO_VERIFY returned 0 results but "
                        "an unfiltered fetch found To-Verify findings — the "
                        "server filter dropped untriaged results for this "
                        "engine; proceeding with client-side filtering.",
                        self.ENGINE.upper())
            # Authoritative client-side confirmation (handles any engine spelling
            # and guards against the server filter being ignored).
            before = len(out)
            out = [r for r in out if is_to_verify(r.get("state") or "")]
            dropped = before - len(out)
            if dropped:
                self.logger.debug(
                    "[%s] dropped %d already-triaged result(s) not in To-Verify",
                    self.ENGINE.upper(), dropped,
                )
        return out
