"""
Realism model for triage.

Real teams don't triage findings at random. They work top-down: high-severity
first, SAST/SCA before IaC/secrets, and they never get to everything — most of
the long tail stays untouched ("To Verify"). Different teams (projects) are more
or less diligent. And there are always exceptions: a Low marked Urgent because
someone flagged it, a Critical left untouched because the team was busy.

This model captures that with two stages plus controlled noise:

  1. COVERAGE — probability a finding receives ANY triage decision, as a function
     of severity, engine, the project's diligence, and the requested intensity.
     This produces the realistic shape: most findings untouched, high-sev far more
     attended, SAST/SCA more than IaC.
  2. OUTCOME — given a finding IS triaged, the state is drawn from a
     severity-conditioned distribution (high-sev skews Confirmed/Urgent;
     low-sev skews Not Exploitable).

  EXCEPTIONS — a small rate flips coverage either way and occasionally draws the
  outcome uniformly, so the result is realistic rather than perfectly rule-bound.

Per-project diligence is seeded by project id, so a given project looks
consistently well- or lightly-triaged across engines and across runs, while
different projects differ — the heart of the "lived-in" feel.

All values are overridable via the `realism` block of triage_rules.yaml.
"""

from __future__ import annotations

import random
import hashlib
from typing import Any

# Untriaged default is "To Verify"; exceptions never set that explicitly.
ACTIVE_STATES = ["Confirmed", "Urgent", "Not Exploitable", "Proposed Not Exploitable"]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# CLI/engine identifiers normalized for coverage lookup.
_ENGINE_ALIAS = {"kics": "iac", "sscs-secret-detection": "secrets"}

class PassBudget:
    """Thread-safe spend counter for one project's triage pass. Shared by all
    engine handlers of that pass, so the human ceiling applies to the pass as a
    whole, not per engine. take() consumes one unit; once exhausted, further
    positive coverage decisions are DEFERRED (the finding stays To Verify —
    the backlog continues next pass, exactly like a real analyst's day ending)."""

    def __init__(self, limit: int | None):
        import threading
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    @property
    def limited(self) -> bool:
        return self._limit is not None

    def take(self) -> bool:
        if self._limit is None:
            return True
        with self._lock:
            if self._used < self._limit:
                self._used += 1
                return True
            return False

    @property
    def exhausted(self) -> bool:
        return self._limit is not None and self._used >= self._limit

    def give_back(self, n: int) -> None:
        """Refund n units — used when decisions were consumed but the writes
        provably never landed (e.g. the whole post was rejected because the
        tenant is in the other SAST grouping mode), so the human-day budget
        isn't spent on actions that didn't happen."""
        if self._limit is None or n <= 0:
            return
        with self._lock:
            self._used = max(0, self._used - n)


DEFAULTS: dict[str, Any] = {
    "enabled": True,
    # Baseline fraction of findings a typical team triages, before modifiers.
    "base_coverage": 0.35,
    "max_coverage": 0.97,
    # Top-down: high severity gets far more attention than low.
    "severity_coverage": {
        "critical": 1.7, "high": 1.25, "medium": 0.6, "low": 0.25, "info": 0.1,
    },
    # SAST/SCA take precedence; IaC/secrets/containers get less attention.
    "engine_coverage": {
        "sast": 1.2, "sca": 1.1, "iac": 0.6, "api": 0.5,
        "containers": 0.5, "secrets": 0.4,
    },
    # Each project draws a stable diligence factor in this range.
    "project_diligence_range": [0.4, 1.3],
    # Maps fuzzy asks ("triage some" vs "triage thoroughly") to a coverage scale.
    # "heavy" models working through the backlog: near-certain coverage of
    # Critical/High and roughly half the Mediums — but ALWAYS paired with the
    # per-pass budget below, because a multiplier alone would let a large
    # project absorb hundreds of decisions in one pass, which no human does.
    "intensity": {"light": 0.5, "some": 0.8, "moderate": 1.0, "thorough": 1.6,
                  "heavy": 2.5},
    # Hard per-(project, pass) ceiling on APPLIED decisions, spent top-down
    # (budget goes to the highest severities first — "worked the top of the
    # backlog, ran out of day"). ~1-3 min per real triage decision makes ~150
    # a full focused analyst-day; that is heavy's OOTB ceiling. Other levels
    # are uncapped by default (backward compatible) but accept keys here too,
    # plus an optional "default" applied to any level without its own value.
    "max_applied_per_pass": {"heavy": 150},
    # Chance to break the rules in either direction (the human factor).
    "exception_rate": 0.05,
    # Given a finding is triaged, the state mix conditioned on severity.
    "outcome_by_severity": {
        "critical": {"Confirmed": 0.45, "Urgent": 0.25,
                     "Proposed Not Exploitable": 0.10, "Not Exploitable": 0.20},
        "high": {"Confirmed": 0.40, "Urgent": 0.10,
                 "Proposed Not Exploitable": 0.15, "Not Exploitable": 0.35},
        "medium": {"Confirmed": 0.25, "Not Exploitable": 0.55,
                   "Proposed Not Exploitable": 0.20},
        "low": {"Not Exploitable": 0.75, "Confirmed": 0.10,
                "Proposed Not Exploitable": 0.15},
        "info": {"Not Exploitable": 0.85, "Proposed Not Exploitable": 0.15},
    },
    # Analyst notes left with each triage decision. A real reviewer explains *why*
    # they set a state; an empty comment looks like an untouched/auto finding. One
    # is drawn at random per result so a project's history reads like several people
    # worked it, not one macro. Keyed by the state being applied.
    #
    # ENGINE-NEUTRAL FALLBACK ONLY. Per-engine wording lives in
    # comments_by_engine below and is what normally gets used; this pool exists so
    # a state still gets a plausible note if an engine has no set of its own (a
    # newly wired engine, or a config that trims one). Keep these free of
    # engine-specific vocabulary — no "sink", no "base image", no "dependency" —
    # because they can be attached to a finding from ANY engine.
    "comments_by_state": {
        "Confirmed": [
            "Reviewed and confirmed as a real issue in this context. Tracking for remediation.",
            "Verified with the owning team; accepted as a true positive and queued for a fix.",
            "Confirmed during review. Added to the remediation backlog.",
        ],
        "Urgent": [
            "High impact and exposed in production — escalating for an immediate fix.",
            "Critical exposure; prioritized for this sprint and flagged to the security lead.",
        ],
        "Not Exploitable": [
            "Reviewed: not exploitable as configured in this environment.",
            "Existing controls mitigate this. Closing as not exploitable.",
            "False positive on review — closing.",
        ],
        "Proposed Not Exploitable": [
            "Believed mitigated — proposing Not Exploitable pending reviewer sign-off.",
            "Compensating control in place; proposing NE for a second reviewer to confirm.",
        ],
    },
    # Per-engine analyst notes, keyed engine -> state. An analyst's reasoning is
    # specific to what they're looking at: SAST is about data flow to a sink, SCA
    # about upgrade paths and reachable methods, IaC about resources and baselines,
    # secrets about rotation and test fixtures, containers about base images and
    # distro backports. Using one shared pool for all of them produced obviously
    # wrong notes — SAST "the sink is not reachable with untrusted data" landed on
    # container OS-package CVEs (spotted 2026-07-30, once container comments first
    # became readable via triage-history).
    #
    # Engine keys are the normalized names (see _ENGINE_ALIAS): sast, sca, iac,
    # secrets, containers. Anything missing falls back to comments_by_state.
    "comments_by_engine": {
        "sast": {
            "Confirmed": [
                "Validated the data flow from source to sink — reachable from untrusted input. Tracking for remediation.",
                "Reproduced during code review; confirming as a true positive and assigning to the owning team.",
                "Confirmed exploitable in this context. Added to the remediation backlog.",
                "Reviewed with the developer — legitimate issue, fix scheduled.",
            ],
            "Urgent": [
                "Exploitable on an internet-facing path with high impact — escalating for an immediate fix.",
                "Reachable from an unauthenticated request handler. Needs urgent remediation.",
                "Critical exposure; prioritized for this sprint and flagged to the security lead.",
            ],
            "Not Exploitable": [
                "Input is validated and encoded upstream; not exploitable in this context.",
                "False positive — the value is a compile-time constant, not attacker-controlled.",
                "Mitigated by the framework's built-in output encoding. Closing as not exploitable.",
                "Reviewed: the sink is not reachable with untrusted data.",
            ],
            "Proposed Not Exploitable": [
                "Believed mitigated by upstream validation — proposing Not Exploitable pending reviewer sign-off.",
                "Compensating control in place; proposing NE for a second reviewer to confirm.",
                "Looks like a false positive on first review; proposing NE while we double-check the data flow.",
            ],
        },
        "sca": {
            "Confirmed": [
                "Vulnerable function is called from our code — upgrade tracked with the owning team.",
                "Confirmed reachable through a transitive dependency; bumping the parent package.",
                "Direct dependency and a fixed version exists. Scheduled for the next dependency bump.",
                "Reproduced against our usage of the library. Added to the remediation backlog.",
            ],
            "Urgent": [
                "Known exploited vulnerability in a runtime dependency — patching immediately.",
                "Public exploit available and the package ships in the production bundle. Escalated.",
                "Critical CVE in a direct dependency; hotfix release being prepared.",
            ],
            "Not Exploitable": [
                "Vulnerable method is never invoked from our code paths — not exploitable.",
                "Dev/test-only dependency; not shipped in the production artifact.",
                "The affected feature is not enabled in our configuration. Closing.",
                "Transitive dependency already overridden to a patched version in the lockfile.",
            ],
            "Proposed Not Exploitable": [
                "Reachability analysis suggests the vulnerable path is unused — proposing NE for review.",
                "Believed unreachable via our API surface; proposing NE pending a second look.",
                "No fix published yet and exposure looks limited — proposing NE while we monitor upstream.",
            ],
        },
        "iac": {
            "Confirmed": [
                "Valid misconfiguration in the Terraform module — fix tracked with the platform team.",
                "Confirmed against the deployed resource; hardening change queued.",
                "Reviewed with the infra owner — the resource does need this control enabled.",
                "Reproduced in a plan run. Added to the hardening backlog.",
            ],
            "Urgent": [
                "Resource is internet-facing without the required control — remediating now.",
                "Public exposure on a production resource; escalated to the platform on-call.",
                "Credentials/data would be exposed as written. Immediate fix in progress.",
            ],
            "Not Exploitable": [
                "This module only deploys to an isolated non-production account. Not exploitable.",
                "Control is enforced centrally by an organization policy, not in this template.",
                "Resource is internal-only behind the service mesh; closing as not exploitable.",
                "False positive — the setting is applied via the module's default variables.",
            ],
            "Proposed Not Exploitable": [
                "Believed covered by our landing-zone baseline — proposing NE pending platform confirmation.",
                "Compensating network control in place; proposing NE for a second reviewer.",
                "Accepted risk on this legacy stack — proposing NE while migration is planned.",
            ],
        },
        "secrets": {
            "Confirmed": [
                "Live credential committed to the repository — rotated and tracked for history rewrite.",
                "Confirmed valid token; revoked at the provider and moved to the secret manager.",
                "Real secret in source control. Rotation done, cleanup of git history queued.",
            ],
            "Urgent": [
                "Active production credential exposed — rotating immediately and auditing for misuse.",
                "Valid cloud key in a public-facing repo. Revoked; incident review underway.",
            ],
            "Not Exploitable": [
                "Test fixture value, not a real credential. Closing as not exploitable.",
                "Placeholder/example string from documentation — not a live secret.",
                "Credential was already revoked before this scan; no longer usable.",
                "This is a public key / non-sensitive identifier, not a secret.",
            ],
            "Proposed Not Exploitable": [
                "Looks like a sample value — proposing NE pending the owning team's confirmation.",
                "Believed already rotated; proposing NE while we verify at the provider.",
                "Scoped to a sandbox tenant with no production access — proposing NE for review.",
            ],
        },
        "containers": {
            "Confirmed": [
                "Package is present in the runtime layer and a patched version exists — base image rebuild scheduled.",
                "Confirmed in the shipped image; tracking the base image bump with the platform team.",
                "Vulnerable binary is actually used at runtime. Added to the image remediation backlog.",
                "Reviewed with the image owner — pinning to a newer base tag next release.",
            ],
            "Urgent": [
                "Critical CVE in an internet-facing image with a fix available — rebuilding now.",
                "Known exploited vulnerability in the running container. Escalated for immediate rebuild.",
                "Remote-code-execution risk in a production image; emergency rebuild in progress.",
            ],
            "Not Exploitable": [
                "Package is only present in the build stage, not in the final image. Not exploitable.",
                "The distro marks this as unimportant and ships no fix; not exploitable in our usage.",
                "Vulnerable component is not installed in the runtime layer — closing.",
                "The affected binary is never executed by this container's entrypoint.",
            ],
            "Proposed Not Exploitable": [
                "No distro backport available yet — proposing NE while we track the upstream advisory.",
                "Believed unreachable in this image's runtime path; proposing NE for a second reviewer.",
                "Inherited from the upstream base image with no fixed version — proposing NE pending rebuild.",
            ],
        },
    },
}


class RealismModel:
    def __init__(self, cfg_block: dict | None = None):
        cfg = dict(DEFAULTS)
        for k, v in (cfg_block or {}).items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                merged = dict(cfg[k]); merged.update(v); cfg[k] = merged
            else:
                cfg[k] = v
        self.enabled = bool(cfg["enabled"])
        self.base_coverage = float(cfg["base_coverage"])
        self.max_coverage = float(cfg["max_coverage"])
        self.severity_coverage = {k.lower(): float(v) for k, v in cfg["severity_coverage"].items()}
        self.engine_coverage = {k.lower(): float(v) for k, v in cfg["engine_coverage"].items()}
        self.project_diligence_range = list(cfg["project_diligence_range"])
        self.intensity = {k.lower(): float(v) for k, v in cfg["intensity"].items()}
        self._max_applied = {str(k).lower(): int(v) for k, v in
                             (cfg.get("max_applied_per_pass") or {}).items() if v}
        self.exception_rate = float(cfg["exception_rate"])
        self.outcome_by_severity = {k.lower(): dict(v) for k, v in cfg["outcome_by_severity"].items()}
        self.comments_by_state = {k: list(v) for k, v in (cfg.get("comments_by_state") or {}).items()}
        self.comments_by_engine = {
            str(engine).lower(): {k: list(v) for k, v in (states or {}).items()}
            for engine, states in (cfg.get("comments_by_engine") or {}).items()
        }

    # ----------------------------------------------------- analyst note
    def comment_for(self, state: str | None, rng: random.Random,
                    engine: str | None = None) -> str:
        """A realistic, state- AND engine-appropriate reviewer note.

        Prefers the engine's own pool (comments_by_engine), because an analyst's
        reasoning is specific to what they are looking at — a container CVE is not
        closed with "the sink is not reachable". Falls back to the engine-neutral
        comments_by_state pool, then to '' — so callers stay safe when an engine
        has no pool of its own or config trims one.
        """
        key = _ENGINE_ALIAS.get((engine or "").lower(), (engine or "").lower())
        pool = (self.comments_by_engine.get(key) or {}).get(state or "")
        if not pool:
            pool = self.comments_by_state.get(state or "")
        return rng.choice(pool) if pool else ""

    # ----------------------------------------------------- per-project diligence
    def project_diligence(self, project_id: str) -> float:
        """Stable per-project factor (same id -> same diligence, across engines/runs)."""
        seed = int(hashlib.sha256((project_id or "").encode()).hexdigest()[:8], 16)
        r = random.Random(seed)
        lo, hi = self.project_diligence_range
        return lo + (hi - lo) * r.random()

    def pass_budget(self, intensity: str | float) -> int | None:
        """Per-(project, pass) cap on applied decisions for this intensity, or
        None for uncapped. Float intensities use the 'default' key if set."""
        caps = self._max_applied
        if isinstance(intensity, str):
            v = caps.get(intensity.lower(), caps.get("default"))
        else:
            v = caps.get("default")
        return int(v) if v else None

    def intensity_scale(self, intensity: str | float) -> float:
        if isinstance(intensity, (int, float)):
            return float(intensity)
        return self.intensity.get(str(intensity).lower(), 1.0)

    # --------------------------------------------------------- coverage stage
    def coverage_probability(self, severity: str, engine: str,
                             diligence: float, intensity: str | float) -> float:
        sev = self.severity_coverage.get((severity or "").lower(), 0.5)
        eng = self.engine_coverage.get(_ENGINE_ALIAS.get((engine or "").lower(), (engine or "").lower()), 0.6)
        p = self.base_coverage * sev * eng * float(diligence) * self.intensity_scale(intensity)
        return max(0.0, min(self.max_coverage, p))

    # ---------------------------------------------------------- decision
    def decide(self, severity: str, engine: str, diligence: float,
               intensity: str | float, rng: random.Random) -> tuple[bool, str | None]:
        """Return (should_triage, state). state is None when left untouched."""
        p = self.coverage_probability(severity, engine, diligence, intensity)
        triage = rng.random() < p
        if rng.random() < self.exception_rate:    # human factor: flip coverage
            triage = not triage
        if not triage:
            return (False, None)

        dist = self.outcome_by_severity.get((severity or "").lower())
        if not dist or rng.random() < self.exception_rate:  # exception: any state
            return (True, rng.choice(ACTIVE_STATES))
        return (True, _weighted_choice(dist, rng))

    # ---------------------------------------------------------- ordering
    @staticmethod
    def priority_key(result: dict) -> tuple:
        """Top-down: highest severity first, then most recent (if available)."""
        sev = str(result.get("severity") or result.get("Severity") or "").lower()
        rank = _SEV_RANK.get(sev, 5)
        # Newer findings first when a comparable timestamp exists; else stable.
        age = (result.get("firstFoundAt") or result.get("foundAt")
               or result.get("FirstFoundAt") or "")
        return (rank, str(age))


def _weighted_choice(dist: dict[str, float], rng: random.Random) -> str:
    total = sum(dist.values()) or 1.0
    roll = rng.random() * total
    cum = 0.0
    for state, w in dist.items():
        cum += w
        if roll <= cum:
            return state
    return next(iter(dist))
