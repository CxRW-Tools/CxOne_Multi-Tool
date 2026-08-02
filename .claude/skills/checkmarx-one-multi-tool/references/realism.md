# Triage Realism Model

How the "lived-in" triage works, and how to tune or extend it. Implemented in
`scripts/ops/realism.py`; configured under `realism:` in `config/triage_rules.yaml`.

This model backs the **`triage-simulate`** verb (formerly `triage`, which still
dispatches here with a deprecation warning). It fabricates plausible states for
demo tenants — it does **not** look at code and its verdicts are not security
assessments. The verbs that make real decisions are `triage-real` (this coding
assistant reviews the source) and `ai-assist triage` (Checkmarx Triage Assist);
see `extending.md`. Never describe simulated output as an assessment.

## Already-triaged detection (SCA)

Coverage is only rolled for findings that are still untriaged, so "is this already
triaged?" has to be answered against CURRENT state. For SAST that is just the
result's `state`. For SCA it is not: the scan is immutable, so the export's
`RiskState` reports the as-of-scan value forever. `SCAHandler._apply_live_states()`
overwrites it from `ops/sca_live_state.py` before any decision is made.

Without that, every pass would re-triage the same risks — flipping states and
re-posting comments on findings a human already decided, on every scheduled agent
run. If you add an engine whose read path is snapshot-based, it needs the same
treatment.

## Why

A demo tenant where every Critical is Confirmed and nothing else is touched looks
fake; so does one where states are sprinkled uniformly at random. Real backlogs
have shape: high-severity and SAST/SCA findings get attention first, most low/info
findings are never reviewed, different teams (projects) differ, and there are
always a few human exceptions. The model reproduces that shape.

## The two stages

For each finding, in top-down order (highest severity first):

1. **Coverage** — `coverage_probability = base_coverage × severity_factor ×
   engine_factor × project_diligence × intensity`, clamped to `max_coverage`.
   A roll decides whether the finding is triaged at all. Most low/info findings
   fall through and stay "To Verify".
2. **Outcome** — if triaged, draw the state from `outcome_by_severity[severity]`
   (a categorical distribution). High severity skews Confirmed/Urgent; low skews
   Not Exploitable.

**Exceptions** (`exception_rate`): with small probability the coverage decision
is flipped (touch something that wouldn't be, or skip something that would), and
the outcome is drawn uniformly across all active states. This is the deliberate
non-determinism — the reason it isn't a pure rules engine.

## Per-project diligence

`project_diligence(project_id)` seeds a RNG from the project id and draws a factor
in `project_diligence_range`. Same id → same factor every run and across engines,
so a project is consistently well- or lightly-triaged, while projects differ.

## Intensity (maps fuzzy asks)

`intensity` scales coverage: `light 0.5 / some 0.8 / moderate 1.0 /
thorough 1.6 / heavy 2.5`. `heavy` models working through the backlog and is
always paired with `max_applied_per_pass` (default `heavy: 150`) — a hard,
thread-safe ceiling on APPLIED decisions per (project, pass), shared across
that pass's engines and spent top-down (highest severities first). The budget
gate sits AFTER the per-finding RNG draw, and each finding's RNG is keyed by
its id, so a seed reproduces the same decision stream and the cap is a pure
truncation of it: the capped pass applies exactly the first N of what the
uncapped pass would. Overflow is counted as `deferred` (stays To Verify;
"Total deferred" in the summary) — the backlog continues next pass. Add keys
(or `default: N`) to cap other levels; they are uncapped out of the box.
The skill maps natural-language quantities to these (see SKILL.md). Even at
`thorough`, coverage intentionally leaves a realistic untouched tail.

## Tuning (config/triage_rules.yaml → realism:)

- Want more findings touched overall → raise `base_coverage`.
- Want IaC/secrets attended less → lower their `engine_coverage`.
- Want a flatter or steeper severity gradient → adjust `severity_coverage`.
- Want more/less project-to-project variation → widen/narrow `project_diligence_range`.
- Want more chaos → raise `exception_rate`.
- Want different state mixes → edit `outcome_by_severity`.
- Want the old deterministic bands instead → `realism.enabled: false` (the
  legacy per-severity `outcomes` bands then apply).

## Extending

- **New engines** (apisec, containers, secrets): add an `engine_coverage` entry and
  a handler that calls `self._decide_state(severity)` (the shared realism/legacy
  decision) per finding, in `priority_key` order. See `base_handler._match_realistic`.
- **Age/recency effects**: `priority_key` already prefers newer findings when a
  timestamp is present; you can add an age factor to `coverage_probability` if
  older scans should look more triaged.
- **Custom states**: add them to `ACTIVE_STATES` and the outcome distributions,
  and ensure the engine's predicate API accepts them.

## Decision units and SAST grouping modes

The model's unit is "one human decision". In Similarity-ID tenants that is one
similarity group (per-result draw); in Attack-Vector tenants it is one VECTOR:
one draw keyed by `attackVectorId` (order-independent, seed-stable), coverage
from the group's worst severity, one outcome/comment for the whole vector, and
ONE `max_applied_per_pass` budget unit regardless of how many results the
vector covers — a bulk vector update is a single human action, which is the
efficiency the feature exists to provide. Vectors are processed worst-severity
first, so a capped heavy pass spends its day on the most severe attack
patterns.
