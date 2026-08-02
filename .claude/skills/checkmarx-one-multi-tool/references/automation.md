# Autonomous / Timed Activity

How the agent makes a tenant look continuously active, and how to tune it.
Implemented in `scripts/agent.py` + `scripts/ops/activity.py`; configured in
`config/activity.yaml`.

## The honest model of "autonomy"

Claude runs in a chat turn; it is not a background process and cannot run your
tenant unattended on its own. Something must execute API calls across wall-clock
time. The design principle: **the scheduler lives INSIDE the agent process**
(`agent run` plans the next 24h, sleeps, executes, re-plans at the horizon), so
the only thing an environment must provide is "keep this process running" — a
primitive every platform already has. No cron, no wrapper scripts, no
PATH/TCC/mail failure modes.

There is exactly one executor, `agent run`, with two substrates it selects
between at start:

1. **Container (recommended for multi-day runs)** — with docker or podman
   available and `--container` chosen, `run` builds the image from the skill's
   Dockerfile (if needed) and starts it with `--restart=unless-stopped`: survives
   reboots and host sleep, captures logs natively (`docker/podman logs`), ledger
   on a named volume.
2. **Process** — `--process`, or automatic when no container runtime exists: the
   identical loop as a long-lived process in the current session (wrap in `nohup
   ... &`, tmux, systemd `Restart=always`, or launchd `KeepAlive` if you want it
   supervised). Same behavior; you own keeping it alive.

When a runtime is detected and no substrate flag was given, `run` asks which to
use (in a non-interactive shell it prints the two options and exits rc 3 —
choose and re-run). There is **no simulation mode and no time compression**: the
agent does real work on a real timeline, always.

**Multi-identity attribution.** When `cxone-identities.yaml` registers
secondary API keys (see SKILL.md "Multi-identity attribution"), the agent
assigns each scan/triage event an identity at PLANNING time — a stable
per-project owner with seeded occasional hand-offs (`identities.affinity` in
activity.yaml, default 0.85). `identities.include_primary` (default true)
controls whether the primary/admin key is itself a candidate owner; false keeps
all autonomous activity on registered secondaries (the scheduled counterpart of
`--as auto-secondary` on demand). With include_primary false and NO secondaries
registered, assignment is a no-op and events execute as primary — register keys
first if strict non-admin attribution matters. The identity shows in the plan log ("... as
alice.dev"), persists in the plan file (restart-resume keeps it), and executes
under that user's key with automatic 403-fallback to primary. In the container,
identities travel as CXONE_IDENTITIES_JSON via a transient 0600 env-file at
launch; they are never baked into the image.

**Timing guarantees.** Events execute within seconds-to-minutes of their planned
time while the host is up. The committed plan is persisted (`.agent_plan.json`,
alongside the ledger), so a restart **resumes** it: events still due — future,
or late within `--max-lateness` (default 2h) — fire as promised; anything older
is **dropped, never replayed** — an outage becomes a quiet gap (realistic), not
a late burst (fake-looking). Planning always resumes forward from now; the
persisted ledger means restarts never double-act. Dry-runs neither save nor
consume the persisted plan (previews must not leak into or erase a live run's
promise). Past `--until` (or `CXONE_AGENT_UNTIL`) the agent idles rather than
exits, so restart policies don't churn. The 24h planning horizon is internal and
not configurable.

**The read-only preview** (no tenant changes): `agent plan` lists the committed
next-24h events and summarizes the general behavior beyond (daily rate,
business-hours weighting, end date) — the way to show an operator cadence and
volume before going live.

## Docker deployment (definitive)

From the skill root (where the `Dockerfile` is):

```bash
# 1. Build the image
docker build -t cxone-agent .

# 2. Create the state volume (the agent's cadence ledger survives upgrades)
docker volume create cxone-agent-state

# 3. Run — credentials as env vars; NEVER bake them into the image
docker run -d --name cxone-agent --restart=unless-stopped \
  -e CXONE_BASE_URL=https://deu.ast.checkmarx.net \
  -e CXONE_TENANT=my_tenant \
  -e CXONE_API_KEY=<tenant admin API key> \
  -e CXONE_AGENT_UNTIL=2026-07-28 \
  -e TZ=America/Chicago \
  -v cxone-agent-state:/state \
  cxone-agent
```

Operate it:

```bash
docker logs -f cxone-agent           # the activity log: each (re)plan lists its
                                     # full committed window, then per-event execution
docker logs --since 24h cxone-agent  # review a day
docker stop cxone-agent              # pause; `docker start` resumes cleanly
docker rm -f cxone-agent             # remove (state volume persists)
```

At each planning pass (startup and every horizon) the agent logs the whole
committed window up front — `Planned N event(s) through <time>:` followed by a
`planned <time>  <event>` line per event — so the log shows *what* is scheduled,
not just counts. Each event is then logged again as it actually executes.

Upgrade (new skill version) without losing cadence memory:

```bash
docker build -t cxone-agent .        # rebuild from the updated skill
docker rm -f cxone-agent && docker run -d ... (same run command)
```

Details that matter:
- **TZ** shapes business-hours realism — set it to the demo tenant's "office"
  timezone or activity will cluster around UTC office hours.
- **`/state` volume** holds `.agent_state.json` (the private ledger). Keep it on a
  named volume; deleting it resets per-project spacing memory (safe, but the first
  day may front-load a few extra scans).
- **Dry-run first** if you want to watch a container plan without acting:
  `docker run --rm -e ... --entrypoint python cxone-agent multitool.py agent run --process`
  (no `--live` → DRY-RUN; add `--seed N` for a reproducible preview).
- **Extend the window**: recreate the container with a new `CXONE_AGENT_UNTIL`
  (state volume keeps continuity). The agent idles past the date, so a forgotten
  container does nothing except log an occasional idle line.
- The container runs as a non-root user; the image contains no credentials.

## How timing is shaped (ops/activity.py)

Events arrive as a **non-homogeneous Poisson process**: inter-arrival gaps are
exponential at an instantaneous rate that varies by time, so events are jittered
and clustered rather than evenly spaced. The rate is:

    rate(t) = events_per_business_hour
              × hour_weight(t)        # 1.0 in business hours, overnight_factor outside
              × weekday_weight(t)     # weekdays high, weekends low

Each event is typed from `event_mix` (mostly scans, some triage, rare onboarding,
plus `idle` gaps). Targets are weighted toward busier projects, but the real
shaping is the **per-project spacing gate** below; tenant-wide hard caps
(`max_events_per_hour`, `max_scans_per_day`, `max_triage_per_day`) bound total volume.

## Per-project cadence — the "don't scan too often" mechanism

The Poisson stream only sets *when something might happen*; whether a given project
is actually acted on is gated by its own cadence, so no project is scanned/triaged
too frequently:

- **Intrinsic interval by rank.** Each project is assigned a stable minimum spacing
  (`scan.interval_hours`, `triage.interval_hours`) by its *rank* within the tenant
  (`interval_map`). Ranking guarantees a realistic spread at any tenant size — a
  busiest project near the floor (~once/day), the most-legacy near the ceiling (a
  week or more), the rest geometrically spaced. `interval_skew` (>1) widens the
  quiet end so "busy" is the exception. A scan/triage is only scheduled if the
  project's interval (× small jitter) has elapsed.
- **Hard per-day ceiling.** `scan.max_per_project_per_day` / `triage.max_per_project_per_day`
  cap an individual project's daily actions (the outlier ceiling, e.g. 3 scans/day).
- **Triage follows scans.** A project is only triageable when it has an *un-reviewed*
  scan (scanned more recently than last triaged), so triage never outpaces scanning
  and looks like real review work. Triage cadence is ranked by *scan* order, so the
  busiest-scanned projects are also reviewed most.
- **Triage volume = a per-engine fraction of untriaged.** Scans run all engines; a
  triage pass touches every engine a project has and clears a per-engine fraction of
  its *currently-untriaged* results (`engine_fractions`, jittered) — biased SAST
  (highest) > SCA > IaC > Secrets > Containers (lowest). So a pass reads like
  "20/99 SAST, 8/74 SCA, 3/120 Containers". Validated secrets are marked Urgent.
- **Daily triage ceiling.** `triage.max_results_per_day` caps the TOTAL results
  triaged tenant-wide per day, so even a large tenant never triages an absurd number
  at once (the per-engine fractions already bound per-pass volume).
- **No dependence on tenant history.** Cadence comes from the intrinsic model plus
  the agent's **own private ledger** (`scripts/.agent_state.json`) — the agent's
  record of what *it* did. It does **not** query the tenant's scan history (which
  mixes in real activity and would be circular). The ledger is what makes
  per-project spacing and daily caps hold across restarts; it
  is excluded from packaging (like `.env`) and trims entries older than 30 days.
- **Only real work is recorded (no-op events are NOT).** `_execute` returns
  True only when at least one project actually resolved; the run loop records
  in the ledger only on True, logging `(NO-OP — nothing resolved)` otherwise.
  This matters because the ledger is the cadence gate: recording a no-op tells
  the planner those projects were just handled, suppressing them for a full
  interval. Live-observed on cnf26 (2026-07): during an ~21h identity
  visibility outage every scan/triage resolved 0 projects but was still
  recorded as done, so 16 project entries were poisoned — a plain re-plan
  would have skipped exactly the projects that had been missed, quietly
  turning a transient outage into a lasting coverage gap. With the gate in
  place an outage leaves the projects still due and the next re-plan picks
  them up naturally, which is the intended "quiet gap, then catch up"
  behavior. Note the ledger only ever *gates* work — a poisoned entry
  suppresses activity, it never causes double-acting.

## Project scope (ops/project_scope.py)

Narrows WHICH projects the agent may act on, applied in `_projects()` **before
planning** — so out-of-scope projects are never scheduled, rather than being
scheduled and then skipped (which would leave phantom events in the plan and
poison the cadence ledger with work that never happened).

`ProjectScope.allows()` evaluates in a fixed order: **excludes win outright**,
then, if any include rule exists, the project must match one. Consequence worth
relying on: an over-broad exclude yields too FEW projects, never too many — the
safe direction for a tool that writes to a live tenant.

Matching: names are case-insensitive substrings unless the pattern contains
`*` `?` `[`, in which case it's a glob over the whole name — so "projects with
Istio in the name" is just `Istio`, and `ShopWorthy/*` works as expected. Tags
are `key` (present, any value) or `key:value`.

Resolution is **per field**, CLI > env (`CXONE_AGENT_INCLUDE_PROJECTS`,
`_EXCLUDE_PROJECTS`, `_INCLUDE_TAGS`, `_EXCLUDE_TAGS`) > `activity.projects` in
activity.yaml — so `--exclude-projects` on the command line overrides only the
excluded names and leaves configured includes intact.

Two failure modes are made loud rather than silent: a scope matching **zero**
projects logs an ERROR (the agent would otherwise idle forever looking healthy),
and the container launch re-emits the scope as CLI flags via `as_cli_args()`
because the image carries its own baked activity.yaml and cannot see host-side
flags or env vars.

## Safety rails (by design)

- **Constructive only.** The agent performs scans, triage, and allowlisted
  onboarding. It has no path to delete/purge or change access — destructive
  actions are excluded from the autonomous model entirely.
- **Simulated triage only — never a metered one.** Every `triage.*` key here
  drives the realism engine (`triage-simulate`), which is free. The agent must
  never invoke `ai-assist` (spends Checkmarx AI credits) or `triage-real` (spends
  coding-assistant tokens and asserts real security verdicts); both require a
  human confirming the spend. If you add event types, keep that boundary.
- **Scopeable.** Project scope (above) bounds *what* it can touch at all,
  independently of the volume caps that bound *how much*.
- **Dry-run by default.** `run` needs `--live` to act; `plan` never acts.
- **Allowlisted onboarding.** `onboard.enabled: false` by default; when enabled it
  only pulls from `onboard.repos`, never arbitrary repos. Each repo once.
- **Caps + stoppable.** Volume caps plus Ctrl-C (process) or `docker/podman stop` (container).
- **Logged in detail.** Each (re)plan logs its full committed window; each event logs execution start (with schedule lag), duration, and outcome — failures include the exception, with full tracebacks under `--debug`.

## Tuning (config/activity.yaml)

- Busier tenant → raise `events_per_business_hour` (per-project spacing still caps
  each project, so this mostly changes overall liveliness).
- Scan projects more/less often → lower/raise `scan.interval_hours` (e.g. `[8, 504]`
  = busiest ~3×/day floor down to ~3-week legacy). Same for `triage.interval_hours`.
- Sharper busy-vs-legacy split → raise `interval_skew`; flatter → lower it.
- Change the per-day ceiling → `scan.max_per_project_per_day` / `triage.max_per_project_per_day`.
- Triage more/less of each engine → `triage.engine_fractions` (SAST highest … Containers lowest).
- Cap total daily triage volume → `triage.max_results_per_day`.
- More overnight/weekend activity → raise `overnight_factor` / weekend weights.
- Different mix → adjust `event_mix` (e.g. more triage passes).
- Shift the workday → change `business_hours`.
- Triage should not require a prior scan → `triage.follow_scan: false`.
- Enable onboarding drips → `onboard.enabled: true` + list repos in `onboard.repos`.
- Tighter safety → lower the `caps`.

## Notes

- Triage on an un-scanned project is a natural no-op (the triage step needs a
  completed scan), so on a fresh tenant let scans accumulate first, or seed with a
  one-off `scan` + `triage` before starting the agent.
- Scans are asynchronous on the platform; the agent triggers them and moves on, it
  does not block waiting for completion.
- Activity is forward-looking — it cannot backdate events, since the platform
  timestamps actions when they happen. The realism is in ongoing cadence, not history.
