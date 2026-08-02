# Checkmarx One Multi-Tool (Claude Skill)

End-to-end management of Checkmarx One tenants for Solution Engineers building
and maintaining realistic demo / POV environments — driven in natural language
through Claude, backed by deterministic, dry-run-safe Python.

This is a Claude **Skill**: `SKILL.md` tells Claude when and how to use it; the
`scripts/` are the engine. Everything also runs directly from the command line.

## Recommended: run from Claude Code or Cowork

Use this from **Claude Code or Cowork on the machine where the tool will run**.
Those run locally with your network and a real terminal, so Claude can reach your
Checkmarx tenant *and* run the commands itself — the experience is natural language
end to end (you don't paste commands).

1. Install the skill: drop `checkmarx-one-multi-tool.skill` into your Claude Code /
   Cowork skills location (or unzip it into your skills folder).
2. Have **Python 3.10+** available. On Windows, if the bare `python` resolves to
   the Microsoft Store stub (can't reach the skill's install path), use the
   bundled `run.py` launcher instead — see "Running the tool" below.
3. Configure credentials for **one tenant at a time**. Easiest: give Claude your
   API key and it derives the base URL + tenant from it (the key is a JWT) and
   writes a project-owned credentials file: `python run.py env init --api-key
   <KEY>`. The tool refuses to write credentials into its own (shared, ephemeral)
   install folder — point it at your project directory, e.g. set
   `CXONE_ENV_FILE=<project-dir>/cxone.env` once per session. Work with exactly
   one tenant at a time; every command states which tenant it's acting on. The
   admin key is required for IAM; add SCM tokens later via chat ("add my ADO
   token" -> `env set-token ado <tok>`).
4. Then just ask, e.g.:
   - "Stand up a demo tenant for Acme: two groups, a few users, onboard WebGoat and
     juice-shop, scan them, and triage so it looks realistic."
   - "Run realistic activity on my tenant for the next few days."

Claude installs the three dependencies, previews actions (dry-run), lists the
specific things a bulk/destructive action will do, confirms, and runs them.

> **On approval prompts:** the Claude interface asks you to approve each action;
> you can approve one for the rest of the session ("Allow for this session"), and
> some setups let you bypass per-action approval entirely. That's possible, but
> be cautious with it — this tool acts on a live tenant with an admin-scoped key,
> and bypassing approval removes your last checkpoint before a change actually
> happens. Prefer approving per action, especially for anything destructive or
> bulk.

## Running the tool

Prefer `python run.py <verb> ...` from the skill root over calling
`scripts/multitool.py` directly. `run.py` locates the scripts relative to itself
(no hardcoded paths) and, on Windows, detects and works around the Microsoft
Store Python stub. Invoke it relatively from the current skill directory each
session rather than a saved absolute path — the skill's install location can
change between sessions.

**Checking the version.** Run `python run.py version` (or `--version`), or just
ask "what version are we running?". The build also prints on `welcome` and rides
along on every command's startup output, so you can always confirm which version
a session is on — useful after installing an update to be sure the new build is
actually loaded (reinstalling a skill doesn't affect an already-running session;
start a fresh session to pick it up).

## Autonomous activity: real time, not simulated

There is no simulation mode and no time compression. "Run realistic activity for
the next N days" means the agent actually runs, live, for N days — scanning and
triaging on its natural schedule. Two verbs:
- `agent plan` — read-only preview of the committed next-24h events plus a
  summary of the general behavior beyond (rate, business-hours weighting, end
  date). No execution.
- `agent run --live --until <date>` — the executor. Detects Docker or Podman; if
  found, choose a durable **container** (survives host sleep/restarts;
  recommended for multi-day runs) or a **process**; with no container runtime it
  runs as a long-lived process automatically. Re-plans internally every 24h and
  **persists its committed plan**, so a restart resumes the promised schedule —
  still-due events fire, and only events past the lateness tolerance are dropped
  (a quiet gap, never a late makeup burst). The container image is
  version-labeled and rebuilt automatically when the installed skill is newer,
  so upgrades reach the agent on next launch. Every planned window and every
  event's execution and outcome is logged in detail — including, when secondary
  identities are registered, *who* performs each event.

When run in a container, the agent auto-detects your host timezone and forwards
it, so log timestamps and the business-hours weighting match your local clock
(DST-aware). Install `tzlocal` (`pip install -r requirements.txt`) for a correct
IANA zone name — especially on Windows; without it the agent falls back to a
fixed UTC offset (aligned to your current clock but not DST-aware) and says so in
the startup log. Set `TZ=Area/City` explicitly to override.

> Web/app chat can design blueprints, preview plans, and tune configs, but cannot
> reach your tenant — use it to prepare, then run from Claude Code / Cowork.

## Manual quick start (running the scripts yourself)
```bash
pip install -r requirements.txt
python run.py env init --api-key <KEY>     # writes credentials to your project dir
python run.py --help
python run.py identities import --file team-keys.txt   # optional: multi-user attribution
python run.py iam create-group "Developers" --dry-run
python run.py provision --blueprint blueprints/example-tenant.yaml --dry-run
```

## Capabilities
Identity (users/groups/roles/membership), applications, projects + repo
onboarding (GitHub; extensible to GitLab/Azure/Bitbucket), scan configuration,
scans, **three distinct kinds of triage** — `triage-simulate` (fabricated states
for demo realism: coverage + outcome model, top-down, per-project variation,
exceptions; five intensity levels up to `heavy`, a backlog push hard-capped at a
human day's decisions per project per pass), `triage-real` (a GENUINE review by
the coding assistant against the exact scanned source, written back as real
states and comments; free, and it refuses to guess when the code can't be read),
and `ai-assist` (Checkmarx Assist AI Triage + Remediation — real, and spends AI
credits, with balance and cost shown before every run), **multi-identity attribution** (register secondary
users' API keys and scans/triage run as different team members — `--as` on
demand incl. `-secondary` variants that exclude the admin key, automatic
per-project owners in the agent with an `include_primary` knob), full blueprint provisioning
**and export** (capture a live tenant back to blueprint YAML), ordered teardown
(scoped to tool-created resources by default; `--all` for a full reset), a
local web UI, and an autonomous activity agent that runs real scans/triage over
real time (business-hours-weighted, jittered, container or process — no
simulation, no time compression). One entry point: `run.py` (or
`scripts/multitool.py` directly).

## Layout
- `run.py` — recommended entry point (skill root); self-locates the scripts and
  works around the Windows Store Python stub. Invoke relatively each session.
- `SKILL.md` — orchestration brain (capabilities, order, safety, extensibility,
  the operating protocol: active-tenant line + dry-run/confirm cycle).
- `cxone-multitool-overview.html` — self-contained, friendly overview + safe-usage
  guide; opens in any browser.
- `scripts/multitool.py` — single CLI over every capability.
- `scripts/cxone/` — auth + unified API client (AST + IAM/Keycloak planes);
  credential resolution (`CXONE_ENV_FILE` / `--env`, refuses the skill's own dir).
- `scripts/{iam,applications,onboard,scanconfig,provision,purge}.py` — admin modules.
- `scripts/export_blueprint.py` — capture a live tenant to blueprint YAML (`export`).
- `scripts/identities.py` + `scripts/cxone/identity_pool.py` — multi-user
  attribution: register/validate secondary API keys (`identities add/import`),
  select per action (`--as`), stable per-project owners for the agent, automatic
  403-fallback to primary.
- `scripts/ops/` — scan + triage engines (with `--seed`-reproducible randomness),
  the realism model (`realism.py`), runners.
- `scripts/ui.py` — local browser UI (auth + common actions, dry-run toggle).
- `scripts/agent.py` + `scripts/ops/activity.py` — the real-time activity agent
  (`agent run` / `agent plan`); `Dockerfile` is its container substrate.
- `config/` — `scan_rules.yaml`, `triage_rules.yaml` (the realism logic),
  `activity.yaml` (agent cadence + identity affinity), and an example
  identities sidecar (`cxone-identities.example.yaml`).
- `blueprints/` — declarative tenant definitions (`provision` applies them; `export` writes them from a live tenant).
- `references/` — API, CLI, MCP, and extension docs so Claude can do novel tasks.

## Extensibility
When asked for something not yet built, Claude adds it using `references/`
(API index + Stoplight, CLI, MCP, and the module pattern in `extending.md`)
rather than declining. Always dry-run and confirm before mutating a real tenant.
