# Extending the Multi-Tool

This skill is meant to grow. When asked to do something not yet implemented,
add it rather than declining — the pieces are designed to make that quick.

## The pattern every module follows

A module is a manager class plus a small CLI:

```python
from cxone import CxConfig, ApiClient

class ThingManager:
    def __init__(self, api): self.api = api; self.cfg = api.config
    def list_things(self): return self.api.paginate("things", results_key="things")
    def create_thing(self, t):
        if self.cfg.dry_run:                      # always guard mutations
            logger.info("[dry-run] would create %s", t); return None
        return self.api.post("things", payload)
```

Rules of the road:
- **Plane:** resource data → default (AST); users/groups/roles → `use_iam=True`.
- **Lists:** use `api.paginate(endpoint, results_key=...)`.
- **Mutations:** guard with `if self.cfg.dry_run:` and log the intended payload.
- **Idempotency:** look up by name/key first and skip if present, where feasible.
- **Secrets:** never log tokens/passwords or put them in URLs; redact in dry-run.
- **Confirm:** destructive/bulk actions need explicit user confirmation in chat.

## Shared helpers — reuse these, don't re-derive them

Each of these exists because a specific trap was hit. Going around one means
hitting it again.

| Module | Use it for | Trap it absorbs |
|---|---|---|
| `ops/findings.py` | Turning a finding into the ids an API wants (`FindingRef`, `FindingResolver`, `buckets_from`, `group_id_for`) | SCA `id` vs `alternateId`; base64 result ids need `quote(v, safe="")`; initiate and retrieve key findings differently; SAST group id is the similarityId OR the attackVectorID depending on tenant config |
| `ops/sca_live_state.py` | **Any** read of current SCA triage state | SCA scans are immutable — `/api/results`, the export, and `/api/risks` all report stale or absent state (see `cxone-api.md`) |
| `ops/source_fetch.py` | Getting the code a scan actually ran against | The 302 looks like an S3 pre-signed URL but still needs the bearer token; token is attached only when the redirect host matches `base_url`; Zip Slip guard |
| `ops/state_normalize.py` | Comparing or displaying triage states | Engines disagree on casing (`ProposedNotExploitable` vs `PROPOSED_NOT_EXPLOITABLE`) |

## Adding anything that spends money or tokens

Three triage paths exist and they are deliberately **separate verbs**, because
they differ in what they cost and who decides:

| Verb | Decides | Cost |
|---|---|---|
| `triage-simulate` | statistical realism model | free |
| `triage-real` | this coding assistant, reviewing real source | coding-assistant tokens |
| `ai-assist triage` / `remediate` | Checkmarx Triage Assist | **Checkmarx AI credits** (triage 1, remediation 3, per finding) |

If you add a fourth, keep them distinct rather than adding a mode flag — the
distinction is the point, and blurring it makes a billable action reachable by
accident. Rules that apply to any new metered verb:

- **Dry-run by default, confirm before spending.** Show what will be touched, the
  credit cost, and the current balance (`ai-assist credits`), then wait.
- **Never present simulated states as a real assessment.** If `triage-real` cannot
  obtain enough evidence to make an honest call, it reports that and writes
  nothing — copy that behavior rather than falling back to a guess.
- **Measure spend against `available`, not `used`** — reservations hit `available`
  immediately while `used` settles later.

## Reading the HTTP status

`get`/`post`/`put`/`patch` return an **`ApiResult`** — a plain `dict` subclass that
also carries `.status_code`. Use it whenever "did this actually land?" matters,
especially for the many CxOne writes that answer with an empty body:

```python
resp = self.api.post(endpoint, json_body=payload)
logger.debug("wrote %d -> HTTP %s", n, resp.status_code)   # 201, not a guess
```

- Because it *is* a dict, every existing pattern still works: `resp.get("_location")`,
  `isinstance(resp, dict)`, `json.dumps(resp)`, `== {...}`.
- **List and scalar JSON bodies are returned bare** — there is nothing to hang an
  attribute on. Pass `with_status=True` to get an explicit `(body, status)` tuple.
  `delete(..., with_status=True)` returns just the status.
- `--debug` logs every request as `METHOD endpoint -> HTTP 201 (empty body)`.

This exists because it was once impossible: the client returned only the body, so a
200 and a 201 were the same value, and an empty-bodied 201 Created — the proof that
SCA triage writes were working — was unobservable. Working writes got reported as a
product defect twice over (`spec/CLEANUP_NOTES.md`, 2026-08-01). **Don't infer a
status; print it.**

## Known sharp edges

- **Non-retryable statuses raise immediately** rather than burning three
  retries — keep that behavior when adding request paths.
- **A GraphQL error is HTTP 200.** Check the `errors` array; never treat a null
  `data` as an empty result. A status code alone will not save you here.

## Finding the endpoint

1. `references/api-index.md` → the resource group and Stoplight.
2. https://checkmarx.stoplight.io for the exact path, method, and schema.
3. For IAM, the Keycloak admin REST API under `/auth/admin/realms/{tenant}`.
4. Confirm the shape against the Postman collection if present.
5. If it is not in any of those, it may still exist — several endpoints this tool
   depends on are undocumented. See `api-index.md` → "When the endpoint isn't in
   any spec" for the two discovery techniques that found them.

## Adding an SCM provider (GitLab / Azure DevOps / Bitbucket)

`onboard.py` implements GitHub fully and stubs the others. To add one:
- Mirror `onboard_github`: build the per-org/group payload, `POST repos-manager/scm-projects`
  with `scm.type` set to the provider, then poll the returned status URL.
- The differences are `scm.type` and the organization/group identity fields
  (e.g. GitLab group/subgroup, Azure org+project, Bitbucket workspace+project).
- Verify the exact identity fields on Stoplight or by inspecting a manual import
  in the tenant; build the user's primary SCM first.
- Add the provider to `SUPPORTED_SCM` and the `create_projects` dispatch.

## Adding a whole new capability area

Examples: presets, policies, webhooks, scheduled scans, reports, identity providers.
Create `presets.py` (etc.) mirroring `applications.py`, wire it into `multitool.py`'s
dispatch table, and—if it belongs in a tenant blueprint—add a section to
`provision.apply_blueprint` and the example blueprint. Document new endpoints in
`references/cxone-api.md` so the next task is even easier. Then run
`python validate_spec.py` and act on what it reports — see SKILL.md "Know
what's available" for how to resolve each finding type (`IAM-PLANE`,
`KNOWN-OMIT`, `METHOD?`, `ABSENT`) rather than leaving it as noise.

## When to use CLI or MCP instead of new code

If the `cx` CLI already does it well (scan/results/triage in pipelines) or the
Checkmarx MCP is connected and the user wants conversational querying, prefer
those (see `cli.md`, `mcp.md`) rather than reimplementing. Build new API code for
the admin-plane gaps those tools don't cover.
