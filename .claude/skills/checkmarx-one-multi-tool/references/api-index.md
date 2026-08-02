# Checkmarx One API Index (for novel tasks)

*Last verified: 2026-07-21 — the live-spec discovery method below was added and
confirmed working this date; the endpoint catalog list further down is a
lightly-maintained summary, not itself re-verified per entry (that's what the
live spec is for — check it directly when precision matters).
Updated 2026-08-01: the undocumented endpoints now in active use, and the two
techniques ("When the endpoint isn't in any spec") that found them — both
verified live on DEU.*

When the Multi-Tool doesn't yet have a function for what's asked, use this to find
the right endpoint, then implement it following the patterns in `cxone-api.md`.

## Where to look

- **Live per-tenant Swagger (most authoritative — check this FIRST for anything
  the bundled spec is thin on or that behaves unexpectedly):** every CxOne
  tenant serves its own live Swagger UI at `{base_url}/spec/v1` — e.g.
  `https://deu.ast.checkmarx.net/spec/v1`, `https://ast.checkmarx.net/spec/v1`,
  `https://us.ast.checkmarx.net/spec/v1` (same path, whatever regional root the
  tenant's `base_url` uses — derive it from the configured tenant, don't hardcode
  a region). It's a live Swagger UI page (HTML) that loads a per-microservice
  list of raw OpenAPI YAML files from `{base_url}/spec/v1/<region>-<service>-
  <TAG>.yaml` (~90 files on cnf26 — access-management, analytics, scans,
  results, sca, repos-manager, etc. — one per backend service). Two ways to use
  it:
  - **Browse**: open `{base_url}/spec/v1` in a browser for the interactive UI.
  - **Fetch raw YAML for a specific service**: `GET {base_url}/spec/v1/
    swagger-starter.js` and regex out the `urls: [...]` array (`{name, url}`
    pairs) to find the right service's YAML, then `GET` that YAML directly —
    no browser needed, works from a script (see `results.py`'s analytics KPI
    work for a worked example).
  - **Limitation**: these per-service YAMLs are bare, service-relative paths
    with no `servers:` block, so the public `/api/...` gateway prefix can't be
    derived from a live YAML alone — you still need that from Stoplight/
    `cxone-api.md`/empirical testing. A full raw snapshot of the live catalog
    (92 services, 463 path entries, as of 2026-07-21) is kept at
    `spec/live_catalog_snapshot.json` for browsing what capabilities/fields
    exist before assuming they don't — read its own `note` field first.
  **This HAS been caught drifting from the bundled `spec/cxone_openapi.json`
  and from the public docs at checkmarx.stoplight.io** — on 2026-07-21 the
  Analytics API endpoint alone had 5 corrections applied from this live check:
  a `scanners` enum missing 3 values, a misspelled `states` enum value (present
  on the public docs too), a `severities` enum that's lowercase here unlike
  every other engine (this was an actual code bug, not just a doc gap — see
  `spec/CLEANUP_NOTES.md` "Live sync"), a `status` enum value the live schema
  doesn't actually accept, and an undocumented `environments` filter. Treat
  the live spec as the tie-breaker whenever the bundled spec, the public docs,
  and live API behavior disagree — it's what the tenant is actually running.
  Since it's tenant/region-served and requires no auth to fetch, there's no
  reason not to check it before guessing at a payload shape.
- **Interactive API reference (public docs, may lag the live tenant):**
  https://checkmarx.stoplight.io
  Every endpoint, schema, and example. Search by resource (e.g. "applications",
  "scans", "predicates", "reports", "uploads"). Good for prose/context the raw
  YAML doesn't carry (descriptions, curl examples) — but confirm exact enums
  and required-ness against the live spec above when it matters.
- **API docs (overview + auth):**
  https://docs.checkmarx.com/en/34965-68772-checkmarx-one-api-documentation.html
- **Generating an API key (refresh token):**
  https://docs.checkmarx.com/en/34965-188712-creating-api-keys.html
- **Postman collection:** the team's `CxOne.postman_collection.json` mirrors many
  of these with working example requests.

## Auth (already implemented — reuse `cxone/auth.py`)

Refresh-token OAuth2: `POST {iam}/auth/realms/{tenant}/protocol/openid-connect/token`
with `grant_type=refresh_token&client_id=ast-app&refresh_token={api_key}`. The
returned `access_token` is the bearer for both planes. Admin operations (IAM)
need an admin API key.

## Endpoint catalog (CxOne API endpoints)

Resource-plane API groups (each documented on Stoplight and docs.checkmarx.com):

- Projects API — projects CRUD, tags, branches, webhooks.
- Applications API — applications + project-association rules.
- Scans API — create/list/cancel scans, scan workflow, status.
- Uploads API — generate upload link + upload source (zip scans).
- SAST Results API / KICS (IaC) Results API / Scanners Results API — read results.
- Results Summary API — aggregated counts.
- SAST Results Predicates API — set state/severity/comment (triage).
- SAST Scan Metadata API — engine metadata.
- SAST REST Preset Manager / SAST Query Editor APIs — presets and custom queries.
- Reports API — scan/project/application reports, SBOM, CSV.
- Audit Trail API — tenant activity.
- DAST Scans/Results API — dynamic scanning.
- Configuration (project/tenant) — scan settings.
- repos-manager — SCM integrations, repo import, projectScan.
- SCA: export service, management-of-risk, recalculation (under the SCA API docs).
- Policy Management — policies and violations.

**Not in the published catalog, but in active use** (all verified live — details
and payloads in `cxone-api.md`):

- Checkmarx Assist — `/api/ai-triage/*` (AI Triage Assist) and `/api/remediation/*`
  (AI Remediation Assist). Credit-metered.
- `/api/credits/info`, `/api/credits/consumption` — AI credit balance and usage.
- `/api/repostore/code/{scanId}` — download the exact source a scan ran against.
- `/api/risks` — risk list carrying `groupId`, `scanId`, `state`, `stateChangedBy`.
  Pages with `limit`; `pageSize` is accepted, echoed back, and ignored.
- `POST /api/sca/graphql/graphql` — GraphQL, the ONLY way to read current SCA
  triage state. Go through `ops/sca_live_state.py`, never call it directly.

## When the endpoint isn't in any spec

Everything in the list above was missing from Stoplight *and* from `{base_url}/spec/v1`.
Two techniques found them; both are cheap and worth trying before concluding a
capability doesn't exist:

1. **Ask the service for its own spec.** Some services publish OpenAPI at
   `{base_url}/api/{service}/openapi.json` with Swagger UI at `/docs` — a route
   that is NOT listed in the `/spec/v1` catalog. This is how the AI Triage and
   Remediation specs were obtained, and they were more current than the published
   reference.
2. **Probe the gateway to enumerate services.** An unknown path prefix answers
   nginx **400** ("Request Header Or Cookie Too Large" — the bearer token is
   large), while a real service answers its own **404** for an unmatched route.
   So 404-vs-400 tells you whether a service prefix exists at all. This is how
   `/api/credits` was found.

Third resort: watch what the product UI itself calls. The SCA GraphQL queries came
from there — no spec anywhere describes them.

IAM (Keycloak admin) — not in the AST catalog; standard Keycloak admin API under
`/auth/admin/realms/{tenant}`: users, groups, roles, role-mappings, identity-providers,
clients. The Keycloak admin REST reference applies.

## Method for a novel request

1. Identify the resource and whether it is AST or IAM plane.
2. Find the exact endpoint + schema — check the tenant's live spec at
   `{base_url}/spec/v1` first (see above), fall back to Stoplight for prose/
   examples (or Keycloak admin docs for IAM). If the bundled
   `spec/cxone_openapi.json` and the live spec disagree, the live spec wins.
3. Implement a small function on `ApiClient` following `cxone-api.md` patterns
   (`use_iam` flag, paginate for lists, dry-run guard on mutations).
4. Prefer adding it to the most relevant existing module; if it's a new area,
   create a new module mirroring `applications.py`'s shape (manager class + CLI).
5. Test with `--dry-run` first and confirm with the user before mutating.
