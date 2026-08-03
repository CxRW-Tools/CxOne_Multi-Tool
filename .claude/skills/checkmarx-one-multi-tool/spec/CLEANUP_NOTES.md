# OpenAPI Spec — Cleanup Notes

`cxone_openapi.json` here is a cleaned copy of the Checkmarx One OpenAPI export
(`openapi: 3.0.3`, 189 paths), generated from Stoplight docs on 2026-06-27,
plus the per-service additions logged under "Vendor-spec additions" below.
**Last live-sync check: 2026-07-31** — this line, `spec/LAST_SYNCED`, and the
file's own `info.x-last-synced`/`info.x-sync-notes` must always agree; update
all three together (see "spec/LAST_SYNCED" below) whenever a sync pass touches
this file, and see the "Live sync" sections below for what's been checked so far.
Changes applied to the raw export:

1. **Removed** `/abc123...` — a placeholder for a presigned upload URL (its own
   description says it's only a placeholder), not a callable API path.
2. **Re-rooted** the SAST predicate DELETE from `/{similarityID}/{projectID}/{predicateID}`
   to `/api/sast-results-predicates/{similarityID}/{projectID}/{predicateID}`
   (the export dropped its service prefix).
3. **Added** `POST /api/repos-manager/scms/{scmId}/orgs/{orgIdentity}/repo/projectScan`
   — the SCM scan-trigger we live-validated; present in the platform but omitted
   from the export. Marked with `x-source` so it's clearly an addition.

Intentionally **retained** (legitimate, not junk):
- `/auth/realms/{tenant_account_name}/protocol/openid-connect/token` — the IAM
  token endpoint (different host/base; used by `cxone/auth.py`).
- `/accounts/{id}/logs`, `/accounts/{id}/resources` — Cloud Insights
  (base `{Base_URL}/api/insights`).

## Known export limitations (surfaced by validate_spec.py, not errors in our docs)

The export captured only a subset of methods on some service paths. Where our
docs list a method the export doesn't (e.g. create is `POST` but the export shows
only `GET` on `/api/feedback-app/v2/apps`, `/api/policy_management_service_uri/policies/v2`),
the docs carry a corrective NOTE. Confirm exact create verbs/bodies on Stoplight
when those planned features are implemented.

**Expected and correct:** `validate_spec.py` reports `ABSENT POST
/api/sca/graphql/graphql (api-index.md)`. That endpoint is GraphQL — one path, one
POST, schema carried in the query body — so it does not belong in a path-keyed
OpenAPI document. Do not "fix" this by inventing a spec entry for it; the queries
are documented in `references/cxone-api.md` and implemented in
`ops/sca_live_state.py`.

## `spec/LAST_SYNCED` — the single-source freshness date

`spec/LAST_SYNCED` holds one ISO date (currently `2026-07-21`), mirroring how
`VERSION` is the single source for the skill version. `cxone/get_reference_freshness()`
reads it and `welcome` / `version` / `--help` print "Reference spec last synced:
<date> (N days ago)", with a refresh suggestion once N exceeds
`cxone.STALE_REFERENCE_DAYS` (90). **Whenever you do a live-spec sync pass like
the one below, update this file to today's date** — it's the only thing that
makes the staleness warning meaningful; forgetting it means the tool keeps
reporting an old sync as current.

## Live sync — 2026-07-21

Every CxOne tenant serves its own live OpenAPI catalog at `{base_url}/spec/v1`
(no auth required) — ~90 per-microservice YAML files, listed via
`{base_url}/spec/v1/swagger-starter.js`'s `urls: [...]` array. This is the
actual ground truth for schema/enum details, since it's what the platform is
running right now rather than a point-in-time doc export. See
`references/api-index.md` "Where to look" for the fetch method.

**Important limitation discovered doing this sync:** the live per-service YAMLs
are bare, service-relative paths with no `servers:` block — there is no way to
mechanically derive the public `/api/...` gateway path from a live YAML alone.
That mapping (e.g. "Analytics Api" service's `/analyticsAPI/v1` → public
`/api/data_analytics/analyticsAPI/v1`) has to come from Stoplight docs or
empirical confirmation, same as how this file's paths were originally sourced.
So a full mechanical regeneration of this spec from the live catalog isn't
possible without that per-service prefix knowledge — what's practical, and
what was done here, is: (1) for every endpoint this tool actually calls,
diff its known `/api/...` path's schema against its live YAML and correct
drift; (2) keep a raw snapshot of the full live catalog
(`spec/live_catalog_snapshot.json`, 92 services / 463 path entries) for future
novel-task discovery of capabilities/fields that might exist but aren't
documented anywhere yet.

**Endpoints corrected on 2026-07-21** (all in `/api/data_analytics/analyticsAPI/v1`,
tagged `x-live-verified: "2026-07-21"` on the operation):
1. `scanners` enum was missing `secretdetection`, `repohealth`, `byor` (bundled
   spec only had `sast,iac,sca,dast,containers`) — confirmed `secretdetection`
   works live and returns real data.
2. `states` enum had `propsedNotExploitable` (typo, also present on the public
   Stoplight docs) — live schema spells it `proposedNotExploitable`.
3. `severities` enum was uppercase (`CRITICAL,HIGH,...,INFO`) matching every
   other engine in this tool — but this endpoint's live enum is **lowercase**
   and spells Info as `information`. Uppercase values 400. This was an actual
   bug in `results.py`'s `kpi()` (fixed same day — see `results.py` history /
   `ANALYTICS_SEVERITY_ALIASES`), not just a doc gap.
4. `status` enum listed `NEW, RECURRENT, FIXED` per the public docs; the live
   schema only has `NEW, RECURRENT` — `FIXED` isn't a valid filter value here
   (use the separate `fixedVulnerabilitiesBySeverityOvertime` KPI instead).
5. `projects`/`applications` filters accept EITHER an ID or a name (`anyOf` in
   the live schema) — the bundled spec only documented ID. Also added the
   `environments` filter, present live but absent from this export entirely.

Nothing else in the bundled spec was found to have drifted as of this sync —
but note everything else was verified via successful real API calls made
during actual tool operation (scans, triage, onboarding all succeeded against
their documented shapes), not a live-schema diff like the Analytics endpoint
got. If a call unexpectedly 400s against a documented shape, check the live
spec for that endpoint before assuming the bug is elsewhere.

## Live sync — 2026-07-31 (Checkmarx Assist / AI endpoints)

The export carried three AI paths that **do not exist on any tenant**:
`/api/v1/ai-triage/trigger`, `/api/v1/ai-remediation/trigger`, and
`/api/v1/ai-tr/process/{processId}`. All three 404 on a live gateway (verified
with and without auth on DEU), their `$ref`s pointed at a `#/__bundled__/...`
section that isn't in the file (so `VulnerabilityIdentifier` / `ProcessResult`
were undefined), and the "poll a processId" model they describe is not how
either service works. **Removed and replaced** with the 7 real operations:

- `POST /api/ai-triage/triage`
- `GET  /api/ai-triage/triage/{project_id}/{group_id}`
- `GET  /api/ai-triage/v2/triage/{project_id}/{group_id}`  *(live-only)*
- `POST /api/ai-triage/triage/{project_id}/{group_id}/discard`  *(live-only)*
- `POST /api/remediation/remediate`
- `GET  /api/remediation/remediation-details/{scan_id}/{result_id}`
- `GET  /api/remediation/remediation-details/{scan_id}`  *(live-only)*

Sources: both services publish their own OpenAPI at
`{base_url}/api/ai-triage/openapi.json` and `{base_url}/api/remediation/openapi.json`
(Swagger UI at `/docs`) — a per-service spec route NOT listed in the
`/spec/v1` catalog, so it is worth probing `{service}/openapi.json` directly for
any service missing from that catalog. Cross-checked against the published
Stoplight YAMLs, kept here as `spec/AI-Triage.yaml` and `spec/AI-Remediation.yaml`.

Doc-vs-live deltas found (docs are stricter than the live services):
1. `TriageRequest` — live requires only `scanID`; Stoplight also marks `buckets`
   required. Live adds `projectID`, `applicationID`, `force`, and omitting
   `buckets` triages every SAST+SCA result in the scan.
2. `TriageBucket` — live requires only `scannerType` (empty `resultIDs` = all
   results for that scanner); Stoplight also requires `resultIDs`.
3. `RemediateRequest` — live accepts an optional `projectID`.
4. Conversely, Stoplight documents `data` / `autoPr` in full while the live spec
   types them as free-form objects — the YAMLs are the better source there.
5. `AI-Triage.yaml` has a doc bug worth reporting upstream: under `POST /triage`
   the **EU** server is listed as `https://us.ast.checkmarx.net/api/ai-triage`
   (a copy of US2). The GET path's server list has `eu.ast...` correctly.

Related live findings recorded in `references/cxone-api.md` (they gate any use of
these endpoints): SCA `id` != `alternateId`, path-segment encoding of base64
result ids, and `GET /api/risks` paging with `limit` rather than `pageSize`.

### Credits API (same sync, 2026-07-31)

`GET /api/credits/info` and `GET /api/credits/consumption` were added — the AI
credit balance and per-user consumption behind Checkmarx Assist. Both are
undocumented in the Stoplight export AND absent from `{base_url}/spec/v1`, and
the service publishes no `openapi.json` of its own. They were found by probing
the gateway: an unknown prefix answers nginx **400** ("Request Header Or Cookie
Too Large", because of the bearer token), while a real-but-unmatched route
answers the service's own **404** — so 404-vs-400 enumerates which service
prefixes exist. Worth reusing for any future "does this service exist?" question.

Derived (not published): per-action credit cost is `triage=1`, `remediation=3`,
from 424 triage + 72 remediation transactions reconciling exactly to 640 credits
used, per-user across all 38 users. `info.actionsAvailable` does NOT follow that
model (it equalled `available/5`). Still unresolved: whether a transaction is
one finding or one request — see `references/cxone-api.md`.

### Scanned-source download (2026-08-01)

`GET /api/repostore/code/{scanId}` added — the UI's "Download source code".
Undocumented in the Stoplight export AND in `/spec/v1`. Answers **302** to a
pre-signed archive URL; the archive is the EXACT snapshot the scan ran against,
so finding line numbers match it precisely (a repo clone gives branch HEAD and
can be shifted). Works for zip-upload scans too, and needs no SCM token.

**Gotcha:** the redirect target carries `X-Amz-*` params and looks like S3, but
on this deployment it is the CxOne gateway (`{base_url}/storage/...`) and
**still requires the Authorization header** — following it credential-free
returns 401. `ops/source_fetch.py` therefore follows manually and attaches the
token only when the redirect host matches `base_url`, so the token is never
handed to a genuine third-party host if this moves later. Extraction guards
against Zip Slip. Powers `triage-real`.

### SCA current-state read model (2026-08-01) — and how it was misdiagnosed twice

The full read model now lives in `references/cxone-api.md` ("SCA triage — writes
work; the READ paths are scan-immutable"). Recorded here is the *investigation*,
because the shape of the mistake is reusable and cost several hours.

**Not in the spec at all:** `POST /api/sca/graphql/graphql`. Two queries carry
current SCA triage state (`vulnerabilitiesRisksByScanId` → `pendingState`;
`searchPackageSupplyChainRiskStateAndScoreActions` → supply-chain action history).
No published REST endpoint exposes it. Not added to `cxone_openapi.json` — it is
GraphQL, so it has no place in a path-keyed OpenAPI document; `ops/sca_live_state.py`
is its documentation.

**The misdiagnosis chain.** Triage writes appeared not to take, and three
successive conclusions were drawn and reported before the real cause was found:

1. "The MoR endpoints silently ignore writes for malicious-package types."
   *(Wrong — a product defect was reported that did not exist.)*
2. "Supply-chain risks are package metadata and aren't triageable." Acted on it by
   adding an `_UNTRIAGEABLE_TYPES` guard, which then suppressed writes that had
   been working the whole time. *(Wrong, and it broke a working path.)*
3. Actual cause: the writes always succeeded — **HTTP 201 Created** — and the read
   paths used to verify them (`/api/results`, the SCA export, `/api/risks`) simply
   never reflect current state for those risk types.

Three things made a correct-looking read lie, all worth checking first next time:

- **`ApiClient.post()` returned `{"_location": ""}` for an empty 201 body**, with
  the status discarded — so "200" was asserted for several turns without the code
  ever being printed. **Fixed in 3.34.0**: responses are now `ApiResult`, a dict
  subclass carrying `.status_code`, and `--debug` logs `-> HTTP 201 (empty body)`
  on every request. See `extending.md` → "Reading the HTTP status".
- **A GraphQL error arrives as HTTP 200** with `data: null`. Reading only `data`
  turns a failed query into "nothing is triaged". `_graphql()` now inspects
  `errors` and returns None (= unknown) so this cannot recur silently.
- **The GraphQL page size caps at 100** (`HC0051`). `take: 200` produced exactly
  the above: an error with `data: null`, read as empty.

The general lesson: **when a write looks like it failed, prove the read surface
reflects writes at all before concluding anything about the write.** Every
symptom here was produced by a stale-but-well-formed response.

## IAM plane

User/group/role endpoints are served by Keycloak at
`/auth/admin/realms/{tenant}/...` and are **not** part of this AST OpenAPI spec.
`validate_spec.py` labels them `IAM-PLANE` and excludes them from drift checks.


## Vendor-spec additions

Operations folded in from Checkmarx's own per-service spec files rather than
from a full re-export. These are additive and scoped to the named service, so
`spec/LAST_SYNCED` is deliberately NOT advanced by them — that date means "the
whole bundled spec was re-checked against live", and claiming it for a
single-service addition would overstate what was verified.

### 2026-08-03 — SAST Results Predicates (attack-vector operations)

Source: the vendor's *SAST Results Predicates API* spec (`NEWSastResultsPredicates.yaml`).

* **Added `POST /api/sast-results-predicates/attack-vector`.** This is what
  `ops/triage/sast_handler.py` writes through on Attack-Vector-mode tenants —
  it has been exercised live on cnf26 throughout, most recently applying 43
  reviewed SAST decisions. It had been carried in
  `validate_spec.KNOWN_SPEC_OMISSIONS` since the bundled export predates the
  feature; that allowlist entry is now **deleted**, because a carried omission
  is debt to clear, not a permanent silence. Captured behaviours worth keeping:
  409/4091 on inconsistent states across similarity groups unless
  `allowInconsistentStates` (the mixed-state case `triage_rules.yaml →
  sast_grouping.mixed_state_policy` handles), and 405/4002 when
  `SAST_ADVANCED_GROUPING_ENABLED` is off — which is a Similarity-ID tenant
  answering normally, not an error.
* **Added `GET /api/sast-results-predicates`** (`getPredicatesByAttackVectorID`),
  the read counterpart: predicate history — state, comment, `createdBy`,
  `createdAt` — for an attack vector. The bundled export had only `post`/`patch`
  on that path. `ops/triage_history.py` currently reads history via
  `GET /api/sast-results-predicates/{similarityId}`; this is the vector-keyed
  equivalent for AV-mode tenants.

Also confirmed against the vendor specs for
`kics-results-predicates` and `micro-engines/{read,write}/predicates`: both
already matched the bundled spec, no change needed.

**Enforcement.** `scripts/publish_skill.py` now runs `validate_spec.py --strict`
as a publish preflight, so a change that leaves code or docs referencing an
endpoint the spec cannot describe cannot be published. The validator's summary
also prints the carried `KNOWN_SPEC_OMISSIONS` on every run, so remaining debt
stays visible instead of reading as "0 misses".
