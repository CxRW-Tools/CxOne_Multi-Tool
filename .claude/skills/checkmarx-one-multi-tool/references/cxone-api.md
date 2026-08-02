# Checkmarx One API Reference

*Last verified against the live tenant spec: 2026-07-21 (see `spec/CLEANUP_NOTES.md`
"Live sync" for method + what was checked). Platform behavior can drift between
syncs — if something here disagrees with a live 400/enum error, the live spec at
`{base_url}/spec/v1` (see `api-index.md`) is the tie-breaker, not this file.*

Endpoints and payloads used by the Multi-Tool, plus enough structure to add new
ones. Verified against working code (v1 Tenant Builder, v2 Swiss Knife) and the
CxOne Postman collection. When you need something not listed, see
`api-index.md` (full API catalog + Stoplight) and `extending.md`.

## Two API planes

| Plane | Base | Client arg | Holds |
|---|---|---|---|
| AST / resource | `{base_url}/api/...` | `use_iam=False` (default) | projects, applications, scans, results, configuration, repos-manager, sca export, reports, policies, presets |
| IAM / Keycloak admin | `{iam}/auth/admin/realms/{tenant}/...` | `use_iam=True` | users, groups, roles, memberships, identity providers |

`iam` host derives from `base_url` by swapping `ast.` → `iam.`. Override with
`CXONE_IAM_BASE_URL`. Auth (both planes): OAuth2 refresh-token grant,
`client_id=ast-app`, at `{iam}/auth/realms/{tenant}/protocol/openid-connect/token`.
Handled by `cxone/auth.py`; never build this by hand.

---

## IAM — `iam.py`  (Keycloak admin, use_iam=True)

| Action | Method + endpoint | Body / notes |
|---|---|---|
| List groups | `GET groups` | array of `{id,name}` |
| Create group | `POST groups` | `{"name":...,"attributes":{"cxone-multitool":["true"]}}` — the attribute is the scoped-purge marker |
| Delete group | `DELETE groups/{id}` | |
| Find user | `GET users?username=&exact=true` | array |
| Create user | `POST users` | `{"username","email","firstName","lastName","enabled":true,"emailVerified":true}`; new id is last segment of `Location` header |
| Set password | `PUT users/{id}/reset-password` | `{"type":"password","value":...,"temporary":bool}` |
| Add to group | `PUT users/{id}/groups/{groupId}` | membership = access in CxOne |
| Delete user | `DELETE users/{id}` | |
| List realm roles | `GET roles` | |
| Assign realm role | `POST users/{id}/role-mappings/realm` | `[{"id","name"}]` |
| List user's groups | `GET users/{id}/groups` | read-only; used by blueprint export |
| List user's realm roles | `GET users/{id}/role-mappings/realm` | read-only; export filters Keycloak builtins (`offline_access`, `default-roles-*`) |
| List user's client roles | `GET users/{id}/role-mappings/clients/{uuid}` | ast-app client uuid via `GET clients?clientId=ast-app`; read-only, used by export |

Notes: `create_user` stamps `attributes.cxone-multitool` (scoped-purge marker)
and never resets an existing user's password — a deliberate password change is
`iam set-password` (`PUT users/{id}/reset-password`).

---

## Applications — `applications.py`  (AST plane)

| Action | Endpoint | Notes |
|---|---|---|
| Create | `POST applications` | see payload below |
| List | `GET applications` (paginated) | |
| Update fields | `PATCH applications/{id}` | |
| Delete | `DELETE applications/{id}` | rules: `DELETE applications/{id}/project-rules/{ruleId}` |

```json
{"name":"Acme Online Banking","description":"","criticality":4,
 "rules":[{"type":"project.tag.key.exists","value":"app:banking"}],
 "tags":{"team":"banking"}}
```
Projects join an application by tag rule: tag the project with the key the rule
matches. `criticality` 1–5. `tags` is a dict.

---

## Projects + onboarding — `onboard.py`  (AST plane)

Manual project — `POST projects`:
```json
{"name":"juice-shop","groups":["<group-uuid>"],"origin":"Checkmarx One Multi-Tool",
 "tags":{"app:banking":""},"criticality":3}
```
`groups` are group **UUIDs** (resolve names via `iam.get_group_id`).
List/get/delete: `GET projects` (paginated, `totalCount`), `GET/PUT/PATCH/DELETE projects/{id}`.

GitHub onboarding (bulk, per-org, async) — `POST repos-manager/scm-projects`:
```json
{"scm":{"type":"github","token":"<pat>"},
 "organization":{"orgIdentity":"<org>","monitorForNewProjects":false},
 "defaultProjectSettings":{"webhookEnabled":true,"decoratePullRequests":true},
 "projects":[{"scmRepositoryUrl":"https://github.com/<org>/<repo>",
   "protectedBranches":[],"branchToScanUponCreation":"main",
   "customSettings":{"webhookEnabled":true,"decoratePullRequests":true,
     "tags":{"app:banking":""},"groups":["<group-uuid>"]}}],
 "scanProjectsAfterImport":false}
```
Response has `processId` and a `message` containing `... GET <status-url>`. Strip
to the path after `/api/` and poll: `currentPhase` → `DONE`, then `result.status`
is `OK`/`PARTIAL`/failed with `successfulProjects` and `failedProjects[{repoUrl,error}]`.
Poll backoff 2s→10s, ~50 attempts. "already imported" = warning, not failure.
GitLab/Azure/Bitbucket: same shape, different `scm.type` + identity — see `extending.md`.

Triggering a scan on an already-onboarded SCM project (used by `scan`):
`POST repos-manager/scms/{scmId}/orgs/{org}/repo/projectScan?projectId={id}`.

---

## Scan configuration — `scanconfig.py`  (AST plane)

`GET configuration/project?project-id={id}` → flat list `{key,name,category,value,...}`.
`PATCH configuration/project?project-id={id}` with changed items, `originLevel:"Project"`.
Key fields: `scan.config.sast.presetName`, `scan.config.sast.incremental` ("true"/"false").

---

## Scans — `ops/scans.py`  (AST plane)

- Manual project: `POST scans` with `{"project":{"id"},"type":"git","handler":{"branch","repoUrl"},"config":[...]}`. This is the **documented** Scans API.
- SCM project: `projectScan` (above). **⚠ Undocumented/internal endpoint.** It is
  not in the public Checkmarx One API Reference — it's the call the Checkmarx UI
  uses to scan an SCM-imported project, reverse-engineered from observed behavior.
  Consequences to respect: (a) no published request/response schema — and
  **live-verified 2026-07-28: it returns an EMPTY body with NO `Location` header,
  so there is no scan id to parse at all.** This is by design, not drift: it hit
  100% of SCM scans (6/6 in one agent window) while a manual-route scan in the
  very same event returned an id normally. Don't chase it as a regression; (b) it
  can change without notice in any release; (c) if it ever breaks, the documented
  fallback is
  the Scans API (`POST /api/scans`) with the project's repo URL + branch — that
  path loses SCM-native niceties (PR decoration, scorecard, SCM-token context) but
  is spec-backed. Don't present `projectScan` as a stable/official API.
- **Endpoint is chosen per project, so a mixed batch is fine.** A project is SCM
  iff it has both `scmRepoId` and `repoId` (the ids the `projectScan` URL needs) —
  NOT by `origin`, which is set on manual projects too (e.g. "Checkmarx One
  Multi-Tool") and can't discriminate. SCM → `projectScan`; everything else →
  `POST scans`. The scan op logs the chosen route per project.
- **Trigger → confirm is ONE flow for both routes** (`_confirm_scan` /
  `_finalize_trigger` in `ops/scans.py`), so the endpoints' different response
  shapes don't leak into results. Step 1: issue the trigger — a raised exception
  is the *only* explicit failure and returns immediately. Step 2: resolve the
  scan and read its real status. Any id in the trigger response is treated as a
  **hint** (present on `POST scans`, absent on `projectScan`); when it's missing
  or doesn't resolve, the scan is found via `GET scans?project-id=…&sort=-created_at`
  taking the newest scan created at/after the trigger instant (120s skew
  tolerance, polled ~4×2s since the record can lag the trigger). Result carries
  a real `scan_id` + `status`; a `Failed`/`Canceled`/`Partial` status is marked
  `✗` in the summary — the trigger succeeded, the scan didn't, and those are
  reported as different things.
- Both trigger endpoints may return an empty body with a `Location` header rather
  than an inline id (the 201-Created pattern); the scan id is the last path
  segment of that URL. The client surfaces it as `_location` and the id extractor
  parses it, so scan-id capture works for both manual and SCM triggers. The
  response also carries `.status_code` (see `extending.md`), so an empty-bodied
  201 is observable rather than inferred.
- `config[].type` ∈ `sast, sca, kics, apisec, containers, microengines`
  (microengines expands to `2ms` + `scorecard` for SCM).
- Secret detection (`2ms`) runs on manual / clone-URL scans too — the scan builder
  sets `microengines.value = {"2ms": "true"}` so secrets are covered on any project.
  Scorecard stays SCM-only (needs repo/PR metadata via an SCM token).
- The API client sends `User-Agent: cxone-multitool`, which CxOne records as the
  scan's `userAgent` ("origin") instead of the bare `python-requests/x`.
- Branch/repo are read from the latest Completed/Partial scan when available.
- Weighted config rolls (preset/incremental) come from `config/scan_rules.yaml`.

## Results + triage — `ops/triage/*`  (AST plane)

**SAST grouping modes.** Tenants triage SAST by Similarity ID (classic) or by
Attack Vector (`SAST_ADVANCED_GROUPING_ENABLED`); each mode's WRITE endpoint
HARD REJECTS the other with 400/code 4002. `sast_grouping.mode: auto` detects
the mode in two layers: (1) authoritative read of
`GET sast-configuration` -> `scan.config.sast.advancedTriageMode`
("Similarity ID" | "Attack Vector ID"), cached per (tenant, project) because
the entry is tenant-origin with allowOverride: true; (2) if that read fails,
assume simid and let the first 4002 name the real mode — the handler flips,
refunds the pass's budget, and RETRIES THE SAME PASS in-process (refetch ->
re-match -> re-apply, single-retry guard), so one-shot CLI invocations recover
immediately instead of waiting for a "next pass" that never comes.

| | Similarity ID mode | Attack Vector mode |
|---|---|---|
| Fetch surface | unified `GET /api/results` | `GET sast-results/` listing (state + resultHash; per the Enrichment design NO listing carries vector ids), then `POST sast-results/similar-results` `{scanId, resultsHash[≤200]}` maps hash -> group id (= the vector id in AV mode) AND yields per-group `isStateInconsistent` + the tenant's effective `groupingMode`; fallback `GET sast-results/compare?scan-id=X&base-scan-id=X&include-additional-columns=true` (self-compare) carries `attackVectorID` per result |
| Endpoint | `POST sast-results-predicates` | `POST sast-results-predicates/attack-vector` |
| Body | array of per-simid predicates | SINGLE-element array per vector, incl. `language`/`queryName` when available (only single-element requests return honest 409/404; multi-element is always 201, failures in server logs) |
| Decision unit | similarity group | attack vector (one realism roll keyed by vector id, coverage from the group's worst severity, ONE heavy-budget unit) |
| Mixed states | n/a | pre-known from similar-results' `isStateInconsistent` -> Mode 2 / skip / override chosen UP FRONT per `mixed_state_policy` (default filtered); the 409 handler remains as the server-authoritative fallback |
| Feature off | — | 405 OR 403+4002 "featureUnavailable" (specs disagree; both sniffed) -> auto falls back to simid |

Mode detection now has THREE sources, best-first: (1) `GET sast-configuration`
(needs an allowlisted X-Source header); (2) similar-results' `groupingMode` in
the response — in-band, no special header, and on a mismatch the handler flips
and processes the SAME pass per-result at zero cost; (3) the write-side 4002
rejection with in-pass retry. similar-results returning 405/code 4005 means
SAST_ADVANCED_GROUPING_ENABLED is off (-> simid). A separate flag,
SAST_ADVANCED_GROUPING_STORE_ATTACK_VECTOR_ENABLED, controls whether vector
ids are computed AT ALL — observed live: account mode can be Attack Vector
while this flag is off, leaving no scan (however fresh) with ids and the CxOne
UI unable to vector-triage either; the tool reports exactly this when nothing
resolves. similar-results also returns an EMPTY set while a predicate update
is in flight (retry shortly). `sast_grouping.attack_vector_field` remains as
the last-resort direct-field override. The `GET sast-configuration` mode read requires an
allowlisted `X-Source` caller header (403/4003 otherwise); the handler sends
`sast-results-viewer` by default (the value the CxOne UI itself uses, verified
accepted live on cnf26), so this read works out of the box. Override via
`sast_grouping.config_xsource` (config) or `CXONE_SAST_CONFIG_XSOURCE` (env) if a
platform build ever changes the accepted value — capture the new one from the
UI's own request in browser devtools. If the read still fails, detection falls
back to the 4002 layer, which works but costs one rejected write. Server-side updates are ASYNCHRONOUS (the UI
polls `POST sast-results/predicates-status`), and with
RESULTS_METADATA_GROUPING_ENABLED on, one vector update propagates
application-wide in the background — applied counts understate true impact.

- SAST/IaC results: `GET results` (paginated). Predicates (state/severity/comment):
  SAST `POST sast-results-predicates`, IaC `POST kics-results-predicates`
  (see handler files for exact paths/payloads).
- **`type` is NOT a filter on `GET results`** — it is only a *sort* option. The
  documented filters are limit/offset/sort/severity/state/status, so passing
  `type=sast` is ignored and the feed returns every engine mixed. Filter by each
  result's `type` field client-side (`ops/triage/base_handler._get_results_page`).
- **State filtering — triage acts ONLY on To-Verify (untriaged) results.** We pass
  `state=TO_VERIFY` to `GET results` (server-side, to page less data) AND re-check
  each result's `state` client-side, which is authoritative. Both are needed: the
  server `state` filter's reliability on this endpoint isn't guaranteed across
  engines, so the client check (`ops.state_normalize.is_to_verify`, which accepts
  every engine spelling — `TO_VERIFY`/`ToVerify`/`To Verify`) is the real guard.
  This is what makes triage idempotent across repeated agent passes: a finding a
  prior pass moved to Confirmed/Proposed-Not-Exploitable is no longer re-selected,
  so states don't flip and notes aren't re-posted on every pass. An empty/unknown
  state is treated as NOT To-Verify (skip) — safer to leave a finding alone than
  to risk clobbering a triaged one.
- **similarityId format differs by engine**: SAST is numeric, KICS/IaC is a hash,
  SCA is a CVE id. Each engine's predicate endpoint accepts its own format — so route
  results by `type` and never post one engine's findings to another's endpoint
  (doing so 400s the whole bulk call: "invalid number passed for field similarityId").
- Triage comments: the realism model attaches a state-appropriate analyst note per
  decision (`realism.comment_for`, pools in `triage_rules.yaml comments_by_state`).
- SCA: async export — `post_sca_export` → `poll_sca_export` → `download_sca_export`.
  Three management-of-risk bulk endpoints — **`actions` is a top-level sibling of the
  item list and applies to every item in the batch**, so group items by target state
  and make one bulk call per group:
  - Vulnerabilities `POST sca/management-of-risk/package-vulnerabilities/bulk`:
    `{packageVulnerabilitiesProfile:[{packageName,packageVersion,packageManager,vulnerabilityId,projectIds:[]}], actions:[{actionType:"ChangeState"|"ChangeScore", value:"<State>"|<int>, comment}]}`
  - Supply-chain risks `POST sca/management-of-risk/package-supply-chain-risks/bulk`:
    same shape but list key `packageSupplyChainRisks` and id field `supplyChainRiskId`.
  - Packages (mute/snooze) `POST sca/management-of-risk/packages/bulk`:
    `{packagesProfile:[{projectId,packageName,packageVersion,packageManager}], actions:[{actionType:"Ignore", value:{state:"Muted"|"Snooze"|"Monitored", endDate:<iso|null>}, comment}]}`
  - SCA states: `ToVerify, NotExploitable, ProposedNotExploitable, Confirmed, Urgent`.
  - Distinguish vuln vs supply-chain risk by the export's `Vulnerabilities[].Type`
    (`Regular` = vulnerability; other = supply-chain). Exploitability from
    `ExploitablePath`/`ExploitabilityStatus`; package signals: `UsageType`,
    `IsMalicious`, `LatestVersionWithoutVulnerabilities` (empty = no fix → snooze).
- Secrets (Secret Detection / 2ms): results type `sscs-secret-detection`; triage via
  `POST micro-engines/write/predicates` with header `Accept: */*; version=1.0` and a
  flat array `[{similarityId, projectId, severity, state, comment}]` (UPPER_SNAKE
  state/severity, hash similarityId accepted). Reports under statusDetails `microengines`.
- **Containers state values are PascalCase with NO SPACES** — live-verified
  2026-07-29 on cnf26. `NotExploitable` / `ProposedNotExploitable` are accepted;
  the spaced `Not Exploitable` / `Proposed Not Exploitable` are REJECTED with
  400 `{"errors":[{"message":"Invalid state: Invalid state: Not Exploitable"}]}`.
  The public docs contradict themselves: the endpoint's "Allowed values" list
  shows the SPACED forms while its own request example sends `"NotExploitable"` —
  the example is correct. `Confirmed`/`Urgent`/`ToVerify` are unaffected (no
  space either way), which is why exactly two states silently failed and roughly
  half of all container triage writes were lost.
- **packageId CANNOT be constructed from `GET results` — read it from the
  containers GraphQL service.** The stored id is a 4-field composite
  `{type}#-#{name}#-#{version}#-#{distribution}`, e.g.
  `Npm#-#tar#-#7.5.15#-#debian:12`, `Oval#-#openssl#-#3.5.6-r0#-#alpine:3.23.4`.
  `GET results` carries only `packageName`, `packageVersion`, `imageName`,
  `imageTag` — NEITHER of the other two fields:
  - `type` varies by ecosystem (`Oval` for OS packages, `Npm` for npm, …), so a
    hardcoded `Oval#-#` prefix is wrong for every language package.
  - `distribution` is the image's BASE OS, NOT the image tag: `node:24` →
    `debian:12`, `node:20-alpine` → `alpine:3.23.4`,
    `gcr.io/distroless/nodejs24-debian13:latest` → `debian:13`.

  A prior note in this file claimed `Oval#-#{name}#-#{version}#-#{image}:{tag}`
  was live-verified correct. It is not: measured 2026-07-30 on cnf26 it matched
  **0 of 2056** findings across three projects (Totally_Secure 0/82, Juice Shop
  0/1932, ShopWorthy/frontend 0/42) — container triage had never resolved a
  single finding. The false positive came from testing against a distro-base
  image (`ubuntu:22.04`), where the image tag coincidentally EQUALS the
  distribution string. The docs' "Workflow" section was right that GraphQL is
  needed for the 4th field. **Lesson: verify an id format against a DERIVED
  image (node:*, python:*-slim), never only a distro-base one.**
- **Containers GraphQL — `POST {base}/api/containers/buffet/graphql`** (AST plane,
  same bearer token; no version header needed). Introspection is enabled. Root
  query fields: `images`, `imagesVulnerabilities`, `imagePackages`, `imageLayers`,
  `imageRemediations`, `imageCounters`, `severityDistribution`,
  `fixableDistribution`, `groups`, `group`.
  - `imagesVulnerabilities(scanId, imageId, take, skip, …)` returns per-package
    `{packageName, packageVersion, type, distribution, id, aggregatedRisks{risksList{cve,state,…}}}`
    where `id` IS the triage `packageId`. Page with `take`/`skip` (~100 per page;
    `totalCount` counts packages, not risks).
  - **`imageId` is REQUIRED** — omitting it 404s with `image information not found
    in GetImagesVulnerabilities query`. Its value is `imageName:imageTag` exactly
    as `GET results` reports it, registry-qualified names included.
  - Index per image, not globally: the same package+version in two images can
    carry different distributions and therefore different ids.
  - The `cveName` from `GET results` (including Checkmarx-internal `Cx…` ids for
    non-CVE findings) matches `risksList[].cve` — live-verified 2056/2056, so
    results→GraphQL joins on `(imageId, packageName, packageVersion)` + cve.
  - `ImageInfoType` (the `images` query) has NO `id`/`name`/`tag` fields; it
    exposes `imageId, imageName, baseImage, vulnerabilities, pkgCount,
    vulnerablePkgCount, size, runtime, fixable, severity, maliciousPackagesCount,
    isImageMalicious, maliciousDescription, groupsData, status, scanError,
    snoozeDate, imageHash`. Deriving `imageId` from the findings themselves avoids
    this query entirely.
- **Never classify container errors on status code alone.** A prior
  `"400" in str(exc)` catch-all swallowed the `Invalid state` 400 above and
  reported it as an unresolvable packageId, hiding a real bug behind a
  plausible story and counting the losses as benign "skipped". Match on the
  response BODY (`"risk not found"`) and surface the server's own message
  otherwise.
- Containers: results type `containers`; triage via `POST containers/triage/triage/
  vulnerability-update` (header `Accept: */*; version=1.0`) — one call per (state,
  severity) with `triages:[{packageId, cveId}]`; package/image mute via
  `package-update` / `image-update` (status Monitored|Muted|Snoozed). The `packageId`
  comes from the GraphQL `id` field (see above) — never reconstruct it; when an id
  doesn't match a stored risk the API returns 400 "risk not found".
- **vulnerability-update payload — mirror the UI.** Captured from the product UI
  2026-07-30 (returned `{"success":true}`) and reproduced live by this tool the
  same day:
  `{state, scanId, projectId, user, group:"vulnerabilities", triages:[{packageId, cveId}]}`.
  - `group` is **nullable and appears to be view context, not semantics** — the UI
    sends `"vulnerabilities"` from one view and `null` from another (both succeed).
    It does NOT widen the write: a `group:"vulnerabilities"` call carrying 20
    triages changed exactly those 20 risks and left the other 62 To-Verify
    (live-checked on cnf26). We send `"vulnerabilities"`.
  - `user` is the display name shown in the finding's triage history, e.g.
    `"Ryan Wakeham"`. Read it from the ACCESS token, not the API key: the key is a
    refresh token with no name claims, while the access token carries
    `name` / `given_name`+`family_name` / `preferred_username`. Each identity mints
    its own access token, so `--as` attribution follows for free.
  - **Do NOT send `severity`.** The UI omits it and the call succeeds, and the
    field is a severity CHANGE — echoing a severity read from `/api/results` would
    silently overwrite the scanner's rating whenever the two sources disagree.
  - `comment` is a top-level string on this same endpoint, and it IS stored —
    live-verified 2026-07-30 via triage-history (below) on all 40 findings this
    tool triaged: comment present 40/40, `user` 40/40. Note `/api/results` is a
    red herring here — it reports `comments.comments` as `""` even for findings
    that demonstrably carry a comment, so never conclude from it that a comment
    was lost.
- **Read back container triage — `POST containers/triage/triage/triage-history/
  {projectId}/{scanId}`** with body `{packageId, cveId}` (header
  `Accept: */*; version=1.0`). This is the authoritative audit view and the only
  way to verify comments and attribution. Note it is a **POST with a body despite
  being a read**, and the ids are PATH params — the guessable `GET
  .../vulnerability-history` and `.../history` both 404, which is what made this
  look unverifiable before.
  Returns `{state, resolvedStateName, packageStatus, imageStatus, actions:[{events:
  [{actionType:"StateChanged", oldValue, newValue}], user, comment, createDate}],
  comments:[{comment, user, createDate}], severity, score, …}`.
  - `severity` comes back `""` and `score` `0` on a state-only triage —
    independent confirmation that this endpoint does not want a severity from us.
  - Use this (not the 200 from the write, and not `/api/results` comments) when
    asked whether triage "really" landed, who it's attributed to, or what the
    analyst note says.
  - Verify container triage by re-reading state, not by the 200: GraphQL
    `risksList[].state` and `GET results` `state` both reflect it (live-checked
    agreeing at 20 applied / 62 untouched on cnf26).
- **Pagination caveat:** `GET results` caps at ~100 per page and offset paging is
  unreliable, so fetch with a large `limit` (handlers use 10000) and apply the
  engine (`type`) and state (To-Verify) filters client-side as described above.
- **Scan selection:** a scan can be Completed overall yet not have run a given engine
  (e.g. an SCA-only re-scan), so verify the engine in `statusDetails`/`engines` before
  triaging against it — don't just take the newest Completed scan.
- Realism: one weighted roll per result from `config/triage_rules.yaml`. Idempotent
  because triage only ever acts on To-Verify results (SCA checks each export
  record's `RiskState`; other engines filter on the result `state`), so a finding
  is triaged at most once and repeated passes never re-flip it. This is the
  differentiated demo logic.
- Triage engines wired in `ops/triage/triage_operation._ENGINE_MAP`: sast, iac, sca,
  secrets, containers. (API Security has no documented triage predicate endpoint.)

## Analytics KPIs — `results.py kpi` / `ApiClient.query_analytics_kpi`  (AST plane)

`POST /api/data_analytics/analyticsAPI/v1` — server-side aggregated tenant-wide
KPIs (severity/state/status distributions, aging, most-common vulns, mean time
to resolution, IDE scan activity). **Prefer this over walking every project's
`GET /api/results` client-side** when the question is a tenant-wide count/rollup
(e.g. "triage state by severity across the tenant") — one call vs. O(projects ×
findings). Reserve the per-project `results.py summary/show` path for per-project
drill-down or when you need the actual finding records, not just counts.

`kpi` values (pass to `--kpi` / `query_analytics_kpi(kpi, ...)`):
`vulnerabilitiesBySeverityTotal`, `vulnerabilitiesByStateTotal`,
`vulnerabilitiesByStatusTotal`, `vulnerabilitiesBySeverityAndStateTotal`,
`vulnerabilitiesBySeverityOvertime`, `meanTimeToResolution`,
`fixedVulnerabilitiesBySeverityOvertime`, `agingTotal`, `allVulnerabilities`
(needs `limit`+`offset`, limit ≤1000), `mostCommonVulnerabilities` /
`mostAgingVulnerabilities` (need `limit`, ≤100), `ideOvertime`, `ideTotal`.

**Gotchas (live-validated on cnf26, all diverge from the public doc site at
checkmarx.stoplight.io):**
- **`endDate` is required**, not optional-defaults-to-now as documented — omitting
  it 400s with `"endDate cannot be null"`. `query_analytics_kpi` defaults it to
  now (ISO 8601, no `Z` suffix — `%Y-%m-%dT%H:%M:%S`) so callers don't need to know this.
- **`startDate` must be within the last year** — anything older 400s with
  `"startDate must not be less than 1 year from today's date"`. Default: 364
  days back. Pass `start_date` explicitly for a narrower window.
- **Content-Type must be `application/json; version=1.0`**, not the client's
  default `application/json` — `query_analytics_kpi` sets this via
  `extra_headers` already; a bare `api.post(...)` without it 400s.
- **The `scanners` filter enum is bigger than our bundled `spec/cxone_openapi.json`
  lists.** The bundled spec only has `sast, iac, sca, dast, containers`; the
  tenant's LIVE spec (see "Live spec" below) additionally has `secretdetection`,
  `repohealth`, `byor` — all confirmed working live (e.g.
  `scanners: ["secretdetection"]` returns real Secrets triage-state counts, which
  the bundled spec's enum would incorrectly suggest is unsupported). **When a
  filter/enum question turns on this endpoint, check the live spec, not the
  bundled snapshot — they've drifted.**
- **The doc site's `states` filter values have a typo**: it lists
  `propsedNotExploitable`; the live spec's `StateType` enum has the correctly
  spelled `proposedNotExploitable`. `ANALYTICS_STATE_ALIASES` in `results.py`
  maps the friendly `--states "Proposed Not Exploitable"` to the correct spelling.
- `projects` accepts EITHER project ID or project name (`anyOf` in the live
  schema) — no separate name-resolution call needed, unlike `results.py
  summary/show` which must resolve names to IDs via `GET projects` first.
- Response shape is a flat array of `{label, results, severities:[{label,
  results}, ...]}` for the *Total KPIs; `_print_severity_and_state_table` in
  `results.py` renders `vulnerabilitiesBySeverityAndStateTotal` as a table — the
  other KPIs are printed as raw JSON (add a formatter if one earns its keep).
- Scope: **tenant-wide by default** (no `--projects` filter) — this is a
  snapshot across every project's current findings, not a per-project drill-down.

## Audit trail — `audit.py`  (AST plane)

`GET /api/audit-events` — tenant activity log (who did what, when). Replaces
the deprecated `GET /api/audit` (still in the bundled spec, flagged
deprecated in its own description — don't use it). Confirmed live-working via
a reference implementation supplied for this feature; the bundled spec's
`auditEvent` response schema is an unresolved `$ref` (same class of gap as
the `feedback-app`/`policy_management_service_uri` paths noted at the top of
`planned-features.md`), so the field list below is sourced from that
live-validated run, not the bundled spec.

**Request**
- Headers: `Authorization: Bearer <token>`, **`Accept: application/json;
  version=1.0`** — required; the client's default `Accept: application/json`
  gets no special treatment from this endpoint, so `audit.py` passes it via
  `extra_headers` (same pattern as `query_analytics_kpi`'s Content-Type).
- Query: `startDate`, `endDate` (RFC3339, e.g. `2026-01-01T00:00:00Z`),
  `limit` (≤ 1000, default 100), `offset` (record count, not a page index —
  `ApiClient.paginate` already treats it that way by default, so no
  page-indexed special-casing was needed here, unlike `/api/results`).
- **Events are retained for the previous 365 days only**, and the platform
  only began collecting them on **2026-03-29** — a query spanning further
  back than that returns nothing for the earlier portion, which is normal,
  not an error.

**Response:** `{"events": [...], "totalFilteredCount": N, "_links": {...}}`.
Each event (live-validated shape): `eventID`, `eventDate`, `eventType`
(e.g. `project.created`, `user.login`), `auditResource` (e.g. `project`,
`user`, `application`), `actionType`, `actionUserId` (a Keycloak user UUID),
`ipAddress`, `data` (a nested dict whose keys vary by `eventType`).

**Coverage is a moving target, not a fixed catalog.** Checkmarx keeps adding
event emission engine by engine; as of this writing several engines (e.g. IaC)
only emit events for a subset of their actions. Treat a thin or empty result
for something you know happened as a platform coverage gap — say so — rather
than concluding the action didn't occur or that this module is broken.

**Audit answers "who did what, when" — never "what's true right now."** The
log is append-only and never reconciled against live state: a project, scan,
or result the events reference may since have been deleted, purged, or
superseded by a re-scan (a new scan issues fresh result identifiers, so old
events keep pointing at ones that no longer resolve to anything). Concretely:
deduping `sast-result.update` events to "latest event per result" and
counting them is NOT the same number as querying current findings (`GET
results` / `results kpi`) for that state — the audit count runs over every
result ID ever mentioned in the retention window, live or not, and (unless
you also filter `data.severity`/equivalent) may span a different severity mix
than whatever live number you're comparing it to. Live-verified 2026-08-02: an
audit-derived "184 results currently in Not Exploitable/Proposed Not
Exploitable" collapsed to 172 once cross-checked against live results, with
several of the audit-only project IDs no longer present in `project list` at
all. **For a "what does X look like today" question, query live state
(`results`/`project`/`iam` etc.) and use audit only to attribute or narrate
already-known live findings — never as the source of a current count.**

**UUID resolution (`--human-readable`).** `actionUserId`/`userId`,
`roleId`/`assignedRoles`/`unassignedRoles`, and `groupId` values are Keycloak
IDs, resolved via the same IAM admin calls every other module already makes
(`ApiClient.get(..., use_iam=True)` — no new URL construction needed):
`users/{id}`, `roles-by-id/{id}`, and `groups` (list + match by id, since
there's no single-group-by-id admin endpoint). Best-effort: a lookup miss
(deleted principal) falls back to the raw UUID instead of raising, since
resolution is a display nicety and shouldn't fail the whole query.

## Scanned source — `ops/source_fetch.py`  (AST plane)

`GET /api/repostore/code/{scanId}` → **302** → pre-signed archive URL → zip of the
**exact snapshot the scan ran against**. What the UI's "Download source code" uses.
Undocumented: absent from the Stoplight export AND from `/spec/v1`.

Why `triage-real` depends on it rather than cloning:
- Line numbers match findings **exactly**; a clone gives branch HEAD, which drifts.
- Works for zip-upload scans, which have no repo to clone.
- Needs no SCM token and no reach to GitHub/GitLab.

**The redirect gotcha (live-verified 2026-08-01).** The `Location` carries
`X-Amz-Algorithm`/`X-Amz-Signature` and looks like an S3 pre-signed URL — but it
points back at the CxOne gateway (`{base_url}/storage/...`) and **still requires
the Authorization header**. Following it as you would a real pre-signed URL
(no auth) returns **401**. The rule implemented: follow the redirect manually and
attach the bearer token **only if the redirect host matches `base_url`** — so the
token is never leaked if this ever moves to genuine third-party storage.

Archives age out; a 404 means "no stored source", which `triage-real` treats as
"cannot review" rather than "empty project". Extraction guards against Zip Slip
(`../` entries are skipped) since the archive mirrors a scanned repo.

## SCA triage — writes work; the READ paths are scan-immutable

**All SCA risk types triage successfully**, regular and supply-chain (malicious /
typosquat) alike, via both the singular and `/bulk` management-of-risk endpoints.
They answer **HTTP 201 Created** with an empty body — confirmed live 2026-08-01
against a Low SCA finding on TSA:

```
POST sca/management-of-risk/package-vulnerabilities/bulk
  -> HTTP 201   body: {'_location': ''}
```

The body carries no evidence whatsoever, so the status is the only signal that the
request was accepted. Read it off the response's `.status_code`, or run with
`--debug` to see `-> HTTP 201 (empty body)` per call.

**But 201 ≠ applied.** It means accepted, not that it matched any risk — a write
against a non-existent id answers 201 too. Confirming a write still requires
re-reading current state (`ops/sca_live_state.py`); the status only tells you the
request was well-formed and reached the service.

Payload shape trap: the list key is **`packageVulnerabilitiesProfile`**, not
`packageVulnerabilities` — the plain name returns 400.

**SCA scans are immutable.** A scan's results are a snapshot: triage applied after
the scan does NOT rewrite it. The state only becomes the scan's `state` on the next
scan or recalculation. So the obvious read paths report scan-time data and look
stale:

| Read surface | Regular / configuration / Usage | Supply-chain |
|---|---|---|
| `GET /api/results` (`state`) | **scan-time — stale after triage** | scan-time |
| SCA export `RiskState` | **scan-time — stale** | scan-time |
| `GET /api/risks` (`state`) | current | **never reflects it** |
| GraphQL `vulnerabilitiesRisksByScanId` | `state` = scan-time, **`pendingState` = current** | not returned here |
| GraphQL `searchPackageSupplyChainRiskStateAndScoreActions` | — | **current (action history)** |

Live example after triaging one CVE:

```
CVE-2015-7501   state=ToVerify   pendingState=ProposedNotExploitable
```

**Consequence for anything that reads SCA:** `/api/results` alone is as-of-scan
and will not show triage performed since. The tool therefore never shows it raw —
`results show` enriches every SCA row through `ops/sca_live_state.py` before
filtering or display, so what it prints (and what `--state` filters on) is the
CURRENT state and can be quoted as such.

What is NOT enriched, and stays as-of-scan: SBOMs, scan reports, and the raw SCA
export. Those are generated by the platform from the frozen scan, so say so rather
than presenting their states as current.

**The rule for new code: never read `state` off a scan and call it current.** Route
it through `ops/sca_live_state.py`. This is exactly the mistake that produced two
wrong bug reports (see `spec/CLEANUP_NOTES.md`, 2026-08-01).

### The two live queries

```
POST sca/graphql/graphql
# current state for Regular / configuration / Usage risks (paginated; take/skip)
query ($take: Int!, $skip: Int!, $scanId: UUID!, $isExploitablePathEnabled: Boolean!) {
  vulnerabilitiesRisksByScanId (take: $take, skip: $skip, scanId: $scanId,
      isExploitablePathEnabled: $isExploitablePathEnabled) {
    totalCount, items { cve, state, pendingState, pendingChanges, isIgnored, type } } }

# current state for supply-chain risks (per risk)
query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, $packageName: String,
       $packageVersion: String, $packageManager: String, $supplyChainRiskId: String) {
  searchPackageSupplyChainRiskStateAndScoreActions (...) {
    actions { actionType, actionValue, previousActionValue, createdAt } } }
```

`ops/sca_live_state.py` wraps both and is the ONLY place that knows how to read
current SCA state. Everything else goes through it: `results show` (rows are
enriched before filtering or display), the realism engine's already-triaged
check, and write verification in both triage paths.

Two traps in these queries themselves:
- **Page size caps at 100** (`HC0051`). Asking for more returns a GraphQL error
  with `data: null`, which reads as "no results" if you only look at `data`.
- **A GraphQL error is HTTP 200.** `_graphql()` checks the `errors` array and
  returns None (= unknown) rather than an empty dict, so a failed query can never
  masquerade as "nothing is triaged".

**Two id forms, not interchangeable.** The SCA export carries a shortened id
(`Cx43050644-3add`); `GET /api/risks` carries the full UUID as the first `#-#`
segment of `groupId` (`43050644-3add-dd9e-31da-a122fda92fcd`). Writes accept
either; **the supply-chain GraphQL read requires the full UUID** — given the short
form it returns zero actions, indistinguishable from "never triaged".
`sca_live_state.risk_uuid_map(api, project_id)` resolves short → full via
`/api/risks`.

**Do not "handle" a malicious package by muting it.** Muting suppresses its
findings; the real remediation is removing or replacing the dependency. Package
state (`Monitored`/`Muted`/`Snooze`) is a separate axis from risk triage.

## Checkmarx Assist (AI) — `ai_assist.py` + `ops/findings.py`  (AST plane)

Two agentic services on their own gateway prefixes. **Everything below was
live-verified on 2026-07-31**; the bundled spec previously carried three
`/api/v1/ai-*` paths that do not exist on any tenant (404) — they are gone.

| Method | Path | Notes |
|---|---|---|
| POST | `ai-triage/triage` | initiate; 202 + `triageID` |
| GET | `ai-triage/v2/triage/{project_id}/{group_id}` | **live-only** (not in Stoplight); richer trace |
| GET | `ai-triage/triage/{project_id}/{group_id}` | documented V1 shape |
| POST | `ai-triage/triage/{project_id}/{group_id}/discard` | **live-only**; 204 |
| POST | `remediation/remediate` | initiate; 202 + `remediationJobId` |
| GET | `remediation/remediation-details/{scan_id}/{result_id}` | one result |
| GET | `remediation/remediation-details/{scan_id}?result_ids=…` | **live-only**; bulk |

Both services publish their own OpenAPI — `GET {base_url}/api/ai-triage/openapi.json`
and `.../api/remediation/openapi.json` (Swagger UI at `/docs`). That is the
tie-breaker for these two services, ahead of the copies in `spec/AI-Triage.yaml`
/ `spec/AI-Remediation.yaml`.

**The five gotchas, in the order they bite:**

1. **`alternateId`, never `id`.** On SAST they are the same string; on SCA `id`
   is the CVE (`CVE-2017-3589`) and `alternateId` is a base64 hash. Code written
   against `id` passes every SAST test and fails silently on SCA.
2. **URL-encode ids used as path segments** (`quote(v, safe="")`). Result ids are
   base64 with `/`, `+`, `=`; SCA group ids embed `#-#`. A raw `#` truncates the
   URL at a fragment.
3. **Initiate and retrieve are keyed differently — triage only.** POST by
   `resultID`; GET by `projectID` + `groupID`. **SCA** =
   `<similarityId>#-#<packageIdentifier>#-#<projectId>`. **SAST depends on the
   tenant's grouping mode**, and this one bites hard (it did, live, on
   2026-07-31):

   | Tenant mode (`scan.config.sast.advancedTriageMode`) | group id |
   |---|---|
   | `Similarity ID` | the result's `similarityId` |
   | `Attack Vector ID` | the **attack-vector id** — NOT on `GET /api/results` at all |

   Why it is a trap rather than a footnote: the POST succeeds either way and the
   AI genuinely triages the findings (states flip, `stateChangedBy: "ai"`), so
   the only symptom of a wrong group id is that every GET 404s — looking exactly
   like "analysis still running". **`GET /api/risks` does not save you**: its
   `groupId` stays the similarityId in BOTH modes, so it confirms the wrong
   answer.

   Resolve the vector id AND the mode in one call — `POST sast-results/similar-results`
   with `{"scanId": ..., "resultsHash": [hash, ...]}` returns `groupingMode` plus a
   `similarResults[]` entry per hash whose **`id` is the attack-vector id**. The
   request key is `resultsHash` (plural-s, singular-Hash); `resultHash` 400s. For
   SAST the result hash is `data.resultHash`, which equals `alternateId`. This is
   what `ops/findings._sast_group_mode_and_vectors` does.

   Remediation has no group concept — it reads back by scan id + result id, so
   it is unaffected by grouping mode entirely.
4. **`GET /api/risks?projectId=<uuid>`** exposes `groupId`, `scanId`, `riskName`,
   `severity`, `state` in one call — but **`risk.id` ≠ `alternateId` for SCA**
   (0/10 matched live), so risks cannot drive the initiate path. Also: it pages
   with **`limit`**, not `pageSize` — the service echoes any `pageSize` you send
   in `metaData` while still serving 20 rows, silently truncating the list. The
   query param is camelCase `projectId`; `project-id` returns 400/4022.
5. **402 and 403 are the codes you will actually hit.** 402 = tenant AI
   consumption credits exhausted (per finding analyzed), 403 = Checkmarx Assist
   not enabled for the tenant. Neither is a malformed request; surface them as
   themselves rather than as generic failures.

Request bodies differ from the published docs — the live services are *more*
permissive: `TriageRequest` requires only `scanID` (omitting `buckets` triages
every SAST+SCA result in the scan — expensive), `TriageBucket` requires only
`scannerType` (empty `resultIDs` = all for that scanner), and `RemediateRequest`
accepts an optional `projectID`. Remediation still requires `buckets` with at
least one `resultID`; there is no whole-scan shortcut there.

Conversely the Stoplight YAMLs are *richer* on responses: the live spec types
`data` and `autoPr` as free-form objects, while `spec/AI-Remediation.yaml` fully
documents `data.analysis.what/why/how`, `data.file_changes[].diff`,
`data.test_creation`, and `autoPr.status/url/error_msg/file_url`. Use both.

### Credits — what an Assist action costs, and what's left

| Method | Path | Notes |
|---|---|---|
| GET | `credits/info` | `{available, total, used, actionsAvailable, actionsPerformed, enforcement:{state, consumptionPct, warningThresholdPct, cutoffThresholdPct}}` |
| GET | `credits/consumption?page=N` | per-user `creditsUsed` + `actionsPerformed.actions[{actionType, transactionCount}]` |

**Both are undocumented** — absent from the Stoplight export *and* from the
`/spec/v1` catalog; found by probing the gateway (`/api/credits/*` answers 404
from the service while an unknown prefix answers nginx 400, which is how the
service was located at all). No `openapi.json` is served here, so the field
list above is from live responses.

**Measured live (2026-07-31): billing is PER FINDING.** A 4-finding SAST triage
moved `available` 360 -> 356. Also: the charge hits `available` immediately as a
reservation, while `used` and `actionsPerformed` settle later (both still read
their old values a minute after the call) — so measure spend with `available`,
never by diffing `used`.

**Per-action cost is derived, not published.** Live on 2026-07-31: 424 `triage`
+ 72 `remediation` transactions against 640 credits used, and
`creditsUsed == 1*triage + 3*remediation` held for all 38 users individually —
hence `CREDIT_COST = {"triage": 1, "remediation": 3}` in `ai_assist.py`. Two
caveats to carry:

- `info.actionsAvailable` disagrees with that model (it equalled `available/5`,
  implying a blended ~5 credits/action). Compute from the action type instead,
  and treat `actionsAvailable` as the platform's own rough estimate.
- **Unresolved: is a "transaction" one FINDING or one REQUEST?** One POST
  carries many `resultIDs`. The tool therefore prints an upper bound
  (findings x unit cost) and names the lower bound (one request), and
  `_report_spend` re-reads `used` after a live call — the first real run
  settles it. Don't state a single number as fact until it does.

`percentOfTotal` in `consumption` is a share of credits *used*, not of the
entitlement, so the pool cannot be inferred from it — read `credits/info`.

Supported engines are **SAST and SCA only** — `ops/findings.AI_ENGINES` enforces
this so other engines' findings are never offered to these endpoints.

## Teardown — `purge.py`

Delete order: projects → applications → groups (→ users). Paginate, `DELETE` each
with retry. Irreversible: always dry-run, count, confirm.

**Scoped by default (v3+):** only resources this tool created are deleted —
projects with the tool `origin` or the `cxone-multitool` tag, applications with
the tag, groups/users with the Keycloak attribute (everything the tool creates
is stamped). `--all` = the whole tenant (needed for pre-3.0 tenants, whose
resources are unstamped). In both modes the users behind the primary API key
AND every registered secondary identity are never deleted (JWT `sub` match).

---

## Blueprint export — `export_blueprint.py`  (read-only)

The inverse of `provision`: reads the whole tenant and writes blueprint YAML in
the exact schema `provision --blueprint` consumes. No new endpoints — it reuses
the reads above (`GET groups/users` + per-user groups/role-mappings,
`GET applications`, `GET projects`, `GET configuration/project`). Lossy parts
are stamped as header comments, never silent: user passwords (not retrievable —
`password: CHANGE-ME`), non-GitHub repos (exported as manual projects), and
per-project scan-config outliers (schema holds ONE default; the modal
preset/incremental combo wins, outliers listed for `scanconfig set`). SCM
entries are reconstructed from the project's `repoUrl` + `mainBranch`.

---

## Multi-identity — `cxone/identity_pool.py` + `identities.py`

No new tenant endpoints — attribution is purely which API key signs the
request. Secondary keys live in `cxone-identities.yaml` (sidecar next to the
env file; `CXONE_IDENTITIES_FILE` overrides; inside a container it arrives as
`CXONE_IDENTITIES_JSON`). Each key's JWT is validated at load AND at
registration: decodable, same tenant as primary (foreign keys refused), one
persona per `sub`. Selection: explicit (`--as name`), seeded `random`/`auto` (affinity) over all
identities, or `random-secondary`/`auto-secondary` to exclude the primary key
(errors when no secondaries exist); the agent's scheduled counterpart is
`identities.include_primary` in activity.yaml. Secondary calls
that return 401/403 replay once on the primary client with a warning
(FallbackClient). The `identities` verb: `list` / `test` (read-only),
`add` / `remove` / `import` (write the sidecar, 0600, never inside the skill dir).

**Project resolution and zero-visibility identities.** Every project-name
resolver (`ops/scans.py`, `ops/scan_status.py`, `ops/triage/
triage_operation.py`, `results.py`) routes its "name didn't match" warning
through `ops/project_resolve.warn_unresolved_projects`. Live-observed on
cnf26 (2026-07): two secondary identities' JWTs decoded fine with the
expected `roles_ast`, yet `GET /api/projects` returned `{"totalCount": 0,
"projects": null}` for both — an authorization/visibility problem on the
account, resolved server-side without any tool-side action, but for ~21h it
produced a per-name `Project not found: 'X'` warning on every scheduled
agent event, which reads exactly like a naming/config error and sent
troubleshooting the wrong direction. The helper now distinguishes: if the
fetched project list is non-empty and specific names just don't match it,
same per-name message as before; if the list came back **entirely empty**,
one clear message pointing at authorization instead (`0 projects visible to
this identity/token at all...`), because a token can be validly-scoped and
still see zero projects if something changed access server-side — a very
different fix than a typo'd name. Diagnose with `project list --as
<identity>` (or plain `project list` for primary) before assuming any
requested name is wrong.

---

## Planned features (NOT YET BUILT) — exact endpoints live in the spec

These capabilities aren't implemented yet. To avoid maintaining the same paths in
three places (and re-drifting), the per-endpoint detail is **not** duplicated here.
Use these two sources instead:

- **`references/planned-features.md`** — for each feature: demo value, CLI design,
  module skeleton, payload shapes, and implementation gotchas.
- **`spec/cxone_openapi.json`** — the authoritative paths, parameters, and
  request/response schemas. Verify with `python validate_spec.py`.

Quick path index (authoritative paths in the spec; confirm verbs/bodies there):

| Feature | Module | Base path(s) in spec |
|---|---|---|
| Reports (PDF/JSON/CSV) — **BUILT** (`reports.py`) | `report` | `POST /api/reports` → poll `GET /api/reports/{id}` (status requested→started→completed) → download via the returned `url`. Live gotchas: `reportName:"improved-scan-report"`; valid `sections` are `scan-information,results-overview,scan-results,resolved-results,categories,vulnerability-details`; `scanners` must be capitalized `[SAST,SCA,KICS,Microengines,Containers]` (no apisec); PDF rendering can take minutes. |
| SBOM — **BUILT** (`reports.py`) | `report` | reuse SCA export: `POST /api/sca/export/requests` (`fileFormat: CycloneDxJson|CycloneDxXml|SpdxJson`) |
| Results querying — **BUILT** (`results.py`) | `results` | `GET /api/results` (page-indexed; use `ApiClient.fetch_results`); app rollup via `GET /api/applications` projectIds/tag rules |
| Role assignment — **BUILT** (`iam.py`) | `iam` | ast-app **client** roles (personas live here, not realm): `GET /clients?clientId=ast-app` → `GET /clients/{uuid}/roles` → `POST /users/{id}/role-mappings/clients/{uuid}`; realm roles as fallback (`/roles`, `/users/{id}/role-mappings/realm`). IAM plane. |
| Policy management | `policies` | `/api/policy_management_service_uri/policies/v2`, `…/policy_violations`, `…/evaluation`, `…/policies/projects/{policyId}` |
| Audit trail | `audit` | `/api/audit`, `/api/audit-events` |
| Feedback apps | `feedback` | `/api/feedback-app/v2/apps`, `/api/feedback-app/v2/profiles` |
| SCM variants (GitLab/ADO/Bitbucket) | `onboard` (extend) | `POST /api/repos-manager/scm-projects` (same as GitHub; only `scm.type` + identity differ) |
| DAST triage | `dast_handler` | `/api/dast/mfe-results/results/{scanId}`, `POST /api/dast/mfe-results/changelog` |
| Custom states | `triage` (extend) | `/api/custom-states`, `/api/custom-states/{id}`, `/api/lists/states` |
| BYOR / SARIF import | `byor` | `POST /api/uploads` → PUT file → `POST /api/byor/imports` |

Note: the OpenAPI export captured only a subset of methods on some service paths
(e.g. it lists `GET` on the feedback/policy v2 paths while create is `POST` to the
same path). `validate_spec.py` flags these as `METHOD?` — expected, not an error.

---

## Lists / lookups useful when building payloads

`GET configuration/tenant`, `GET presets` (or SAST preset-manager), `GET queries`,
`GET <results lists>/states|statuses|severities`, `GET applications/{id}/project-rules`.
See `api-index.md` for the full catalog.

