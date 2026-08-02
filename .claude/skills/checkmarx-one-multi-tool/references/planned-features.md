# Planned Features — Implementation Roadmap

Derived from a review of the full Checkmarx One user guide (May 2026). Each section
maps a demo-valuable capability to the API and the implementation pattern.

*Spec cross-check: 2026-07-21 — the `feedback-app` and `policy_management_service_uri`
paths referenced below (flagged `METHOD?` by `validate_spec.py`, since the bundled
spec's export only captured GET on them) do NOT appear by name in this tenant's live
`{base_url}/spec/v1` catalog of ~90 services (see `api-index.md` "Where to look").
Either they're under a service name this search didn't match, gated off on this
tenant/region, or renamed — confirm on Stoplight and/or by browsing `{base_url}/spec/v1`
directly before implementing either feature, don't assume the bundled spec's GET-only
capture is complete.*

## Completed (this iteration — no longer on the roadmap)

These shipped and are validated against a live tenant; see SKILL.md capabilities:

- **Results querying** (`results` verb) — summary by engine×severity per project,
  per-application rollup, and finding-level drill-down.
- **Reports** (`report` verb) — PDF/JSON/CSV scan reports (async poll+download) and
  CycloneDX/SPDX SBOMs (reusing the SCA export flow). *(was roadmap #1)*
- **Role assignment** (`iam assign-role` / `list-roles`, `create-user --roles`,
  blueprint `roles:`) — assigns ast-app **client** roles (ast-viewer, ast-scanner,
  …) with realm-role fallback. *(was roadmap #5)*
- **Scan status / history** (`scan status|history`, on-demand) + a duplicate-scan
  guard on the trigger path (`--force` to override).
- **One-shot & batch onboarding** (`project create`, `project onboard`) and
  **`quickstart`** (blueprint → scan → triage in one command).
- **Results pagination fix** — `/api/results` `offset` is a *page index*, not a
  record offset; `ApiClient.paginate` now pages it correctly (`fetch_results`).

Shipped 2026-07-31 → 08-01 (not previously on this roadmap):

- **Checkmarx Assist** (`ai-assist` verb) — AI Triage Assist and AI Remediation
  Assist: initiate, poll, retrieve details, discard, and report credit balance and
  per-action cost. Endpoints were undocumented; see `spec/CLEANUP_NOTES.md`.
- **`triage-real`** — real triage decisions made by this coding assistant against
  the actual scanned source (fetched via `ops/source_fetch.py`, falling back to a
  repo clone, then metadata). Writes nothing when the evidence is insufficient.
- **`triage-simulate`** — the realism engine, renamed from `triage` so the three
  triage paths are unambiguous. `triage` still works with a deprecation warning.
- **Current SCA state** (`ops/sca_live_state.py`) — SCA scans are immutable;
  `results show`, both triage paths, and the already-triaged check now read
  `pendingState` rather than the frozen scan state.
- **Audit trail** (`audit.py`, `audit` verb) — search/export tenant activity via
  `GET /api/audit-events` (replaces the deprecated `GET /api/audit`), with
  `--type`/`--resource`/`--user`/`--search` filters, `--human-readable` UUID
  resolution via IAM admin lookups, and `--csv` export. Coverage is still
  growing platform-side (some engines, e.g. IaC, only emit events for a subset
  of actions) — a thin/empty result is a coverage gap, not a bug.
  *(was roadmap #3)*

## Priority matrix (remaining)

| # | Feature | Module | Priority | Effort |
|---|---|---|---|---|
| 1 | Policy management + incidents | `policy` (new) | HIGH | Medium |
| 2 | GitLab / Azure DevOps / Bitbucket onboarding | `project` (extend) | HIGH | Low-Medium |
| 3 | Feedback apps (Slack / Jira / Teams / etc.) | `feedback` (new) | MEDIUM | Medium-High |
| 4 | DAST triage | `ops/triage/` (extend) | MED-LOW | Low |
| 5 | Custom triage states | `ops/triage/` (extend) | MED-LOW | Low |
| 6 | Pre-commit hook setup | `hooks` (new) | LOW | Low |
| 7 | Bring Your Own Results (BYOR / SARIF import) | `byor` (new) | LOW | Low |

All endpoint schemas are in `cxone-api.md`. Follow the module pattern in `extending.md`.

---

## 1 — Policy Management (`policy` module, HIGH)

### Demo value
The "break the build" moment is a top SE demo closer. Creating a policy that
blocks a PR with critical SAST findings — then showing the incident in the
Violations tab — demonstrates security gates in action.

### CLI commands to add
```bash
# Create a By-Scanner policy
policy create --name "No Critical SAST" \
    --scanner sast \
    --severity Critical,High \
    --break-build \
    [--description "Block merges with new critical/high SAST findings"]

# Create an All-Scanners (net-new PR) policy
policy create --name "Block Net-New" \
    --all-scanners \
    --severity Critical \
    --break-build

# Associate with projects
policy assign --name "No Critical SAST" --projects WebGoat,"WebGoat.NET"
policy assign --name "No Critical SAST" --default   # sets as tenant default

policy list
policy incidents [--policy <name>] [--project <name>]
policy delete --name <name>
```

### Module to create: `scripts/policies.py`
```python
class PolicyManager:
    def create(self, name, *, scanner=None, all_scanners=False,
               severities=None, break_build=False, description="", tags=None):
        # POST /api/policy_management_service_uri/policies/v2
        # (list: GET /api/policy_management_service_uri/policies/v2)
        # (OpenAPI export lists GET on policies/v2; create is POST to the same path)
        # Rule type: "ALL_SCANNERS" or "BY_SCANNER" (scanner name upper-cased)

    def assign_projects(self, policy_id, project_ids, *, default=False):
        # PUT /api/policy_management_service_uri/policies/projects/{policyId} — set projects
        # (DELETE same path removes projects)

    def list_policies(self):
        return self.api.paginate("policies", results_key="policies")

    def incidents(self, policy_id=None, project_id=None):
        # GET /api/policy_management_service_uri/policy_violations  (detail)
        # summary: GET /api/policy_management_service_uri/evaluation
        return self.api.paginate("policy_management_service_uri/policy_violations", results_key="violations",
                                 params={"policy-id": policy_id, "project-id": project_id})

    def delete(self, policy_id):
        return self.api.delete(f"policies/{policy_id}")
```

### Policy rule shapes (from Stoplight)
```json
// By-Scanner rule
{
  "name": "No Critical SAST",
  "description": "",
  "rules": [{
    "type": "BY_SCANNER",
    "scanner": "SAST",
    "conditions": [{
      "filter": "SEVERITY",
      "operator": "IN",
      "value": ["Critical", "High"]
    }],
    "breakBuild": true
  }],
  "isDefault": false,
  "projectIds": ["<uuid>"]
}

// All-Scanners rule (net-new on PR only)
{
  "name": "Block Net-New Critical",
  "rules": [{
    "type": "ALL_SCANNERS",
    "netNewVulnerabilities": ["Critical"],
    "breakBuild": true
  }],
  "isDefault": false
}
```

### Key implementation notes
- Supported scanners for By-Scanner rules: `SAST`, `SCA`, `IaC Security`,
  `Container Security`.
- A policy with multiple By-Scanner rules is violated if **any** rule fires (OR).
- Within a By-Scanner rule, conditions in the same group all must match (AND).
- `isDefault: true` applies the policy to all projects (only one default at a time).
- Violations appear under `GET /api/policy_management_service_uri/policy_violations`; each has a
  `policyId`, `projectId`, `scanId`, and the conditions triggered.
- Permissions: `create-policy-management`, `view-policy-management`.

### Blueprint support
Add `policies:` list to the blueprint schema:
```yaml
policies:
  - name: "No Critical SAST"
    scanner: sast
    severities: [Critical, High]
    break_build: true
    projects: ["WebGoat", "WebGoat.NET"]
```
`provision.apply_blueprint` creates each policy and assigns it after projects exist.

---

## 2 — GitLab / Azure DevOps / Bitbucket Onboarding (extend `project`, HIGH)

### Demo value
Most enterprise customers aren't on GitHub. Failing to show ADO or GitLab
onboarding in a POV is a competitive gap. The API shape is identical to GitHub —
only `scm.type` and identity fields differ.

### CLI commands to add
```bash
project gitlab --group <gitlab-group> --repos <repo1,repo2> \
    --branch main --groups "Developers" --tag app:banking
project ado --org <azure-org> --project <ado-project> \
    --repos <repo1,repo2> --branch main --groups "Developers"
project bitbucket --workspace <workspace> --repos <repo1,repo2> \
    --branch main --groups "Developers"
```

### Implementation in `scripts/onboard.py`
Mirror `onboard_github` for each provider. The key diffs:

**GitLab**
```python
scm = {"type": "gitlab", "token": cfg.gitlab_token}
org = {"orgIdentity": group_path}        # e.g. "myorg/mygroup"
# repo URL: "https://gitlab.com/<group>/<repo>"
```

**Azure DevOps**
```python
scm = {"type": "azure", "token": cfg.ado_token}
org = {"orgIdentity": f"{ado_org}/{ado_project}"}  # org/project combined
# repo URL: "https://dev.azure.com/<org>/<project>/_git/<repo>"
```

**Bitbucket Cloud**
```python
scm = {"type": "bitbucket", "token": cfg.bitbucket_token}
org = {"orgIdentity": workspace}
# repo URL: "https://bitbucket.org/<workspace>/<repo>"
```

### Token env vars to add in `envmgr.py`
- `CXONE_GITLAB_TOKEN` (already exists as `env set-token gitlab <TOKEN>`)
- `CXONE_ADO_TOKEN` (`env set-token ado <TOKEN>`)
- `CXONE_BITBUCKET_TOKEN` (`env set-token bitbucket <TOKEN>`)

### Key implementation notes
- The `POST repos-manager/scm-projects` endpoint and its poll/result shape are
  identical for all SCM providers. Only the `scm` and `org` blocks differ.
- ADO has an extra layer: `orgIdentity` is `"<azure-org>/<ado-project>"` to
  distinguish repos within different ADO projects under the same org.
- For Bitbucket Server (self-hosted), `scm.type = "bitbucket_server"` and the
  URL scheme is `https://<host>/scm/<project>/<repo>.git`.
- Verify the exact `orgIdentity` format by inspecting a manual import in the
  tenant's repos-manager settings, or check Stoplight under `repos-manager`.
- Add each provider to `SUPPORTED_SCM` constant and the `create_projects` dispatch.
- Add `CXONE_<PROVIDER>_TOKEN` lookup in `CxConfig` and `env set-token`.

---

## 3 — Feedback App Integrations (`feedback` module, MEDIUM)

### Demo value
Closes the loop: "what happens after a vulnerability is found?" A Jira ticket
opens, a Slack alert fires. This is the workflow story that enterprise customers
need to see — security findings flowing into their existing tooling.

### CLI commands to add
```bash
# Slack (simplest — just a webhook URL, no OAuth)
feedback create-slack --name "Security Alerts" \
    --webhook-url https://hooks.slack.com/... \
    --channel "#appsec-alerts" \
    --scanners sast,sca \
    --severities Critical,High \
    --projects WebGoat,"WebGoat.NET"

# Jira
feedback create-jira --name "AppSec Jira" \
    --url https://myco.atlassian.net \
    --username user@myco.com \
    --token <jira-api-token> \
    --project-key SEC \
    --issue-type Bug \
    --severities Critical,High \
    --projects WebGoat

feedback list
feedback delete --name <name>
```

### Two-entity model
CxOne separates **Feedback Apps** (integration config + credentials) from
**Feedback Profiles** (groups apps + associates projects). Creating a usable
integration requires both:
1. `POST /api/feedback-app/v2/apps` → returns `appId`
2. `POST /api/feedback-app/v2/profiles` with `appId` and `projectIds`
(list endpoints: `GET /api/feedback-app/v2/apps`, `GET /api/feedback-app/v2/profiles`)
(NOTE: the OpenAPI export only lists GET on these v2 paths; create is POST to the
same path — confirm the POST body on Stoplight when implementing.)

### Module to create: `scripts/feedback.py`
```python
class FeedbackManager:
    def create_slack_app(self, name, *, webhook_url, channel,
                         scanners=None, severities=None):
        payload = {
            "name": name,
            "type": "Slack",
            "config": {
                "webhookUrl": webhook_url,
                "channel": channel,
            },
            "filters": {
                "scanners": scanners or ["SAST", "SCA", "KICS", "CONTAINER_SECURITY"],
                "severities": severities or ["Critical", "High"],
            }
        }
        return self.api.post("feedback-app/v2/apps", json_body=payload)

    def create_jira_app(self, name, *, jira_url, username, token,
                        project_key, issue_type="Bug", scanners=None,
                        severities=None):
        payload = {
            "name": name, "type": "Jira",
            "config": {
                "url": jira_url, "username": username, "token": token,
                "projectKey": project_key, "issueType": issue_type,
            },
            "filters": {
                "scanners": scanners or ["SAST", "SCA"],
                "severities": severities or ["Critical", "High"],
            }
        }
        return self.api.post("feedback-app/v2/apps", json_body=payload)

    def create_profile(self, name, app_ids, project_ids):
        # POST /api/feedback-app/v2/profiles
        payload = {
            "name": name,
            "feedbackApps": [{"id": a} for a in app_ids],
            "projects": [{"id": p} for p in project_ids],
        }
        return self.api.post("feedback-app/v2/profiles", json_body=payload)
```

### Key implementation notes
- **Never log or URL-embed Jira tokens or Slack webhook URLs** — treat as secrets.
- Slack webhooks are single-URL; Jira needs basic auth (username + API token).
- Maximum 2,000 tickets created per scanner per scan — excess results are skipped
  with priority given to higher severity.
- Supported alerting types: Slack, Microsoft Teams, Email.
- Supported bug tracking types: Jira, GitHub Issues, Azure Boards.
- For Microsoft Teams, `type = "MicrosoftTeams"` and config is `{webhookUrl}`.
- For email: `type = "Email"` and config is `{recipients: [<email>]}`.
- Permissions required: `create-feedbackapp`.
- For manually-created projects (not SCM-integrated), the project must have a
  primary branch set before Feedback Apps will trigger on it. The multi-tool's
  `scan` command already sets branch info via `set-repo`; ensure `primaryBranch`
  is populated on the project record.

---

## 4 — DAST Triage (extend `triage` module, MED-LOW)

### Demo value
DAST results already appear in tenants that have run DAST scans. The triage
module has no handler for them; a `DastHandler` closes that gap without needing
to build the complex DAST environment/scan setup.

### Implementation
Add `DastHandler` in `scripts/ops/triage/dast_handler.py`:

```python
_RESULTS_TYPE = "dast"

class DastHandler(BaseTriageHandler):
    ENGINE = "dast"

    def fetch_results(self, project_id, scan_id):
        # DAST results are a SEPARATE service, not /api/results:
        #   GET /api/dast/mfe-results/results/{scan_id}
        return self.api.get(f"dast/mfe-results/results/{scan_id}") or []

    def apply_triage(self, project_id, matched_results, summary):
        # DAST triage: POST /api/dast/mfe-results/changelog (state/severity update)
        # Results fetched from GET /api/dast/mfe-results/results/{scan_id}
        for result in matched_results:
            rule = result["_matched_rule"]
            predicate = {
                "resultId": result.get("id"),
                "state": dast_state_to_api(rule.get("state", "")),
                "severity": result.get("severity", ""),
                "note": rule.get("comment", ""),
            }
            if not self.dry_run:
                self.api.post("dast/mfe-results/changelog", json_body=predicate)
            summary.results_applied += 1
```

Wire into `triage_operation._ENGINE_MAP`:
```python
"dast": {"result_type": "dast", "status_detail_name": "apisec"}  # verify name
```

### Key implementation notes
- DAST states: `To Verify`, `Not Exploitable`, `Proposed Not Exploitable`,
  `Confirmed`, `Urgent` (same as other engines).
- The DAST Results API is a separate service; verify the exact predicate endpoint
  on Stoplight under "DAST Results Service".
- Permissions needed: `dast-update-result-states` or `dast-high-level-update-result-states`.
- DAST scan setup (environment/tunnel/CLI) is intentionally out of scope for the
  multi-tool; this handler only triages results from scans already in the tenant.

---

## 5 — Custom Triage States (extend `triage` module, MED-LOW)

### Demo value
Enterprise customers have process-specific states beyond the standard five
(To Verify / Confirmed / Urgent / Not Exploitable / Proposed Not Exploitable).
Custom states like "Ready to Fix" or "Accepted Risk" show that CxOne fits their
existing workflow rather than forcing a new one.

### CLI commands to add
```bash
triage create-state --name "Ready to Fix" --type INFO|LOW|MEDIUM|HIGH
triage list-states [--scanner sast|sca|iac|containers] [--show-deleted]
```

### Extension to `scripts/ops/` or `scripts/scanconfig.py`
```python
def create_custom_state(name, state_type="INFO"):
    # POST /api/custom-states
    return self.api.post("custom-states",
                         json_body={"name": name, "type": state_type})

def list_custom_states(scanner="sast", show_deleted=False):
    # GET /api/custom-states?type=<scanner>&show-deleted=<bool>  (all states: GET /api/lists/states)
    return self.api.get("custom-states",
                        params={"type": scanner, "show-deleted": show_deleted})
```

### Key implementation notes
- Custom states are currently only available on tenants with "New Access Management
  (Phase 1)" enabled. If `POST /api/custom-states` returns 404, the tenant
  doesn't have the feature — log a clear warning.
- The `cx triage get-states` CLI command also returns custom states alongside the
  five standard states; use it to verify after creation.
- Once created, a custom state can be used in `triage_rules.yaml` as any other
  state name. The SAST/IaC predicate endpoints accept custom state IDs.
- Supported engines: SAST, SCA, IaC Security, Container Security (not DAST/Secrets).

---

## 6 — Pre-Commit Hook Setup (`hooks` module, LOW)

### Demo value
The developer shift-left story: "here's how your engineers catch secrets before
they even push." A live demo of a commit being blocked by the pre-commit hook
is compelling and quick to run.

### CLI commands to add
```bash
hooks install [--path /path/to/repo]    # install the cx pre-commit hook
hooks uninstall [--path /path/to/repo]
hooks list                              # show where hooks are installed
```

### Implementation: thin wrapper around `cx` CLI
```python
import subprocess, shutil

class HooksManager:
    def install(self, repo_path="."):
        if not shutil.which("cx"):
            raise RuntimeError("cx CLI not found; install it first")
        subprocess.run(["cx", "hooks", "pre-commit", "install",
                        "--file", repo_path], check=True)

    def uninstall(self, repo_path="."):
        subprocess.run(["cx", "hooks", "pre-commit", "uninstall",
                        "--file", repo_path], check=True)
```

### Key implementation notes
- Requires the `cx` CLI to be installed and authenticated (it reads from its own
  config, not from our `.env`). Check `shutil.which("cx")` before attempting.
- The hook runs `cx scan create` on `git commit` — so the user needs a valid
  `cx` auth config. Point them to `cx configure` if not set.
- Global install (`--global` flag) installs for all repos under the user's home;
  local install (default) installs in `.git/hooks/` of the specified repo.
- This is intentionally a thin wrapper — the `cx` CLI owns hook management.

---

## 7 — Bring Your Own Results / SARIF Import (`byor` module, LOW)

### Demo value
POVs where the customer already has results from another tool (Veracode, Snyk,
Semgrep) and wants to consolidate them in CxOne. Uploading a SARIF file and
seeing results appear alongside native CxOne findings is the "consolidation hub"
story.

### CLI commands to add
```bash
byor import --project <name> --file scan-results.sarif \
    [--branch main] [--description "Imported from Snyk"]
byor list --project <name>   # show imported result sets
```

### Module to create: `scripts/byor.py`
```python
class BYORManager:
    def import_sarif(self, project_id, sarif_file_path, *,
                     branch="main", description=""):
        # Step 1: upload the SARIF file to get a presigned URL
        upload_url = self.api.post("uploads", json_body={})
        # Step 2: PUT the file to the presigned URL
        with open(sarif_file_path, "rb") as f:
            requests.put(upload_url["url"], data=f,
                         headers={"Content-Type": "application/json"})
        # Step 3: create an import job
        return self.api.post("byor/imports", json_body={
            "projectId": project_id,
            "uploadId": upload_url["uploadId"],
            "branch": branch,
            "description": description,
        })
```

### Key implementation notes
- Permission required: `import-findings-external-platforms`.
- SARIF format: version 2.1.0. The file must be valid SARIF — CxOne will reject
  malformed inputs.
- Imported results appear in the UI alongside native scan results under a distinct
  "External" source label.
- After import, results are triage-able through the normal SAST predicates API
  (they're stored as SAST-type results under the hood).
- The upload flow (presigned URL → PUT) is the same pattern as the existing
  `Uploads API` in `cxone-api.md` — see that section for the exact endpoint.
- For Snyk/Veracode, customers may need to export to SARIF first; each tool has
  its own SARIF export command.
