# Checkmarx One CLI (`cx`) Reference

The `cx` CLI is a maintained alternative for scan/project/result/triage work. The
Multi-Tool can shell out to it when it's installed and configured, rather than
calling the API directly — useful for scans inside pipelines and for quick reads.

Docs: https://docs.checkmarx.com/en/34965-68625-checkmarx-one-cli-commands.html
Install: https://docs.checkmarx.com/en/34965-68622-checkmarx-one-cli-installation.html

## Auth / config

```bash
cx configure                       # interactive
# or env: CX_APIKEY, CX_BASE_URI, CX_BASE_AUTH_URI, CX_TENANT
cx configure set --prop-name cx_apikey --prop-value <key>
```

## Commands (what the CLI covers)

| Command | Subcommands | Use |
|---|---|---|
| `auth` | validate | check credentials / create OAuth creds |
| `configure` | set / show | manage profile + global props |
| `project` | create, list, show, delete, tags | project CRUD (`--groups`, `--tags`) |
| `scan` | create, list, show, cancel, ... | run/manage scans |
| `results` | show, ... | retrieve results (json/sarif/sonar/etc.) |
| `triage` | show, update, ... | get/update a result's state/severity |
| `utils` | import (BYOR sarif), remediation (kics), pr decoration, contributors | misc |
| `version` | | version |

Common one-liners:
```bash
cx scan create --project-name "my_project" --branch main -s <repo-url-or-path>
cx scan list --filter "project-id=<id>,statuses=Completed" --format json
cx results show --scan-id <id> --report-format json
cx triage update --project-id <id> --similarity-id <sid> --scan-type sast \
    --state not_exploitable --severity low --comment "demo triage"
cx project create --project-name "demo" --groups "Developers" --tags "app:banking"
```

## What the CLI does NOT cover (use the Multi-Tool API modules)

User provisioning, group/role management, application creation, SCM repo
onboarding (bulk import), preset/policy creation, tenant teardown. These are the
admin-plane gaps the Multi-Tool fills directly via API.

## When to prefer CLI vs API

- Prefer `cx scan`/`cx results` in CI/CD or when the user already has it set up.
- Prefer the Multi-Tool's `ops/` scan+triage when you want the weighted-roll
  realism logic, or to stay in one Python process with the admin modules.
- Either way, shelling out: `subprocess.run(["cx", "scan", "create", ...], check=True)`.
