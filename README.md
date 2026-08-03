# CxOne_Multi-Tool

Source of truth for the **`checkmarx-one-multi-tool` Claude Skill** — end-to-end
management of Checkmarx One (CxOne) tenants for Solution Engineers building and
maintaining realistic demo / POV environments. You describe what you want in
plain language; the skill runs deterministic, dry-run-safe Python against your
tenant.

> **What can it actually do?** Users, groups, roles, applications, repo
> onboarding, scan config, scans, three distinct kinds of triage, full blueprint
> provisioning and export, teardown, and an agent that generates realistic
> activity over real time.
> **→ [Full tool documentation](.claude/skills/checkmarx-one-multi-tool/README.md)**

## Quick start (git deploy — recommended)

Claude Code reads skills from a **live directory**, so a clone *is* an install.
No packaging, no upload: `git pull` is how you update.

```bash
git clone https://github.com/CxRW-Tools/CxOne_Multi-Tool.git
cd CxOne_Multi-Tool
pip install -r .claude/skills/checkmarx-one-multi-tool/requirements.txt
```

Then pick how you want it available:

**A. Project skill — simplest.** Open this repo as your working directory in
Claude Code. `.claude/skills/checkmarx-one-multi-tool/` is auto-discovered. Done.

**B. Personal skill — available in every project.** Link (don't copy) your
personal skills folder at the clone, so `git pull` keeps it current:

```bash
# macOS / Linux
ln -s "$(pwd)/.claude/skills/checkmarx-one-multi-tool" \
      ~/.claude/skills/checkmarx-one-multi-tool
```

```
:: Windows (junction — no admin rights needed)
mklink /J %USERPROFILE%\.claude\skills\checkmarx-one-multi-tool C:\path\to\CxOne_Multi-Tool\.claude\skills\checkmarx-one-multi-tool
```

**Then connect a tenant.** Start a Claude Code session and say:

> Run the Checkmarx One Multi-Tool

It prints a banner, reports that no tenant is configured, and asks for your CxOne
API key (Settings → Identity and Access Management → API Keys). The key is a JWT,
so the tool derives your region and tenant name from it and confirms with you
before saving anything. Python 3.10+ required.

From there, just ask:

> Stand up a demo tenant for Acme: two groups, a few users, onboard WebGoat and
> juice-shop, scan them, and triage so it looks realistic.

Every command names the tenant it's acting on, previews changes with a dry-run,
and asks before anything destructive.

## Staying up to date

```bash
git pull      # you now have the latest
```

The skill also checks itself. At session start it compares your checkout against
`origin`'s default branch — merged work only, since an unmerged branch is a
proposal, not a release — and speaks up only if you're behind:

```bash
python run.py selfcheck          # status
python run.py selfcheck --sync   # fast-forward to the published version
```

## Contributing changes back

The skill is built to be extended in-session: ask Claude for something it doesn't
do yet and it will implement it. To publish that work:

```bash
python .claude/skills/checkmarx-one-multi-tool/scripts/publish_skill.py "what changed"
```

That runs the whole path — branch → commit → push → PR → squash-merge → tag — and
the `release-skill` Action packages the `.skill` and attaches it to a GitHub
Release on tag push. **Working from this repo, you never build or zip a `.skill`
yourself.** Preflight refuses to publish from a checkout that is behind `main`,
or one whose code/docs reference API endpoints missing from the bundled OpenAPI
spec.

Bump `.claude/skills/checkmarx-one-multi-tool/VERSION` (and the matching
`metadata.version` in `SKILL.md`) with any change — semver: patch = fix, minor =
new capability, major = breaking.

## Other install surfaces

Claude.ai, the Desktop app, and API skill upload need a packaged `.skill` rather
than a live directory. Grab one from
[Releases](https://github.com/CxRW-Tools/CxOne_Multi-Tool/releases/latest), or
build it locally:

```bash
python scripts/package_skill.py checkmarx-one-multi-tool   # -> dist/ (gitignored)
```

Those surfaces can design blueprints and tune configs, but **cannot reach your
tenant** — run from Claude Code or Cowork for anything that touches CxOne.

## Layout

```
.claude/skills/checkmarx-one-multi-tool/   the skill itself — see its README for detail
  SKILL.md                                 how Claude drives the tool (protocol, safety)
  scripts/                                 the CLI engine (run.py / multitool.py)
  references/                              API, CLI, MCP and extension docs
  spec/cxone_openapi.json                  bundled OpenAPI, validated on publish
scripts/package_skill.py                   builds a .skill zip for upload surfaces
.github/workflows/release-skill.yml        packages + publishes on tag push
```

## Credentials — read this

Never commit `.env`, `cxone.env`, `cxone-identities.yaml`, or any file holding
real API keys. `.gitignore` blocks the common names and the publish script
independently refuses to stage anything that looks like a secret — but check
`git status` before committing anyway.

Credentials belong in **your project directory, not the skill folder**. The tool
refuses to read or write them inside its own install path: that location is
shared between sessions, and a stale file there is exactly how you end up acting
on the wrong tenant. Point `CXONE_ENV_FILE` at your project's `cxone.env`.

One tenant per session — switching tenants means a new session, not a reconfigure.
