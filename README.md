# Checkmarx One Multi-Tool

End-to-end management of Checkmarx One (CxOne) tenants for Solution Engineers
building and maintaining realistic demo / POV environments. You describe what you
want in plain language; the tool runs deterministic, dry-run-safe Python against
your tenant.

This repo is the source of truth for the `checkmarx-one-multi-tool` Claude Skill.

> **What can it actually do?** Users, groups, roles, applications, repo
> onboarding, scan config, scans, three distinct kinds of triage, full blueprint
> provisioning and export, teardown, and an agent that generates realistic
> activity over real time.
> **→ [Full tool documentation](.claude/skills/checkmarx-one-multi-tool/README.md)**

## Quick start — clone the repo (recommended)

**Claude Code works directly against the cloned source. There is nothing to
export and nothing to import.** No `.skill` file is built, and the skill never
has to be installed into Claude — point Claude Code at the clone and it reads
`SKILL.md` and the scripts as they sit on disk.

```bash
git clone https://github.com/CxRW-Tools/CxOne_Multi-Tool.git
cd CxOne_Multi-Tool
pip install -r .claude/skills/checkmarx-one-multi-tool/requirements.txt
```

Open that directory in Claude Code and say:

> Run the Checkmarx One Multi-Tool

It prints a banner, reports that no tenant is configured, and asks for your CxOne
API key (Settings → Identity and Access Management → API Keys). The key is a JWT,
so the tool derives your region and tenant name from it and confirms with you
before saving anything. Python 3.10+ required.

Then just ask:

> Stand up a demo tenant for Acme: two groups, a few users, onboard WebGoat and
> juice-shop, scan them, and triage so it looks realistic.

Every command names the tenant it's acting on, previews changes with a dry-run,
and asks before anything destructive.

**Updating is `git pull`.** Because the clone *is* what runs, there is no
re-export or re-import step — the next session picks up the new version.

<details>
<summary><b>Optional: use it from any directory, not just this repo</b></summary>

Link your personal skills folder at the clone (link, don't copy — a copy stops
tracking git and you lose `git pull` updates):

```bash
# macOS / Linux
ln -s "$(pwd)/.claude/skills/checkmarx-one-multi-tool" \
      ~/.claude/skills/checkmarx-one-multi-tool
```

```
:: Windows (junction — no admin rights needed)
mklink /J %USERPROFILE%\.claude\skills\checkmarx-one-multi-tool C:\path\to\CxOne_Multi-Tool\.claude\skills\checkmarx-one-multi-tool
```

Still the same clone and still git-updated — this only changes *where* it's
visible from.
</details>

## Alternative: install a released `.skill`

Use this **only when cloning isn't an option** — no git access, or a surface that
requires an upload rather than a directory (Claude.ai, the Desktop app, API skill
upload). Download the latest `.skill` from
[Releases](https://github.com/CxRW-Tools/CxOne_Multi-Tool/releases/latest) and
import it into Claude.

It works, but it is the weaker path:

- **No `git pull`.** Every update means downloading a new `.skill` and importing
  it again.
- **Reinstalling doesn't affect a running session** — start a fresh one, and
  check with `python run.py version` that the build you expect is loaded.
- **Web and app surfaces cannot reach your tenant.** They can design blueprints
  and tune configs, but anything that touches CxOne has to run from Claude Code
  or Cowork on a machine with network access to it.

To build one locally instead of downloading:

```bash
python scripts/package_skill.py checkmarx-one-multi-tool   # -> dist/ (gitignored)
```

## Staying up to date

Running from a clone, that's the whole story:

```bash
git pull      # you now have the latest
```

(If you installed a released `.skill` instead, updating means downloading and
importing a new one — see the alternative above.)

The skill also checks itself. Every command compares your checkout against
`origin`'s default branch — merged work only, since an unmerged branch is a
proposal, not a release — and speaks up only if you're behind. The per-command
cost is one cached file read; the actual git fetch happens on a background
thread at most once an hour, so nothing ever waits on it:

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
