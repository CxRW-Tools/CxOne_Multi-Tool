# CxOne_Multi-Tool

Source of truth for the `checkmarx-one-multi-tool` Claude Skill: a tenant
management tool for Checkmarx One (CxOne) demo/POV environments. This repo
is what you edit and version-control; individual machines link to it or
install a packaged build from it depending on how the skill is being used.

## Layout

```
.claude/skills/checkmarx-one-multi-tool/   the skill itself (SKILL.md, scripts, blueprints, etc.)
scripts/package_skill.py                    builds a .skill zip for upload-based surfaces
.github/workflows/release-skill.yml         packages + publishes to GitHub Releases on tag push
```

## Using it in Claude Code

Claude Code reads skills from a live directory — no packaging needed.

**Project skill (simplest):** open this repo as your working directory in
Claude Code. `.claude/skills/checkmarx-one-multi-tool/` is auto-discovered.

**Personal skill (available in any project/session):** link the personal
skills folder to your clone of this repo instead of copying files.

- macOS/Linux:
  ```
  ln -s /path/to/CxOne_Multi-Tool/.claude/skills/checkmarx-one-multi-tool \
        ~/.claude/skills/checkmarx-one-multi-tool
  ```
- Windows (junction, no admin rights required):
  ```
  mklink /J %USERPROFILE%\.claude\skills\checkmarx-one-multi-tool C:\path\to\CxOne_Multi-Tool\.claude\skills\checkmarx-one-multi-tool
  ```

Edit, `git commit`, `git push` — every linked machine picks up the change on
next pull. Never edit the files at the symlink/junction destination directly
in a way that bypasses git; always work through the repo clone.

## Packaging a `.skill` zip

Surfaces that require an upload (Claude.ai, Desktop app, API skill upload)
need a packaged `.skill` file rather than a live directory. Build one
locally with:

```
python scripts/package_skill.py checkmarx-one-multi-tool
```

This reads `VERSION` inside the skill directory and writes
`dist/checkmarx-one-multi-tool-v<version>.skill`. `dist/` is gitignored —
it's a build artifact, not source.

## Cutting a release

1. Bump `.claude/skills/checkmarx-one-multi-tool/VERSION`.
2. Commit and push.
3. Tag and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The `release-skill` GitHub Action packages the skill and attaches the
`.skill` zip to a new GitHub Release automatically.

## Credentials

Never commit `.env`, `cxone.env`, `cxone-identities.yaml`, or any file with
real API keys/tokens — `.gitignore` blocks the common cases, but always
double-check `git status` before committing.
