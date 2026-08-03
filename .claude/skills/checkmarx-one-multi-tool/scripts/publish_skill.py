#!/usr/bin/env python3
"""Publish this skill's own changes, when it runs from a git checkout.

**In a repo, this IS the publish.** Merging to the default branch and pushing a
``v<version>`` tag is the whole delivery path: the ``release-skill`` workflow
packages the ``.skill`` and attaches it to a GitHub Release. Nobody should be
zipping the folder by hand. The manual export in SKILL.md exists only for a
standalone copy with no repo behind it.

**Flow: branch -> commit -> push -> PR -> squash-merge -> tag.** The tag is cut
from the default branch *after* the merge, so ``v<version>`` always names a
commit that is actually published rather than one that only ever lived on a
feature branch. ``--no-merge`` stops after opening the PR when a change wants
eyes on it first; the tag then waits for the merge (re-run with ``--tag-only``
once it lands).

**Preflight is unthrottled on purpose.** Being behind the published branch is a
correctness problem when publishing, not a cadence one: committing from a stale
checkout is how a push gets rejected or two sessions pick the same version
number. So this always asks the network, regardless of selfcheck's TTL.

Every failure mode prints why and changes nothing. Never force-pushes.

Usage:
    python scripts/publish_skill.py "short summary of the change"
    python scripts/publish_skill.py "..." --no-merge     # open the PR, don't merge
    python scripts/publish_skill.py "..." --tag-only     # tag an already-merged version
"""
import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

# Defense-in-depth beyond .gitignore: filenames that should never be staged
# for this skill, no matter how they got there (a renamed secret, a scratch
# file dropped mid-session, an editor backup). Checked against the actually
# staged paths, not just the ignore rules, so an unexpected name still trips
# it. Glob patterns, matched against the path relative to the skill dir.
DISALLOWED_STAGED_PATTERNS = [
    "*.env", ".env", "cxone.env", "cxone-identities.yaml", ".agent_state.json",
    "agent.log*", "*.pem", "*.key", "*api*key*",
    "packet*.json", "decisions*.json",
    ".selfcheck_state.json",
    "*.tmp", "*.bak", "*~",
    "scratch/*", "tmp/*",
    "*/__pycache__/*", "*.pyc",
]


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def skip(message: str) -> None:
    print(f"publish skipped: {message}")


def find_disallowed_staged(repo_root: Path, skill_relpath: Path) -> list[str]:
    staged = run(["git", "-C", str(repo_root), "diff", "--cached", "--name-only"], check=False)
    offenders = []
    skill_prefix = str(skill_relpath).replace("\\", "/") + "/"
    for line in staged.stdout.splitlines():
        path = line.strip().replace("\\", "/")
        if not path.startswith(skill_prefix):
            continue
        rel = path[len(skill_prefix):]
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(rel).name, pat)
               for pat in DISALLOWED_STAGED_PATTERNS):
            offenders.append(path)
    return offenders


def _changed_files(repo_root: Path, base: str) -> list[str]:
    """`M path` / `A path` lines for this branch vs the published branch."""
    r = run(["git", "-C", str(repo_root), "diff", "--name-status",
             f"origin/{base}...HEAD"], check=False)
    return [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]


def _pr_body(repo_root: Path, base: str, version: str, summary: str,
             notes: str | None) -> str:
    """Assemble the PR description.

    A PR whose body is just its title tells a reviewer (or whoever bisects to it
    in six months) nothing about scope. So the body ALWAYS carries a summary and
    the concrete file list; ``--notes`` adds the reasoning and test evidence on
    top when the change deserves more than one line.
    """
    files = _changed_files(repo_root, base)
    parts = [f"## Summary\n\n{summary}"]
    if notes:
        parts.append(notes.strip())
    if files:
        rendered = "\n".join(f"- `{ln}`" for ln in files)
        parts.append(f"## Changes ({len(files)} file(s))\n\n{rendered}")
    parts.append(
        f"Skill version: **v{version}**. Merging and tagging `v{version}` "
        f"publishes the `.skill` via the release workflow."
    )
    return "\n\n".join(parts)


def _slug(summary: str) -> str:
    """A branch-safe slug from the summary, so branches read like the change."""
    s = re.sub(r"[^a-z0-9]+", "-", summary.lower()).strip("-")
    return (s[:48].rstrip("-")) or "update"


def _have_gh() -> bool:
    if run(["gh", "--version"], check=False).returncode != 0:
        return False
    return run(["gh", "auth", "status"], check=False).returncode == 0


def _default_branch(repo_root: Path) -> str:
    r = run(["git", "-C", str(repo_root), "symbolic-ref", "--short",
             "refs/remotes/origin/HEAD"], check=False)
    out = r.stdout.strip()
    if r.returncode == 0 and out.startswith("origin/"):
        return out.split("/", 1)[1]
    return "main"


def _spec_preflight() -> None:
    """Refuse to publish code/doc changes that reference endpoints the bundled
    spec cannot describe.

    The spec drifts silently otherwise: an endpoint gets added in code, the
    validator is never run (or its warning is waved through), and the next
    person reads a spec that quietly omits something the tool depends on. Tying
    it to publish makes the check unskippable at exactly the moment the change
    becomes everyone else's problem. `--strict` fails only on genuine drift
    (ABSENT / METHOD?); entries deliberately carried in KNOWN_SPEC_OMISSIONS
    still pass, and are printed on every run so they stay visible as debt.
    """
    validator = SKILL_DIR / "validate_spec.py"
    if not validator.is_file():
        return
    r = run([sys.executable, str(validator), "--strict"], check=False)
    if r.returncode != 0:
        # Show only the offending lines. The full report is long, and pasting
        # its tail buries the two lines that say what to fix.
        offenders = [ln for ln in (r.stdout or "").splitlines()
                     if ln.lstrip().startswith(("ABSENT", "METHOD?")) or ln.startswith("SUMMARY")]
        sys.exit(
            "publish aborted: the API spec is out of sync with the code or docs.\n"
            + "\n".join(offenders)
            + "\n\nFix the bundled spec (spec/cxone_openapi.json), correct the "
              "path, or add a justified KNOWN_SPEC_OMISSIONS entry — then publish.\n"
              "Full report: python validate_spec.py --strict"
        )


def _preflight(repo_root: Path, default_branch: str) -> None:
    """Refuse to publish from a checkout that is behind the published branch."""
    if run(["git", "-C", str(repo_root), "fetch", "--quiet", "--tags", "origin",
            default_branch], check=False).returncode != 0:
        sys.exit("publish aborted: cannot reach origin to verify this checkout is "
                 "current. Publishing from a stale checkout risks a rejected push "
                 "or a duplicated version number.")
    counts = run(["git", "-C", str(repo_root), "rev-list", "--left-right", "--count",
                  f"HEAD...origin/{default_branch}"], check=False)
    try:
        _ahead, behind = (int(x) for x in counts.stdout.split())
    except ValueError:
        return  # can't tell; the push itself will fail loudly if it matters
    if behind:
        sys.exit(
            f"publish aborted: this checkout is {behind} commit(s) behind "
            f"origin/{default_branch}. Another session has published since. "
            f"Run `selfcheck --sync` first, re-check that your change still "
            f"applies and that the version number is still free, then publish."
        )


def _tag_and_push(repo_root: Path, version: str, commit_msg: str) -> None:
    tag = f"v{version}"
    existing = run(["git", "-C", str(repo_root), "ls-remote", "--tags", "origin", tag],
                   check=False)
    if existing.stdout.strip():
        skip(f"tag {tag} already exists on origin — bump VERSION again before the next publish.")
        return
    run(["git", "-C", str(repo_root), "tag", "-a", tag, "-m", commit_msg])
    if run(["git", "-C", str(repo_root), "push", "origin", tag], check=False).returncode != 0:
        sys.exit(f"tag push failed, resolve manually: {tag}")
    print(f"pushed tag {tag} -> origin — the release workflow will build and "
          f"publish the .skill artifact")


def main() -> None:
    ap = argparse.ArgumentParser(prog="publish_skill.py")
    ap.add_argument("summary", help="one-line summary of the change")
    ap.add_argument("--no-merge", action="store_true",
                    help="open the PR but do not merge or tag (review first)")
    ap.add_argument("--tag-only", action="store_true",
                    help="skip branch/PR; just tag the current default branch")
    ap.add_argument("--notes", default=None,
                    help="extra PR body detail (rationale, test evidence). The PR "
                         "always carries a summary and the changed-file list; this "
                         "adds the reasoning on top.")
    args = ap.parse_args()
    summary = args.summary.strip()
    if not summary:
        sys.exit('usage: publish_skill.py "short summary of the change"')

    toplevel = run(["git", "-C", str(SKILL_DIR), "rev-parse", "--show-toplevel"], check=False)
    if toplevel.returncode != 0:
        skip("not inside a git repository — use the manual .skill export flow instead.")
        return
    repo_root = Path(toplevel.stdout.strip())

    if run(["git", "-C", str(repo_root), "remote", "get-url", "origin"],
           check=False).returncode != 0:
        skip("no 'origin' remote configured — use the manual .skill export flow instead.")
        return

    default_branch = _default_branch(repo_root)
    skill_relpath = SKILL_DIR.relative_to(repo_root)
    version = (SKILL_DIR / "VERSION").read_text().strip()
    commit_msg = f"checkmarx-one-multi-tool v{version}: {summary}"

    _preflight(repo_root, default_branch)
    _spec_preflight()

    if args.tag_only:
        _tag_and_push(repo_root, version, commit_msg)
        return

    if not _have_gh():
        sys.exit(
            "publish aborted: the GitHub CLI (`gh`) is not installed or not "
            "authenticated, so the PR cannot be opened.\n"
            "Fix with `gh auth login`, or do it by hand:\n"
            f"  git checkout -b <branch> && git add -- {skill_relpath} && "
            f"git commit && git push -u origin <branch>\n"
            "  ...open and squash-merge the PR, then re-run with --tag-only."
        )

    start = run(["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"],
                check=False).stdout.strip()
    if start == "HEAD":
        skip("repo is in a detached HEAD state — check out a branch first.")
        return

    branch_name = f"skill-v{version}-{_slug(summary)}"
    if start != branch_name:
        if run(["git", "-C", str(repo_root), "checkout", "-b", branch_name],
               check=False).returncode != 0:
            sys.exit(f"could not create branch {branch_name} — does it already exist?")
        print(f"branch: {branch_name}")

    run(["git", "-C", str(repo_root), "add", "--", str(skill_relpath)])

    offenders = find_disallowed_staged(repo_root, skill_relpath)
    if offenders:
        run(["git", "-C", str(repo_root), "reset", "--", str(skill_relpath)], check=False)
        offender_list = "\n".join(f"  - {o}" for o in offenders)
        sys.exit(
            "publish aborted: staged file(s) look like credentials or scratch/junk "
            "output that shouldn't ship with the skill:\n"
            f"{offender_list}\n"
            "Delete or .gitignore these, then re-run publish_skill.py. "
            "(Staged changes have been unstaged; nothing was committed.)"
        )

    if run(["git", "-C", str(repo_root), "diff", "--cached", "--quiet"],
           check=False).returncode == 0:
        skip("nothing new staged under the skill directory.")
        return

    if run(["git", "-C", str(repo_root), "commit", "-m", commit_msg],
           check=False).returncode != 0:
        sys.exit("commit failed, resolve manually (is a commit identity configured?)")
    print(f"committed: {commit_msg}")

    if run(["git", "-C", str(repo_root), "push", "-u", "origin", branch_name],
           check=False).returncode != 0:
        sys.exit("push failed (resolve manually, e.g. pull/rebase if the remote moved)")
    print(f"pushed {branch_name} -> origin/{branch_name}")

    body = _pr_body(repo_root, default_branch, version, summary, args.notes)
    pr = run(["gh", "pr", "create", "--head", branch_name,
              "--base", default_branch, "--title", commit_msg,
              "--body", body], check=False)
    if pr.returncode != 0:
        sys.exit(f"could not open the PR, resolve manually:\n{pr.stderr}")
    print((pr.stdout or "").strip())

    if args.no_merge:
        print("PR opened and left for review (--no-merge). Once it is merged, run "
              "`publish_skill.py \"<summary>\" --tag-only` from the default branch "
              "to cut the release tag.")
        return

    if run(["gh", "pr", "merge", branch_name, "--squash", "--delete-branch"],
           check=False).returncode != 0:
        sys.exit("merge failed — the PR is open; merge it in GitHub, then re-run "
                 "with --tag-only to cut the tag.")
    print(f"squash-merged into {default_branch}")

    run(["git", "-C", str(repo_root), "checkout", default_branch], check=False)
    run(["git", "-C", str(repo_root), "pull", "--ff-only", "origin", default_branch],
        check=False)
    _tag_and_push(repo_root, version, commit_msg)


if __name__ == "__main__":
    main()
