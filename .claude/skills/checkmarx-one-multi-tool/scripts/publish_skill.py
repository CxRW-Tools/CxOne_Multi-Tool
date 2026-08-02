#!/usr/bin/env python3
"""Publish this skill's own changes to GitHub, if the skill folder happens to
be running from inside a git checkout with a reachable 'origin' remote.

Commits only the files under this skill's directory, pushes the current
branch, and — since VERSION is expected to have just changed — tags and
pushes v<version>. On a repo with the release-skill GitHub Action configured,
that tag push builds a .skill zip and attaches it to a new GitHub Release
automatically.

If there's no git repo, no 'origin' remote, nothing staged, a detached HEAD,
or the tag already exists, this prints why and exits cleanly without making
any change — the caller should fall back to the manual .skill export flow
documented in SKILL.md.

Usage:
    python scripts/publish_skill.py "short summary of the change"
"""
import fnmatch
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


def main() -> None:
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        sys.exit('usage: publish_skill.py "short summary of the change"')
    summary = sys.argv[1].strip()

    toplevel = run(["git", "-C", str(SKILL_DIR), "rev-parse", "--show-toplevel"], check=False)
    if toplevel.returncode != 0:
        skip("not inside a git repository — use the manual .skill export flow instead.")
        return
    repo_root = Path(toplevel.stdout.strip())

    remote = run(["git", "-C", str(repo_root), "remote", "get-url", "origin"], check=False)
    if remote.returncode != 0:
        skip("no 'origin' remote configured — use the manual .skill export flow instead.")
        return

    branch = run(["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"], check=False)
    branch_name = branch.stdout.strip()
    if branch.returncode != 0 or branch_name == "HEAD":
        skip("repo is in a detached HEAD state — check out a branch first.")
        return

    skill_relpath = SKILL_DIR.relative_to(repo_root)
    version = (SKILL_DIR / "VERSION").read_text().strip()

    commit_msg = f"checkmarx-one-multi-tool v{version}: {summary}"

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

    staged = run(["git", "-C", str(repo_root), "diff", "--cached", "--quiet"], check=False)
    if staged.returncode == 0:
        # Nothing new to commit — but a prior run may have committed already and
        # only failed to push/tag. Don't bail here; fall through and let the
        # push/tag steps below no-op cleanly if there's truly nothing left to do.
        print("nothing new staged under the skill directory — checking push/tag state.")
    else:
        commit = run(["git", "-C", str(repo_root), "commit", "-m", commit_msg], check=False)
        if commit.returncode != 0:
            sys.exit(f"commit failed, resolve manually:\n{commit.stderr}")
        print(f"committed: {commit_msg}")

    push = run(["git", "-C", str(repo_root), "push", "origin", branch_name], check=False)
    if push.returncode != 0:
        sys.exit(
            f"push failed (resolve manually, e.g. pull/rebase if the remote moved):\n{push.stderr}"
        )
    print(f"pushed {branch_name} -> origin/{branch_name}")

    tag = f"v{version}"
    existing = run(["git", "-C", str(repo_root), "ls-remote", "--tags", "origin", tag], check=False)
    if existing.stdout.strip():
        skip(f"tag {tag} already exists on origin — bump VERSION again before the next publish.")
        return

    run(["git", "-C", str(repo_root), "tag", "-a", tag, "-m", commit_msg])
    tag_push = run(["git", "-C", str(repo_root), "push", "origin", tag], check=False)
    if tag_push.returncode != 0:
        sys.exit(f"tag push failed, resolve manually:\n{tag_push.stderr}")
    print(f"pushed tag {tag} -> origin — release workflow (if configured) will "
          f"build and publish the .skill artifact")


if __name__ == "__main__":
    main()
