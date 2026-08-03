"""
selfcheck — is this copy of the skill current with the PUBLISHED line, and can
it update itself?

The skill is meant to improve as it is used, which means more than one session
may be editing it. When this folder is a git checkout, another session's merged
work reaches us only when we pull; until then we are running yesterday's build
while the repo has moved on. This module is how that gets noticed.

**"Current" means current with ``origin``'s default branch — nothing else.**
Only merged work counts as an update. A feature branch someone pushed for
review is a proposal, not a published version, so it is deliberately invisible
here: syncing to unreviewed work would spread half-finished changes between
sessions, which is precisely the failure this is meant to prevent. The
comparison is always ``HEAD`` against ``origin/<default branch>`` (``main``
here), whatever branch happens to be checked out locally.

**Two modes, and the difference matters.**

* ``repo`` — the skill folder lives inside a git checkout with an ``origin``
  remote (the normal case for this project). "Out of date" means *behind
  origin/main*, and the fix is a fast-forward pull. Nothing needs to be
  packaged or reinstalled: the checkout IS the installed skill.
* ``standalone`` — the skill was copied somewhere without the repo. Nothing can
  be synced from here; the honest answer is "reinstall the latest release", and
  saying anything else would imply a self-update that cannot happen.

**Why the check is throttled.** ``welcome`` calls this at session start, and a
network round-trip on every session start is fine, but the same check firing on
every command would be a tax on work that has nothing to do with the skill's
own version. So a remote check runs at most once per ``TTL_HOURS``; in between,
the cached counts are reported and labelled as cached. The one place throttling
is deliberately bypassed is publishing (``check(force=True)``), where "am I
behind?" is a correctness question, not a cadence one — committing from a stale
checkout is how a push gets rejected or a version number collides.

Everything here degrades to a quiet "unknown" rather than raising. A flaky
network, a missing remote, or a detached HEAD must never take down a tenant
operation that has nothing to do with git.
"""

from __future__ import annotations

import json
import datetime as _dt
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = SKILL_ROOT / ".selfcheck_state.json"

# How long a remote check stays fresh. Four hours means a session-start check
# plus one more if the day runs long — roughly one or two fetches a day, which
# is responsive to another session's merge without turning into git spam.
TTL_HOURS = 4

# Used only if origin/HEAD isn't set locally (a clone that never resolved it).
_FALLBACK_DEFAULT_BRANCH = "main"

# git talks to the network here; bound it so a hung connection cannot stall the
# CLI. The check is advisory, so a timeout is just "unknown", never an error.
_NET_TIMEOUT = 15
_LOCAL_TIMEOUT = 10


@dataclass
class Status:
    mode: str = "standalone"            # 'repo' | 'standalone'
    version: str = ""                   # local VERSION
    branch: str | None = None           # currently checked-out branch
    publish_branch: str = _FALLBACK_DEFAULT_BRANCH   # origin's default branch
    behind: int = 0                     # published commits we lack
    ahead: int = 0                      # local commits not on the published line
    dirty: bool = False                 # tracked modifications present
    latest_tag: str | None = None       # newest v* tag known to origin
    remote_checked: bool = False        # did this call hit the network?
    checked_at: str | None = None       # when the counts were last refreshed
    notes: list[str] = field(default_factory=list)

    @property
    def on_publish_branch(self) -> bool:
        return self.branch is not None and self.branch == self.publish_branch

    @property
    def out_of_date(self) -> bool:
        return self.mode == "repo" and self.behind > 0

    @property
    def can_sync(self) -> bool:
        """Behind, on the published branch, and not blocked by local edits."""
        return self.out_of_date and self.on_publish_branch and not self.dirty

    def summary_line(self) -> str | None:
        """One line for `welcome`, or None when there is nothing to say.

        Silence is the desired output of a healthy check: an up-to-date
        checkout should not add noise to every session start.
        """
        if self.mode == "standalone" or not self.out_of_date:
            return None
        cached = "" if self.remote_checked else " (cached)"
        one = self.behind == 1
        line = (f"⚠ Update available: {self.behind} published commit{'' if one else 's'} on "
                f"origin/{self.publish_branch} {'is' if one else 'are'} not in this "
                f"checkout{cached}.")
        if self.latest_tag:
            line += f" Newest release: {self.latest_tag} (local v{self.version})."
        if self.can_sync:
            line += "\n    Run `selfcheck --sync` to fast-forward."
        elif not self.on_publish_branch:
            line += (f"\n    On branch '{self.branch}' — finish or park that work, "
                     f"switch to {self.publish_branch}, then `selfcheck --sync`.")
        else:
            line += ("\n    Local changes are present — commit or stash them, "
                     "then `selfcheck --sync`.")
        return line


# ------------------------------------------------------------------ git plumbing
def _git(*args: str, timeout: int = _LOCAL_TIMEOUT) -> tuple[int, str]:
    """Run a git command rooted at the skill dir. Never raises."""
    try:
        p = subprocess.run(["git", "-C", str(SKILL_ROOT), *args],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _default_branch() -> str:
    """origin's default branch — the only line that counts as published."""
    rc, out = _git("symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    if rc == 0 and out.startswith("origin/"):
        return out.split("/", 1)[1]
    return _FALLBACK_DEFAULT_BRANCH


def _read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(data: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass  # a cache we cannot persist just means we re-check next time


def _ttl_expired(state: dict, ttl_hours: int) -> bool:
    raw = state.get("checked_at")
    if not raw:
        return True
    try:
        last = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return True
    age = _dt.datetime.now(_dt.timezone.utc) - last
    # A clock that moved backwards would otherwise cache "forever".
    return age.total_seconds() < 0 or age > _dt.timedelta(hours=ttl_hours)


# ---------------------------------------------------------------------- check
def check(*, force: bool = False, ttl_hours: int = TTL_HOURS) -> Status:
    """Sync state against the published branch. ``force=True`` hits the network."""
    from cxone import get_version
    st = Status(version=get_version())

    rc, _ = _git("rev-parse", "--is-inside-work-tree")
    if rc != 0:
        st.notes.append("Not a git checkout — this is a standalone install.")
        return st
    rc, _ = _git("remote", "get-url", "origin")
    if rc != 0:
        st.notes.append("No 'origin' remote — cannot compare against a source of truth.")
        return st

    st.mode = "repo"
    st.publish_branch = _default_branch()

    rc, branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    if rc == 0 and branch and branch != "HEAD":
        st.branch = branch
    else:
        # Comparison against origin/main still works detached; only syncing and
        # publishing need a branch, and those say so themselves.
        st.notes.append("Detached HEAD — check out a branch before syncing or publishing.")

    # Only TRACKED modifications block a fast-forward. Untracked files (a
    # scratch file, an unignored venv) do not, and treating them as blockers
    # would make the guard fire constantly and get ignored.
    rc_a, _ = _git("diff", "--quiet")
    rc_b, _ = _git("diff", "--cached", "--quiet")
    st.dirty = (rc_a != 0) or (rc_b != 0)

    state = _read_state()
    if force or _ttl_expired(state, ttl_hours):
        rc, _ = _git("fetch", "--quiet", "--tags", "origin", st.publish_branch,
                     timeout=_NET_TIMEOUT)
        if rc != 0:
            # Offline, or no such upstream branch. Fall through to the cached
            # numbers rather than claiming we are up to date.
            st.notes.append("Could not reach origin — reporting the last known state.")
            _apply_cached(st, state)
            return st
        st.remote_checked = True

    counts = _rev_counts(st.publish_branch)
    if counts is None:
        st.notes.append(f"No origin/{st.publish_branch} to compare against.")
        _apply_cached(st, state)
        return st
    st.ahead, st.behind = counts
    st.latest_tag = _latest_tag()

    if st.remote_checked:
        st.checked_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        _write_state({"checked_at": st.checked_at, "publish_branch": st.publish_branch,
                      "ahead": st.ahead, "behind": st.behind,
                      "latest_tag": st.latest_tag})
    else:
        st.checked_at = state.get("checked_at")
    return st


def _apply_cached(st: Status, state: dict) -> None:
    if state.get("publish_branch") == st.publish_branch:
        st.ahead = int(state.get("ahead") or 0)
        st.behind = int(state.get("behind") or 0)
        st.latest_tag = state.get("latest_tag")
        st.checked_at = state.get("checked_at")


def _rev_counts(publish_branch: str) -> tuple[int, int] | None:
    """(ahead, behind) of HEAD vs origin/<publish_branch>, or None if absent."""
    rc, out = _git("rev-list", "--left-right", "--count",
                   f"HEAD...origin/{publish_branch}")
    if rc != 0 or not out:
        return None
    try:
        ahead, behind = out.split()
        return int(ahead), int(behind)
    except ValueError:
        return None


def _latest_tag() -> str | None:
    rc, out = _git("tag", "--list", "v*", "--sort=-v:refname")
    if rc != 0 or not out:
        return None
    return out.splitlines()[0].strip() or None


# ----------------------------------------------------------------------- sync
def sync() -> tuple[int, Status]:
    """Fast-forward to the published branch. Returns (exit code, new status).

    Fast-forward ONLY, on purpose. A merge or rebase here would rewrite or
    combine work this session never saw, in a directory that is also the
    running program. If it cannot fast-forward, that is a real divergence and
    a person should look at it.
    """
    st = check(force=True)
    if st.mode != "repo":
        print("Standalone install — nothing to sync from.")
        print("Reinstall the latest release to update: "
              "https://github.com/CxRW-Tools/CxOne_Multi-Tool/releases/latest")
        return 2, st
    if st.branch is None:
        print("Detached HEAD — check out "
              f"{st.publish_branch} before syncing.")
        return 2, st
    if not st.behind:
        print(f"Already current with origin/{st.publish_branch} (v{st.version}).")
        return 0, st
    if not st.on_publish_branch:
        # Never switch branches for the user: that could strand in-progress work
        # in a directory they are actively editing.
        print(f"{st.behind} published commit(s) are missing here, but the checkout "
              f"is on '{st.branch}', not {st.publish_branch}.")
        print(f"Finish or park that branch, `git checkout {st.publish_branch}`, "
              "then re-run `selfcheck --sync`.")
        return 1, st
    if st.dirty:
        print(f"Behind origin/{st.publish_branch} by {st.behind} commit(s), but there "
              "are uncommitted tracked changes.")
        print("Commit or stash them first — refusing to pull over local edits.")
        return 1, st

    rc, out = _git("pull", "--ff-only", "origin", st.publish_branch, timeout=_NET_TIMEOUT)
    if rc != 0:
        print(f"Fast-forward failed — local and origin/{st.publish_branch} have diverged.")
        print("Resolve by hand (rebase or merge deliberately); nothing was changed.")
        return 1, st
    if out:
        print(out)

    after = check(force=True)
    print(f"Synced to origin/{st.publish_branch}. Version {st.version} -> {after.version}.")
    if after.version != st.version:
        # The SKILL.md the assistant loaded at session start is now the old one.
        # Saying so is the whole point: newer instructions sitting on disk while
        # stale instructions drive the session is the failure this invites.
        print("NOTE: the skill's instructions changed with this sync. Re-read "
              "SKILL.md before following the version already loaded in context.")
    return 0, after


# ---------------------------------------------------------------------- report
def report(st: Status) -> None:
    print(f"Checkmarx One Multi-Tool v{st.version}")
    print(f"  Mode: {st.mode}")
    if st.mode == "repo":
        print(f"  Branch: {st.branch or '(detached)'}"
              f"   Published branch: origin/{st.publish_branch}")
        print(f"  Behind published: {st.behind}   Ahead: {st.ahead}   "
              f"Uncommitted: {'yes' if st.dirty else 'no'}")
        if st.latest_tag:
            print(f"  Newest release tag: {st.latest_tag}")
        when = st.checked_at or "never"
        how = "this run" if st.remote_checked else f"cached, TTL {TTL_HOURS}h"
        print(f"  Remote last checked: {when} ({how})")
    for n in st.notes:
        print(f"  {n}")
    if st.out_of_date:
        print()
        print(st.summary_line())
    elif st.mode == "repo":
        print("  Up to date with the published branch.")


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="multitool selfcheck",
        description="Report whether this skill checkout is current with the "
                    "published branch (origin's default branch), and "
                    "fast-forward it on request. Unmerged feature branches are "
                    "deliberately ignored — only merged work counts.")
    p.add_argument("--sync", action="store_true",
                   help="fast-forward to the published branch (never merges or rebases)")
    p.add_argument("--force", action="store_true",
                   help=f"check the remote now, ignoring the {TTL_HOURS}h throttle")
    p.add_argument("--quiet", action="store_true",
                   help="print only the one-line update notice, and only if behind")
    a = p.parse_args(argv or [])

    if a.sync:
        rc, _ = sync()
        return rc
    st = check(force=a.force)
    if a.quiet:
        line = st.summary_line()
        if line:
            print(line)
        return 0
    report(st)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
