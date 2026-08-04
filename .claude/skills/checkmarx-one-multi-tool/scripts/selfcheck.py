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

import os
import json
import datetime as _dt
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = SKILL_ROOT / ".selfcheck_state.json"


def _ttl_hours() -> float:
    """How long a remote check stays fresh.

    One hour: the check now runs from every command (cache read on the hot path,
    refresh on a background thread), so the TTL sets how often git is actually
    consulted rather than how often you are told. An hour is responsive to
    another session's merge while keeping fetches to roughly one per working
    hour. ``CXONE_UPDATE_TTL_HOURS`` overrides it.
    """
    raw = os.environ.get("CXONE_UPDATE_TTL_HOURS")
    if raw:
        try:
            val = float(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    return 1.0


TTL_HOURS = 1.0   # nominal default; call _ttl_hours() for the effective value

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
    capability: str = "unknown"         # see "publish capability" below
    capability_reason: str = ""         # why that level, in one clause
    capability_checked_at: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def on_publish_branch(self) -> bool:
        return self.branch is not None and self.branch == self.publish_branch

    @property
    def can_publish(self) -> bool:
        """Full flow available: push a branch AND open/merge a PR."""
        return self.capability == "publish"

    @property
    def needs_feature_request(self) -> bool:
        """No write path to origin — a change must be handed off instead.

        'unknown' is deliberately excluded: a failed probe is not evidence of
        denial, and routing someone to the handoff path on a flaky network
        would be its own kind of wrong.
        """
        return self.capability in ("local-only", "standalone")

    def capability_line(self) -> str:
        """One line describing what this checkout can contribute, and how."""
        label = {
            "publish": "publish (push + PR/merge)",
            "push-only": "push branches only (no PR tooling)",
            "local-only": "local only (no write access to origin)",
            "standalone": "standalone install (no repo)",
            "unknown": "unknown (could not probe)",
        }.get(self.capability, self.capability)
        line = f"  Contribution: {label}"
        if self.capability_reason:
            line += f"\n    {self.capability_reason}"
        if self.capability == "push-only":
            line += ("\n    Changes can be pushed as a branch, but someone with PR "
                     "rights must open and merge it.")
        elif self.needs_feature_request:
            line += ("\n    Build changes locally, then run `feature-request new` to "
                     "produce a shareable handoff bundle.")
        return line

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
# git emits UTF-8; `text=True` alone would decode it with the locale codec
# (cp1252 on Windows), mangling any non-ASCII in a branch name or an error
# message. Pin the codec rather than inherit the console's.
_ENC = {"encoding": "utf-8", "errors": "replace"}


def _git(*args: str, timeout: int = _LOCAL_TIMEOUT) -> tuple[int, str]:
    """Run a git command rooted at the skill dir. Never raises."""
    try:
        p = subprocess.run(["git", "-C", str(SKILL_ROOT), *args],
                           capture_output=True, timeout=timeout, **_ENC)
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
    """Write the cache atomically.

    The refresh now runs on a background thread while the foreground is reading
    this same file, so a partially-written file is a real possibility. Write to
    a sibling temp file and rename (atomic on POSIX, and on Windows for
    os.replace), so a reader sees either the old contents or the new ones.
    """
    tmp = STATE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, STATE_FILE)
    except OSError:
        # A cache we cannot persist just means we re-check next time.
        try:
            tmp.unlink()
        except OSError:
            pass


def _ttl_expired(state: dict, ttl_hours: float | None = None) -> bool:
    ttl_hours = _ttl_hours() if ttl_hours is None else ttl_hours
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


# -------------------------------------------------------------- ambient check
# Used by multitool's per-command hook. The design constraint is that a tenant
# command must never pay for this: the hot path touches ONE small file and runs
# no subprocess at all, and the git work happens on a background thread whose
# result is read by a LATER command. That trade — learning one command late
# instead of blocking this one — is what makes an every-command check
# affordable at all.

_ENV_DISABLE = "CXONE_NO_UPDATE_CHECK"
_refresh_started = False        # at most one refresh per process
_notice_emitted = False         # at most one printed notice per process


def _remember_mode(mode: str) -> None:
    """Record repo/standalone so the hot path stops spawning refreshes on a
    checkout that can never be behind (a packaged install, the agent's
    container image). Without this, every command in those environments would
    fork git only to rediscover there is no repo."""
    state = _read_state()
    if state.get("mode") == mode:
        return
    state["mode"] = mode
    state.setdefault("checked_at", _dt.datetime.now(_dt.timezone.utc).isoformat())
    _write_state(state)


def ambient_notice() -> str | None:
    """The "you are behind" line for the per-command hook, from cache only.

    Returns None when there is nothing to say — which is the common case and
    must stay silent. Also schedules a background refresh when the cache has
    aged past the TTL. Never raises, never blocks, never runs git inline.
    """
    if os.environ.get(_ENV_DISABLE):
        return None
    state = _read_state()
    if state.get("mode") == "standalone":
        return None                      # nothing to sync from; stay quiet
    if _ttl_expired(state):
        _refresh_async()
    if not state or int(state.get("behind") or 0) <= 0:
        return None
    st = Status(
        mode="repo",
        version=str(state.get("version") or ""),
        branch=state.get("branch"),
        publish_branch=str(state.get("publish_branch") or _FALLBACK_DEFAULT_BRANCH),
        behind=int(state.get("behind") or 0),
        ahead=int(state.get("ahead") or 0),
        dirty=bool(state.get("dirty")),
        latest_tag=state.get("latest_tag"),
        remote_checked=False,            # always cached on this path
    )
    return st.summary_line()


def emit_notice_once(stream=None) -> bool:
    """Print the update notice at most once per process, from ANY entry point.

    ``multitool.main()`` is not the only way this tool gets used: analysis and
    one-off scripts do ``from cxone import ApiClient`` and never touch the CLI
    dispatcher, so tying the check to the CLI left every programmatic caller
    unchecked. That gap is not hypothetical — a whole afternoon of live tenant
    queries ran through direct imports while the checkout sat several versions
    behind, with the "runs on every command" machinery structurally unreachable.

    ``ApiClient.__init__`` therefore calls this too. The once-per-process guard
    is what makes that safe: a run builds one client per identity and more
    inside worker threads, and nobody needs the same notice ten times.
    """
    global _notice_emitted
    if _notice_emitted:
        return False
    _notice_emitted = True                # set FIRST: a failure below must not
    try:                                  # leave the door open to retry-spam
        line = ambient_notice()
    except Exception:                                     # noqa: BLE001
        return False
    if not line:
        return False
    import sys as _sys
    print(line, file=stream or _sys.stderr)
    return True


def _refresh_async() -> None:
    """Refresh the cache on a daemon thread. Fire-and-forget by design.

    Daemon so it can never hold up interpreter exit: if the command finishes
    first the fetch is simply abandoned and the TTL stays expired, so the next
    command tries again. That is strictly better than making every command wait
    on the network.
    """
    global _refresh_started
    if _refresh_started:
        return
    _refresh_started = True

    def _work():
        try:
            check(force=True)
        except Exception:                                 # noqa: BLE001
            pass                                          # advisory only
    try:
        threading.Thread(target=_work, name="selfcheck-refresh",
                         daemon=True).start()
    except Exception:                                     # noqa: BLE001
        pass


def record_check(*, publish_branch: str, ahead: int, behind: int,
                 latest_tag: str | None = None) -> None:
    """Let another component donate a fresh result to the cache.

    `publish_skill.py` already fetches and computes behind/ahead in its
    preflight; without this it threw that away, so publishing repeatedly (four
    times in one afternoon, in the case that prompted this) left the update
    cache hours stale while claiming to be authoritative about the same fact.
    """
    from cxone import get_version
    state = _read_state()
    state.update({
        "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "publish_branch": publish_branch, "ahead": int(ahead),
        "behind": int(behind), "mode": "repo", "version": get_version(),
    })
    if latest_tag is not None:
        state["latest_tag"] = latest_tag
    _write_state(state)


# ---------------------------------------------------------------------- check
def check(*, force: bool = False, ttl_hours: float | None = None) -> Status:
    """Sync state against the published branch. ``force=True`` hits the network."""
    from cxone import get_version
    st = Status(version=get_version())

    rc, _ = _git("rev-parse", "--is-inside-work-tree")
    if rc != 0:
        st.notes.append("Not a git checkout — this is a standalone install.")
        _remember_mode(st.mode)
        return st
    rc, _ = _git("remote", "get-url", "origin")
    if rc != 0:
        st.notes.append("No 'origin' remote — cannot compare against a source of truth.")
        _remember_mode(st.mode)
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
        # Merge, never replace: the capability probe keeps its own keys and its
        # own (much longer) TTL in this same file, and a wholesale overwrite
        # here would silently discard them on every refresh.
        state.update({"checked_at": st.checked_at, "publish_branch": st.publish_branch,
                      "ahead": st.ahead, "behind": st.behind,
                      "latest_tag": st.latest_tag, "mode": st.mode,
                      "branch": st.branch, "dirty": st.dirty,
                      "version": st.version})
        _write_state(state)
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


# ------------------------------------------------------- publish capability
# Being CURRENT is not the same as being able to CONTRIBUTE. A user can sit on
# a perfectly up-to-date checkout and still have no write access to origin —
# and today they only find out at the moment `publish_skill.py` tries to push,
# which is *after* the change is written, staged and committed to a local
# branch. That strands tested work at the worst possible moment.
#
# Probing capability up front is what lets a session say "I can build this, but
# you can't publish it — I'll produce a handoff bundle" BEFORE any of that work
# happens. Four levels, each mapped to what it can actually do:
#
#   publish     push a branch AND open/merge a PR   -> the normal publish flow
#   push-only   push a branch, but no PR tooling    -> push it, hand off the name
#   local-only  no write access at all              -> feature-request bundle
#   standalone  not a git checkout                  -> feature-request bundle
#
# 'unknown' means the probe could not reach the network. It is never treated as
# permission — but it is never treated as denial either, because routing
# someone to the handoff path over a flaky connection is its own failure.
#
# This probe is NOT on the ambient path. It costs a network round-trip, and the
# hot path's whole design is that a tenant command never pays for git. It runs
# only from the explicit `selfcheck` verb, from `feature-request`, and from
# publish's preflight — all of which are already synchronous and blocking.

CAPABILITY_TTL_HOURS = 24.0   # write access changes far less often than commits

# Pushed to a throwaway ref name, never to the publish branch: a --dry-run
# against a protected `main` reports the protection rule, which would read as
# "no write access" for someone who has plenty. Branch creation is the
# permission the publish flow actually needs.
_PROBE_REF = "refs/heads/_cxone_capability_probe"


def _capability_ttl_hours() -> float:
    raw = os.environ.get("CXONE_CAPABILITY_TTL_HOURS")
    if raw:
        try:
            val = float(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    return CAPABILITY_TTL_HOURS


def _capability_expired(state: dict) -> bool:
    raw = state.get("capability_checked_at")
    if not raw:
        return True
    try:
        last = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return True
    age = _dt.datetime.now(_dt.timezone.utc) - last
    return age.total_seconds() < 0 or age > _dt.timedelta(hours=_capability_ttl_hours())


def _run(*args: str, timeout: int = _LOCAL_TIMEOUT) -> tuple[int, str]:
    """Run a command that isn't rooted at the skill dir (gh). Never raises."""
    try:
        p = subprocess.run(list(args), capture_output=True, timeout=timeout, **_ENC)
        return p.returncode, (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _git_err(*args: str, timeout: int = _LOCAL_TIMEOUT) -> tuple[int, str]:
    """Like _git, but returns stdout AND stderr combined.

    Git reports transport and permission failures on stderr — "Repository not
    found", "Permission denied" and friends never appear on stdout. Classifying
    a push probe from stdout alone means classifying an empty string, which is
    how every denial silently became "unknown".
    """
    try:
        p = subprocess.run(["git", "-C", str(SKILL_ROOT), *args],
                           capture_output=True, timeout=timeout, **_ENC)
        return p.returncode, ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _origin_slug() -> str | None:
    """'owner/repo' from origin's URL, for `gh api`. None if not GitHub-shaped."""
    rc, url = _git("remote", "get-url", "origin")
    if rc != 0 or not url:
        return None
    u = url.strip()
    if u.endswith(".git"):
        u = u[:-4]
    if u.startswith("git@"):                    # git@github.com:owner/repo
        _, _, path = u.partition(":")
    elif "://" in u:                            # https://github.com/owner/repo
        path = u.split("://", 1)[1]
        path = path.split("/", 1)[1] if "/" in path else ""
    else:
        return None
    parts = [p for p in path.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else None


def _gh_pr_capable() -> bool | None:
    """Can `gh` open a PR here? None when gh is absent or unauthenticated.

    Only a *capability* answer — whether a given PR would pass branch
    protection is a review-policy question no probe can settle in advance.
    """
    if _run("gh", "--version")[0] != 0:
        return None
    if _run("gh", "auth", "status", timeout=_NET_TIMEOUT)[0] != 0:
        return None
    slug = _origin_slug()
    if not slug:
        return None
    rc, out = _run("gh", "api", f"repos/{slug}", "--jq", ".permissions.push",
                   timeout=_NET_TIMEOUT)
    if rc != 0:
        return None
    return out.strip().lower() == "true"


def _push_capable() -> tuple[bool | None, str]:
    """Can we create a branch on origin? (True/False/None-unknown, reason).

    `git push --dry-run` is the only probe that actually exercises the
    credential path rather than inferring from config, which is why it is the
    load-bearing one. It contacts the server and changes nothing.
    """
    rc, _ = _git("rev-parse", "HEAD")
    if rc != 0:
        return None, "no commit to probe with"
    p_rc, out = _git_err("push", "--dry-run", "--porcelain", "origin",
                         f"HEAD:{_PROBE_REF}", timeout=_NET_TIMEOUT)
    if p_rc == 0:
        return True, "write access to origin confirmed"
    blob = (out or "").lower()
    # Network trouble is checked FIRST: an offline machine can produce messages
    # containing "authentication", and calling that a denial would route a
    # privileged user onto the handoff path for the duration of an outage.
    if any(s in blob for s in ("could not resolve", "timed out", "timeout",
                               "network is unreachable", "connection refused",
                               "connection timed out", "unable to access",
                               "failed to connect")):
        return None, "could not reach origin to probe write access"
    if any(s in blob for s in ("permission", "denied", "403", "forbidden",
                               "read-only", "unauthorized", "authentication",
                               "protected branch", "pre-receive hook declined")):
        return False, "origin rejected the push probe (no write access)"
    # GitHub deliberately answers "not found" rather than 403 for a repo the
    # caller cannot see, so this is the SHAPE most private-repo denials take.
    # A genuinely deleted repo lands here too — different cause, same
    # consequence (nothing can be pushed), so the reason states what was
    # observed instead of asserting why.
    if "not found" in blob or "does not exist" in blob:
        return False, "origin reports the repository as not found (no access, or it moved)"
    # Non-zero for a reason we cannot classify. Refusing to guess is the point:
    # calling this 'denied' would push a privileged user onto the handoff path.
    return None, "push probe failed for an unrecognized reason"


def probe_capability(st: Status, *, force: bool = False) -> Status:
    """Fill in st.capability, using the cache unless it has aged out."""
    if st.mode != "repo":
        st.capability = "standalone"
        st.capability_reason = "not a git checkout — nothing to push to"
        return st

    state = _read_state()
    if not force and not _capability_expired(state) and state.get("capability"):
        st.capability = str(state.get("capability"))
        st.capability_reason = str(state.get("capability_reason") or "") + " (cached)"
        st.capability_checked_at = state.get("capability_checked_at")
        return st

    can_push, reason = _push_capable()
    if can_push is None:
        st.capability, st.capability_reason = "unknown", reason
        return st                      # never cache an inconclusive probe
    if not can_push:
        st.capability, st.capability_reason = "local-only", reason
    else:
        pr_ok = _gh_pr_capable()
        if pr_ok:
            st.capability = "publish"
            st.capability_reason = "write access to origin, and gh can open PRs"
        elif pr_ok is None:
            st.capability = "push-only"
            st.capability_reason = ("write access to origin, but gh is missing or "
                                    "not authenticated")
        else:
            st.capability = "push-only"
            st.capability_reason = "gh reports no push permission on this repo"

    st.capability_checked_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    state.update({"capability": st.capability,
                  "capability_reason": st.capability_reason,
                  "capability_checked_at": st.capability_checked_at})
    _write_state(state)
    return st


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
    print(st.capability_line())
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
    if not a.quiet:
        # Explicit, synchronous command — affordable place to pay for the probe.
        probe_capability(st, force=a.force)
    if a.quiet:
        line = st.summary_line()
        if line:
            print(line)
        return 0
    report(st)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
