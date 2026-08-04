"""
feature-request — capture a feature gap as a shareable handoff bundle.

The skill improves by being used: someone hits a gap, the change gets written,
published, and every other session picks it up on the next sync. That loop
assumes the person who found the gap can push to origin. Plenty of users
cannot — no write access, no PR rights, or a copy of the skill with no repo
behind it at all.

Without this module their options are bad ones: describe the gap in a chat that
nobody else will read, or write the change and discover at `publish_skill.py`'s
push step that it is stranded on a local branch. This module is the third
option — a self-contained bundle that a privileged developer can act on.

**A bundle is a patch plus its context, not a wish.** Prose alone gets
re-implemented from scratch by whoever picks it up, and the tested work is
thrown away. So when the change already exists locally, `change.patch` ships
with it and the developer runs `git am` (or `git apply`) instead of rebuilding
from a description. When the user only *identified* the gap, REQUEST.md stands
alone and says so.

**Redaction is a hard gate, not a nicety.** The whole point of this file is to
be sent to someone else, and the context worth capturing — the prompt, the
scenario, the command that failed — is exactly where credentials live. A
session that configured a tenant has an API key in its scrollback; several, if
secondary identities were registered. Every field is scrubbed before it is
written, and an unclassifiable high-entropy string blocks the write rather than
riding along. `publish_skill.py` already refuses to stage secrets
(DISALLOWED_STAGED_PATTERNS); this is the same instinct applied to prose.
"""

from __future__ import annotations

import os
import re
import sys
import argparse
import datetime as _dt
import subprocess
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent

_GIT_TIMEOUT = 20


# --------------------------------------------------------------- redaction
# Known-shape secrets, redacted by pattern. Each keeps its label so the reader
# of a bundle can see WHAT was removed and judge whether the context still
# makes sense — a bare "<REDACTED>" leaves them guessing.
# A value that is obviously a stand-in, not a credential. Documentation, help
# text and code comments are full of `--api-key <KEY>` and `TOKEN=$MY_TOKEN`,
# and redacting those rewrites legitimate source: the first real patch this
# module produced had its own comment `# --api-key <value>` silently turned
# into `# --api-key <REDACTED:secret>`. A patch whose code differs from what
# the author wrote is worse than no patch, because it applies cleanly.
_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|\$\{?[A-Za-z_]\w*\}?|\{\{?\w+\}?\}|\.{3,}|\*{3,}|x{3,}"
    r"|your[_-]?\w*|redacted\S*|key|token|secret|password|value|change-me"
    r"|<?redacted:[a-z-]+>?)$", re.I)


def _is_placeholder(value: str) -> bool:
    """True if `value` is a stand-in rather than a credential.

    Trailing punctuation is trimmed first: a value captured out of prose
    arrives as ``<KEY>` `` or ``$MY_TOKEN,`` — carrying the backtick or comma
    that closed the sentence — and testing that raw string misses every
    placeholder written inside documentation. Falls back to the untrimmed value
    so an all-punctuation placeholder like `...` still matches.
    """
    v = value.strip()
    trimmed = v.rstrip("`,;.)]}\"'")
    return bool(_PLACEHOLDER.match(trimmed or v))


def _keep_key(m: "re.Match[str]") -> str:
    if _is_placeholder(m.group(2)):
        return m.group(0)
    return f"{m.group(1)}=<REDACTED:{m.group(1).lower()}>"


def _keep_flag(m: "re.Match[str]") -> str:
    if _is_placeholder(m.group(2)):
        return m.group(0)
    return f"{m.group(1)}<REDACTED:secret>"


_PATTERNS: list[tuple[str, "re.Pattern[str]", object]] = [
    # CxOne API keys are refresh-token JWTs; this is the single most likely
    # secret to appear, because the user pastes one to configure the tenant.
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
     "<REDACTED:jwt>"),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
     "<REDACTED:github-token>"),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
     "<REDACTED:github-token>"),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{15,}"),
     "<REDACTED:gitlab-token>"),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
     "Bearer <REDACTED:bearer>"),
    # KEY=value / KEY: value in pasted env files and logs.
    ("assignment", re.compile(
        r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|TOKEN|SECRET|PASSWORD|PASSWD))"
        r"\s*[=:]\s*[\"']?([^\s\"'#,]{6,})"), _keep_key),
    # --api-key <value> in a pasted command line.
    ("cli-flag", re.compile(
        r"(?i)(--(?:api-key|password|token|secret|client-secret)[=\s]+)"
        r"[\"']?([^\s\"']{6,})"), _keep_flag),
]

# Anything left that LOOKS like a credential but matched no known shape. This
# does not redact — it blocks, because silently shipping an unrecognized secret
# is the failure mode that matters, and silently mangling a legitimate long
# string is a close second. 40 chars keeps CxOne result ids (~28, base64) and
# UUIDs (36) out of it.
_UNCLASSIFIED = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b")

# Known-benign long strings, so the block above stays a signal rather than
# noise the user learns to override reflexively.
_BENIGN = re.compile(r"(?i)^(?:[0-9a-f]{40}|[0-9a-f]{64}|<redacted:[a-z-]+>)$")

# Long file paths match the pattern above, because '/' and '-' are legitimately
# part of base64url. A repo path like
# 'claude/skills/checkmarx-one-multi-tool/scripts/selfcheck' is 56 chars and
# tripped the blocker on every real patch, which would have trained users to
# pass --allow-unclassified reflexively — the precise way a safety gate stops
# working. Slash-separated lowercase word segments are the discriminator: a
# base64 blob does not have them, so 'abc/DEF+ghi==' stays suspicious.
_PATHLIKE = re.compile(r"/[a-z][a-z0-9_-]*(?:/|$)")


def _is_benign(token: str) -> bool:
    return bool(_BENIGN.match(token) or _PATHLIKE.search(token))


def redact(text: str, *, extra: list[str] | None = None) -> tuple[str, list[str], list[str]]:
    """Scrub known secrets. Returns (clean_text, kinds_removed, unclassified).

    ``extra`` holds literals to remove verbatim — the tenant name, for one,
    which is not a secret but does identify a customer environment.
    """
    if not text:
        return "", [], []
    kinds: list[str] = []
    out = text
    for label, pat, repl in _PATTERNS:
        # Count REAL redactions, not matches: the placeholder-aware handlers
        # return the match untouched, and counting those would report secrets
        # removed from a document that never had any.
        hits = 0

        def _apply(m: "re.Match[str]", _r=repl) -> str:
            nonlocal hits
            new = _r(m) if callable(_r) else _r
            if new != m.group(0):
                hits += 1
            return new

        out = pat.sub(_apply, out)
        if hits:
            kinds.append(f"{label} x{hits}")
    for literal in (extra or []):
        if literal and len(literal) >= 4 and literal in out:
            out = out.replace(literal, "<REDACTED:tenant>")
            kinds.append("tenant")
    suspicious = [m.group(0) for m in _UNCLASSIFIED.finditer(out)
                  if not _is_benign(m.group(0))]
    return out, kinds, suspicious


def _tenant_literals(env_file: str | None) -> list[str]:
    """Tenant name / base URL host from the credentials file, if one is readable.

    Best-effort and silent on failure: a bundle must be writable on a machine
    that never configured a tenant at all.
    """
    try:
        import config_setup as cs
        from cxone import default_env_file
        data = cs.read_env_file(env_file or default_env_file())
    except Exception:                                       # noqa: BLE001
        return []
    out = []
    for key in ("CXONE_TENANT",):
        val = (data.get(key) or "").strip()
        if val:
            out.append(val)
    return out


# ------------------------------------------------------------------- git
# git speaks UTF-8. `text=True` alone decodes with the locale encoding, which on
# Windows is cp1252 — so every non-ASCII byte in a diff came back double-encoded
# and the em-dashes in these very docstrings landed in the patch as mojibake.
# The patch IS the deliverable here, so a corrupted one is the whole feature
# failing quietly. Pin the codec everywhere git output is read.
_ENC = {"encoding": "utf-8", "errors": "replace"}


def _git(*args: str) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", "-C", str(SKILL_ROOT), *args],
                           capture_output=True, timeout=_GIT_TIMEOUT, **_ENC)
        return p.returncode, (p.stdout or "")
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _head_sha() -> str:
    rc, out = _git("rev-parse", "--short", "HEAD")
    return out.strip() if rc == 0 else "(unknown)"


def _publish_branch() -> str:
    rc, out = _git("symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    out = out.strip()
    if rc == 0 and out.startswith("origin/"):
        return out.split("/", 1)[1]
    return "main"


def _repo_root() -> Path | None:
    rc, out = _git("rev-parse", "--show-toplevel")
    if rc != 0 or not out.strip():
        return None
    return Path(out.strip())


def _untracked_diff() -> str:
    """Diff hunks for NEW files, which `git diff` does not report at all.

    Without this a bundle silently ships an incomplete patch: adding a feature
    usually means adding a module, and a diff of tracked files alone contains
    every wiring change *referencing* the new file and not the file itself. The
    recipient gets something that applies cleanly and then fails on import.

    `--no-index` produces the hunks without an `git add -N`, so the user's index
    is never mutated as a side effect of writing a report. `--exclude-standard`
    honours .gitignore, which is what keeps credentials, the agent ledger and
    the selfcheck cache out of the patch.
    """
    root = _repo_root()
    if root is None:
        return ""
    try:
        rel = SKILL_ROOT.relative_to(root).as_posix()
    except ValueError:
        return ""
    rc, out = _git("ls-files", "--others", "--exclude-standard", "--", ".")
    if rc != 0 or not out.strip():
        return ""
    chunks = []
    for name in out.splitlines():
        name = name.strip()
        if not name:
            continue
        path = f"{rel}/{name}" if not name.startswith(rel) else name
        try:
            p = subprocess.run(
                ["git", "-C", str(root), "diff", "--no-index", "--", os.devnull, path],
                capture_output=True, timeout=_GIT_TIMEOUT, **_ENC)
        except (OSError, subprocess.SubprocessError):
            continue
        # --no-index exits 1 when the files differ, which is always the case
        # here; only a >1 code means it actually failed.
        if p.returncode <= 1 and (p.stdout or "").strip():
            chunks.append(p.stdout)
    return "".join(chunks)


def build_patch() -> tuple[str | None, str]:
    """The local change as a patch, plus a one-line description of its form.

    Commits ahead of the published branch become a `git am`-able mailbox;
    uncommitted edits become a plain diff, with new files folded in. Everything
    is scoped to the skill directory so unrelated repo changes never ride along
    in a bundle that is about to be sent to someone.
    """
    base = _publish_branch()
    rc, out = _git("rev-list", "--count", f"origin/{base}..HEAD")
    ahead = 0
    if rc == 0 and out.strip().isdigit():
        ahead = int(out.strip())
    if ahead:
        rc, patch = _git("format-patch", f"origin/{base}..HEAD", "--stdout", "--", ".")
        if rc == 0 and patch.strip():
            # Committed work already carries its new files.
            return patch, f"{ahead} commit(s) ahead of origin/{base} (apply with `git am`)"

    new_files = _untracked_diff()
    rc, tracked = _git("diff", "--", ".")
    tracked = tracked if rc == 0 else ""
    if not tracked.strip():
        rc, staged = _git("diff", "--cached", "--", ".")
        if rc == 0 and staged.strip():
            tracked = staged
    combined = (tracked or "") + (new_files or "")
    if combined.strip():
        n_new = new_files.count("\ndiff --git ") + (1 if new_files.startswith("diff --git ") else 0)
        desc = "uncommitted working-tree changes (apply with `git apply`)"
        if n_new:
            desc += f", including {n_new} new file(s)"
        return combined, desc
    return None, "no local code change found"


# ------------------------------------------------------------------ fields
def read_field(value: str | None) -> str:
    """A field value, or the contents of @file, or stdin for '-'.

    Long prose (a scenario, a failing transcript) does not belong on a command
    line, and shell-quoting it is how it gets mangled.
    """
    if not value:
        return ""
    if value == "-":
        return sys.stdin.read().strip()
    if value.startswith("@"):
        path = Path(value[1:]).expanduser()
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"could not read {path}: {exc}")
    return value.strip()


def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s[:48].rstrip("-")) or "feature-request"


def build_request_md(*, title: str, use_case: str, gap: str, scenario: str,
                     prompt: str, proposed_cli: str, notes: str,
                     version: str, capability: str, patch_desc: str,
                     redaction_kinds: list[str]) -> str:
    """REQUEST.md — everything a developer needs to act without the session."""
    today = _dt.date.today().isoformat()
    parts = [
        f"# Feature request: {title}",
        "",
        "> Raised from a Checkmarx One Multi-Tool session by a user who cannot "
        "publish to the repository directly. Everything needed to act on it "
        "should be in this file; if something is missing, that is a bug in the "
        "`feature-request` template.",
        "",
        "| | |",
        "|---|---|",
        f"| Date | {today} |",
        f"| Skill version | v{version} |",
        f"| Checkout | `{_head_sha()}` |",
        f"| Reporter capability | `{capability}` |",
        f"| Patch included | {patch_desc} |",
        "",
        "## Use case",
        "",
        use_case or "_(not supplied)_",
        "",
        "## The gap",
        "",
        gap or "_(not supplied)_",
    ]
    if scenario:
        parts += ["", "## Scenario / how it came up", "", scenario]
    if prompt:
        parts += ["", "## What was asked", "",
                  "The request that surfaced the gap, as phrased by the user:",
                  "", "```text", prompt, "```"]
    if proposed_cli:
        parts += ["", "## Proposed CLI shape", "", "```bash", proposed_cli, "```"]
    if notes:
        parts += ["", "## Implementation notes", "", notes]
    parts += [
        "",
        "## Applying the patch",
        "",
        "```bash",
        "# from the repo root, on a branch off the published branch",
        "git am < change.patch        # if the patch was made from commits",
        "git apply change.patch       # if it is a plain diff",
        "```",
        "",
        "Bump `VERSION` and `SKILL.md`'s `metadata.version` before publishing, "
        "then run `scripts/publish_skill.py \"<summary>\"` as usual.",
        "",
        "---",
        "",
        "### Redaction",
        "",
    ]
    if redaction_kinds:
        parts.append("Secrets were removed from this document before it was "
                     f"written: {', '.join(sorted(set(redaction_kinds)))}. "
                     "Placeholders read `<REDACTED:kind>`.")
    else:
        parts.append("No credential-shaped strings were found in the supplied "
                     "context. The document was still scanned before writing.")
    parts.append("")
    return "\n".join(parts)


# ------------------------------------------------------------------ command
def _inside_skill_tree(d: Path) -> bool:
    """True if `d` IS the skill root or sits under it.

    cxone.is_inside_skill_dir is file-shaped — it tests `resolved.parent`, so
    handing it a directory that IS the skill root returns False and the guard
    silently passes. `--out .` from the skill folder hit exactly that, and a
    bundle landed inside the tree that `selfcheck --sync` fast-forwards.
    """
    try:
        resolved = d.resolve()
    except (OSError, ValueError):
        return False
    return resolved == SKILL_ROOT or SKILL_ROOT in resolved.parents


def _default_out_root(env_file: str | None) -> Path | None:
    """Where a bundle goes when --out was not given, or None if undecidable.

    The documented way to run this tool is to `cd` into the skill folder and
    call `python run.py ...`, which makes the naive default (cwd) the one
    directory a bundle must never land in. Rather than refuse the common case,
    fall back to the credentials file's directory: `cxone.env` is required to
    live in the user's own project folder, so it is a reliable pointer to it.
    """
    cwd = Path.cwd()
    if not _inside_skill_tree(cwd):
        return cwd
    try:
        from cxone import default_env_file
        candidate = Path(env_file or default_env_file()).expanduser().resolve().parent
    except Exception:                                       # noqa: BLE001
        return None
    return candidate if not _inside_skill_tree(candidate) else None


def cmd_new(args) -> int:
    from cxone import get_version

    title = read_field(args.title)
    fields = {
        "use_case": read_field(args.use_case),
        "gap": read_field(args.gap),
        "scenario": read_field(args.scenario),
        "prompt": read_field(args.prompt),
        "proposed_cli": read_field(args.proposed_cli),
        "notes": read_field(args.notes),
    }

    if args.out:
        out_root = Path(args.out).expanduser().resolve()
    else:
        resolved = _default_out_root(args.env)
        if resolved is None:
            print("Refused: cannot pick a safe output directory. The current "
                  "directory is inside the skill folder, and no credentials "
                  "file outside it was found to infer your project directory "
                  "from.\nName one explicitly: --out <dir>.", file=sys.stderr)
            return 2
        out_root = resolved
    if _inside_skill_tree(out_root):
        print("Refused: won't write a feature-request bundle inside the skill "
              f"directory ({out_root}).\nThat folder is fast-forwarded by "
              "`selfcheck --sync` and staged by publish, so a bundle there is "
              "both at risk of being overwritten and at risk of being "
              "committed.\nWrite it to your own working directory instead "
              "(--out <dir>).", file=sys.stderr)
        return 2

    extra = [] if args.keep_tenant else _tenant_literals(args.env)

    cleaned: dict[str, str] = {}
    kinds: list[str] = []
    suspicious: list[str] = []
    for name, raw in fields.items():
        text, k, s = redact(raw, extra=extra)
        cleaned[name] = text
        kinds += k
        suspicious += s
    title_clean, k, s = redact(title, extra=extra)
    kinds += k
    suspicious += s

    if suspicious and not args.allow_unclassified:
        print("Refused: the supplied context contains long high-entropy "
              "string(s) that match no known credential shape, so they were "
              "neither redacted nor understood:", file=sys.stderr)
        for item in sorted(set(suspicious))[:5]:
            print(f"  {item[:12]}…{item[-4:]}  ({len(item)} chars)", file=sys.stderr)
        print("\nThis bundle is meant to be shared, so it is not written until "
              "that is resolved. Either remove the string from the context, or "
              "re-run with --allow-unclassified if you have confirmed it is "
              "not a secret.", file=sys.stderr)
        return 2

    patch, patch_desc = (None, "not included (--no-patch)") if args.no_patch \
        else build_patch()
    if patch:
        # Known-shape redaction applies to the patch — a JWT or PAT committed
        # into a diff is a real risk and is caught here.
        #
        # The unclassified-entropy BLOCK deliberately does not. That heuristic
        # exists for prose a human pasted, where an unknown-shaped secret can
        # plausibly hide. A patch is generated from tracked source in a git
        # repo, so it is dense with long identifiers and paths that the
        # heuristic cannot distinguish from secrets, and blocking on them would
        # make every real bundle require an override flag.
        patch, p_kinds, _ = redact(patch, extra=None)
        kinds += p_kinds
        if p_kinds:
            # Redaction inside a patch means the diff no longer matches the
            # author's source. That is the right trade when a real credential
            # was committed, but it must never be silent — the recipient is
            # about to apply this.
            patch_redacted = ", ".join(sorted(set(p_kinds)))
            patch_desc += f" — WARNING: {patch_redacted} redacted INSIDE the diff"

    version = get_version()
    capability = _capability_label()
    body = build_request_md(
        title=title_clean, use_case=cleaned["use_case"], gap=cleaned["gap"],
        scenario=cleaned["scenario"], prompt=cleaned["prompt"],
        proposed_cli=cleaned["proposed_cli"], notes=cleaned["notes"],
        version=version, capability=capability, patch_desc=patch_desc,
        redaction_kinds=kinds)

    bundle = out_root / "cxone-feature-requests" / f"{_dt.date.today().isoformat()}-{_slug(title)}"

    if args.dry_run:
        print(f"DRY-RUN — would write bundle to: {bundle}")
        print(f"  REQUEST.md   ({len(body)} bytes)")
        if patch:
            print(f"  change.patch ({len(patch)} bytes) — {patch_desc}")
        else:
            print(f"  (no patch: {patch_desc})")
        if kinds:
            print(f"  Redacted: {', '.join(sorted(set(kinds)))}")
        print("\n--- REQUEST.md ---")
        print(body)
        return 0

    try:
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "REQUEST.md").write_text(body, encoding="utf-8")
        if patch:
            (bundle / "change.patch").write_text(patch, encoding="utf-8")
    except OSError as exc:
        print(f"could not write bundle: {exc}", file=sys.stderr)
        return 1

    print(f"Feature request written: {bundle}")
    print(f"  REQUEST.md    the gap, use case, and context")
    if patch:
        print(f"  change.patch  {patch_desc}")
    else:
        print(f"  (no patch — {patch_desc})")
    if kinds:
        print(f"  Redacted before writing: {', '.join(sorted(set(kinds)))}")
    print("\nSend this folder to someone with write access to the repository.")
    return 0


def _capability_label() -> str:
    """The reporter's contribution level, for the bundle header.

    Tells the recipient why this arrived as a document rather than a PR.
    """
    try:
        import selfcheck
        st = selfcheck.check()
        selfcheck.probe_capability(st)
        return st.capability
    except Exception:                                       # noqa: BLE001
        return "unknown"


def cmd_list(args) -> int:
    # Same default as `new`, so `list` looks where `new` actually wrote.
    base = Path(args.out).expanduser().resolve() if args.out \
        else (_default_out_root(getattr(args, "env", None)) or Path.cwd())
    root = base / "cxone-feature-requests"
    if not root.is_dir():
        print(f"No feature requests found under {root}.")
        return 0
    found = sorted(p for p in root.iterdir() if p.is_dir())
    if not found:
        print(f"No feature requests found under {root}.")
        return 0
    print(f"{len(found)} feature request(s) in {root}:")
    for d in found:
        has_patch = "patch" if (d / "change.patch").is_file() else "no patch"
        print(f"  {d.name}  ({has_patch})")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="multitool feature-request",
        description="Capture a feature gap as a shareable handoff bundle, for "
                    "users who cannot publish to the repository themselves.")
    p.add_argument("--env", default=None)
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("new", help="write a feature-request bundle")
    n.add_argument("--title", required=True, help="one-line summary of the ask")
    n.add_argument("--use-case", required=True,
                   help="what the user is trying to accomplish, and why "
                        "(prefix @ to read from a file, '-' for stdin)")
    n.add_argument("--gap", required=True,
                   help="what the tool cannot do today")
    n.add_argument("--scenario", default=None,
                   help="how it came up — tenant shape, workflow, constraints")
    n.add_argument("--prompt", default=None,
                   help="the user's own phrasing of the request")
    n.add_argument("--proposed-cli", default=None,
                   help="suggested command shape, if one is obvious")
    n.add_argument("--notes", default=None,
                   help="implementation notes: endpoints, modules, gotchas")
    n.add_argument("--out", default=None,
                   help="parent directory for cxone-feature-requests/ "
                        "(default: current directory)")
    n.add_argument("--no-patch", action="store_true",
                   help="describe the gap only; skip the local diff")
    n.add_argument("--keep-tenant", action="store_true",
                   help="do not redact the tenant name from the bundle")
    n.add_argument("--allow-unclassified", action="store_true",
                   help="proceed despite high-entropy strings that matched no "
                        "known credential shape (confirm they are not secrets)")
    n.add_argument("--dry-run", action="store_true",
                   help="print the bundle instead of writing it")
    n.set_defaults(func=cmd_new)

    l = sub.add_parser("list", help="list bundles already written here")
    l.add_argument("--out", default=None)
    l.set_defaults(func=cmd_list)

    a = p.parse_args(argv if argv is not None else sys.argv[1:])
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
