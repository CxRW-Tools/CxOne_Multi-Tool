"""
Project scoping — which projects the autonomous agent is allowed to touch.

A demo tenant is rarely uniform: some projects are the demo, others are
scratch, a customer POV, or someone else's work that must not be scanned or
triaged. This narrows the agent's universe BEFORE planning, so out-of-scope
projects are never scheduled in the first place (rather than being planned and
then skipped, which would leave misleading events in the plan and the ledger).

Rules, in evaluation order:
  1. EXCLUDES ALWAYS WIN. If a project matches any exclude rule it is out,
     even if it also matches an include rule. This makes "everything tagged
     Demo except the Istio ones" expressible, and makes a mistake in an
     exclude rule fail safe (too few projects, never too many).
  2. If any INCLUDE rule is set, a project must match at least one to be in
     scope. With no include rules, everything not excluded is in scope.

Name patterns are case-insensitive and match as a SUBSTRING by default
("Istio" excludes "Istio - FAE" and "Istio - No FAE"), which is what people
mean by "projects with Istio in the name". A pattern containing a glob
metacharacter (`*`, `?`, `[`) is matched as a glob against the whole name
instead ("ShopWorthy/*", "*Goat").

Tag patterns are `key` (project carries that tag key, any value) or
`key:value` (both must match). Both sides are compared case-insensitively.
"""

from __future__ import annotations

import fnmatch
import logging

logger = logging.getLogger("cxone.scope")

_GLOB_CHARS = ("*", "?", "[")


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _split_list(value) -> list[str]:
    """Accept a comma-separated string OR an already-parsed list."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.split(",")
    else:
        parts = list(value)
    return [str(p).strip() for p in parts if str(p).strip()]


def matches_name(pattern: str, name: str) -> bool:
    """Glob if the pattern looks like one, else case-insensitive substring."""
    pat, target = _norm(pattern), _norm(name)
    if not pat:
        return False
    if any(ch in pat for ch in _GLOB_CHARS):
        return fnmatch.fnmatch(target, pat)
    return pat in target


def matches_tag(pattern: str, tags: dict | None) -> bool:
    """`key` = has that tag key (any value); `key:value` = both must match."""
    pat = (pattern or "").strip()
    if not pat:
        return False
    tags = tags or {}
    if ":" in pat:
        key, val = pat.split(":", 1)
        key, val = _norm(key), _norm(val)
        return any(_norm(k) == key and _norm(v) == val for k, v in tags.items())
    return any(_norm(k) == _norm(pat) for k in tags)


class ProjectScope:
    """Include/exclude filter over project records ({name, tags, ...})."""

    def __init__(self, include_names=None, exclude_names=None,
                 include_tags=None, exclude_tags=None):
        self.include_names = _split_list(include_names)
        self.exclude_names = _split_list(exclude_names)
        self.include_tags = _split_list(include_tags)
        self.exclude_tags = _split_list(exclude_tags)

    @property
    def active(self) -> bool:
        return bool(self.include_names or self.exclude_names
                    or self.include_tags or self.exclude_tags)

    def allows(self, project: dict) -> bool:
        name = project.get("name") or ""
        tags = project.get("tags") or {}
        # 1. Excludes win outright.
        if any(matches_name(p, name) for p in self.exclude_names):
            return False
        if any(matches_tag(p, tags) for p in self.exclude_tags):
            return False
        # 2. Any include rule present -> must match at least one.
        if self.include_names or self.include_tags:
            return (any(matches_name(p, name) for p in self.include_names)
                    or any(matches_tag(p, tags) for p in self.include_tags))
        return True

    def apply(self, projects: list[dict], log: logging.Logger | None = None) -> list[dict]:
        """Filter, logging what the scope did. Selecting NOTHING out of a
        non-empty tenant is treated as a configuration error and logged at
        ERROR: the agent would otherwise idle forever with no explanation."""
        log = log or logger
        if not self.active:
            return projects
        kept = [p for p in projects if self.allows(p)]
        dropped = len(projects) - len(kept)
        if projects and not kept:
            log.error(
                "Project scope matched 0 of %d project(s) — the agent would have "
                "nothing to do. Check the scope: %s", len(projects), self.describe())
        else:
            log.info("Project scope: %d of %d project(s) in scope (%d filtered out) — %s",
                     len(kept), len(projects), dropped, self.describe())
            if kept:
                log.debug("In scope: %s", ", ".join(sorted(
                    (p.get("name") or p.get("id") or "?") for p in kept)))
        return kept

    def describe(self) -> str:
        bits = []
        if self.include_names:
            bits.append("include names %s" % self.include_names)
        if self.include_tags:
            bits.append("include tags %s" % self.include_tags)
        if self.exclude_names:
            bits.append("exclude names %s" % self.exclude_names)
        if self.exclude_tags:
            bits.append("exclude tags %s" % self.exclude_tags)
        return "; ".join(bits) if bits else "no filters (all projects)"

    def as_cli_args(self) -> list[str]:
        """Re-emit as CLI flags, so a host-side scope can be forwarded into the
        container verbatim (the image carries its own activity.yaml, which
        would otherwise not know about flags given on the host)."""
        out: list[str] = []
        for flag, values in (("--include-projects", self.include_names),
                             ("--exclude-projects", self.exclude_names),
                             ("--include-tags", self.include_tags),
                             ("--exclude-tags", self.exclude_tags)):
            if values:
                out += [flag, ",".join(values)]
        return out

    @classmethod
    def resolve(cls, cli: dict | None = None, env: dict | None = None,
                config: dict | None = None) -> "ProjectScope":
        """Build from CLI flags > env vars > activity.yaml, per field.

        Resolution is PER FIELD, not all-or-nothing: `--exclude-projects` on the
        command line overrides only the excluded names, leaving any configured
        include rules in place.
        """
        cli, env, config = cli or {}, env or {}, config or {}
        env_keys = {
            "include_names": "CXONE_AGENT_INCLUDE_PROJECTS",
            "exclude_names": "CXONE_AGENT_EXCLUDE_PROJECTS",
            "include_tags": "CXONE_AGENT_INCLUDE_TAGS",
            "exclude_tags": "CXONE_AGENT_EXCLUDE_TAGS",
        }
        resolved = {}
        for field, env_key in env_keys.items():
            if cli.get(field):
                resolved[field] = cli[field]
            elif env.get(env_key):
                resolved[field] = env[env_key]
            else:
                resolved[field] = config.get(field)
        return cls(**resolved)
