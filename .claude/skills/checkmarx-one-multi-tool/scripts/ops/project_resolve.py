"""Shared diagnostics for project-name resolution.

Every project-name lookup in this tool (scan, scan status, triage, results)
ends the same way: some requested names don't match anything in the fetched
project list, and we log a warning per unmatched name. But "this one name
didn't match" and "the WHOLE fetched list came back empty" are different
problems that look identical from inside a per-name loop — and only one of
them means the name is actually wrong.

Live-observed case (cnf26, 2026-07): two secondary identities (agent
personas registered via cxone-identities.yaml) had their JWTs decode fine
and carry the expected roles_ast, yet GET /api/projects returned
{"totalCount": 0, "projects": null} for both — an authorization/visibility
problem on the account, not a naming problem. Every scan/triage event for
~21 hours logged "Project not found: 'ShopWorthy/frontend'" (and others) as
if each name were individually wrong, which sent troubleshooting toward
"did someone rename/delete these projects?" instead of "why does this
identity see zero projects?" — the real question, answerable in one command
(`project list --as <identity>`) instead of an hour of dead ends.
"""

import logging


def warn_unresolved_projects(
    logger: logging.Logger,
    requested_names: list[str],
    all_projects: list[dict],
    found_names: set[str],
) -> None:
    """Warn about names in `requested_names` not present in `found_names`
    (both already lowercased by the caller). If `all_projects` is empty,
    emit ONE diagnostic pointing at an authorization/visibility problem
    instead of N misleading per-name "not found" warnings — a valid,
    correctly-scoped token can still see zero projects if something changed
    access server-side, and that's a very different fix than a typo'd name.
    """
    unresolved = [n for n in requested_names if n.lower() not in found_names]
    if not unresolved:
        return
    if not all_projects:
        logger.warning(
            "0 projects visible to this identity/token at all — %d requested "
            "name(s) %s could NOT be checked against anything, and this is "
            "almost certainly NOT a naming problem. If this identity worked "
            "before, something changed its project visibility server-side "
            "(the 'Acting as identity' line above this shows which one). "
            "Verify with `project list --as <identity>` (or plain `project "
            "list` for the primary key) before assuming any of these names "
            "are wrong.",
            len(unresolved), unresolved,
        )
        return
    for name in unresolved:
        logger.warning("Project not found: '%s'", name)
