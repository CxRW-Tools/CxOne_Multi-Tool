"""Base class for scan/triage operations (ported from v2)."""
import copy
import logging
from argparse import Namespace


class Operation:
    def __init__(self, config, auth, api, logger: logging.Logger,
                 identity_selector=None):
        self.config = config
        self.auth = auth
        self.api = api
        self.logger = logger
        # Set for the AUTOMATIC --as specs (auto/random, ±secondary): resolves the
        # acting identity PER PROJECT rather than once per invocation. None means a
        # single fixed identity for the run (primary, or an explicitly named one).
        self.identity_selector = identity_selector

    def execute(self, args: Namespace) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------ identity
    def acting_for(self, project_name: str) -> tuple["Operation", str | None]:
        """(operation view bound to that project's identity, identity name).

        Returns a SHALLOW COPY with `api`/`auth` swapped, so every `self.api` call
        in the per-project code path attributes to the right user without
        threading a client argument through a few dozen call sites. The copy is
        safe because operations hold only read-only state once execute() has set
        it up (rules, realism model, seed) — per-project state (budgets,
        summaries) is created inside the per-project call and returned, never
        accumulated on the instance.

        With no selector this returns (self, None) — byte-identical behavior to
        single-identity runs.
        """
        if self.identity_selector is None:
            return self, None
        client, name = self.identity_selector.for_key(project_name)
        # Always announce the owner while a selector is active — including
        # 'primary'. Suppressing primary would print a partial ownership map and
        # read as "this project had no owner" rather than "the admin owns it".
        self.logger.info("[%s] acting as identity '%s'", project_name, name)
        bound = copy.copy(self)
        bound.api = client
        bound.auth = getattr(client, "auth", self.auth)
        return bound, name
