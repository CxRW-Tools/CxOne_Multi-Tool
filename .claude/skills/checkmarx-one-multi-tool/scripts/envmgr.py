"""
Credential & .env management for the Multi-Tool (single tenant per chat/project).

Verbs:
  derive    Read-only: decode the API key and show the base URL + tenant it implies
            (so the user can confirm before anything is written).
  init      Write a single-tenant .env from the key (refuses to switch tenants
            unless --force). Optionally set a GitHub token.
  show      Print the current .env with secrets masked.
  set       Set a CXONE_* var (guards tenant/host changes).
  set-token Set an SCM token by provider (github/azure|ado/gitlab/bitbucket).

Typical chat flow (Claude in Claude Code / Cowork):
  user: "set up my tenant, key is eyJ..."
  -> env derive --api-key eyJ...        (show derived base URL + tenant, confirm)
  -> env init   --api-key eyJ... --yes  (write .env)
  user: "add my ADO token abc123"
  -> env set-token ado abc123
"""

from __future__ import annotations

import sys
import logging
import argparse
from getpass import getpass

import config_setup as cs
from cxone import default_env_file, is_inside_skill_dir

logger = logging.getLogger("cxone.env")


def _print_derived(info: dict) -> None:
    from cxone import get_version
    print(f"Derived from API key (Multi-Tool v{get_version()}):")
    print(f"  Tenant   : {info.get('tenant_name') or '(could not extract — please provide)'}")
    print(f"  Base URL : {info.get('base_url') or '(could not derive — please provide)'}")
    if info.get("iam_base_url"):
        print(f"  IAM URL  : {info['iam_base_url']}")


def cmd_derive(args) -> int:
    key = args.api_key or getpass("Checkmarx API key: ")
    info = cs.derive_tenant_info(key)
    _print_derived(info)
    if not (info.get("tenant_name") and info.get("base_url")):
        print("\nSome values couldn't be derived; pass --base-url / --tenant to `env init`.")
    return 0


def cmd_init(args) -> int:
    key = args.api_key or getpass("Checkmarx API key: ")
    info = cs.derive_tenant_info(key)
    _print_derived(info)
    base_url = args.base_url or info.get("base_url")
    tenant = args.tenant or info.get("tenant_name")
    if not (base_url and tenant):
        print("\nMissing base URL or tenant. Re-run with --base-url and/or --tenant.")
        return 1
    # Refuse to write credentials into the skill's own directory: it may be an
    # ephemeral copy (wiped between turns) and is shared across sessions, which is
    # exactly how two chats end up reading/writing the same .env. Require a
    # project-owned path instead — set once via CXONE_ENV_FILE or passed with --env.
    if is_inside_skill_dir(args.env):
        print(
            "\nRefused: won't write credentials inside the skill directory "
            f"({args.env}). That location is shared across chats and may be wiped "
            "between turns.\nName a project-owned file instead, e.g.:\n"
            "  export CXONE_ENV_FILE=\"$PWD/cxone.env\"   # then re-run `env init`\n"
            "  # or: env init --env /abs/path/to/project/cxone.env --api-key <KEY>"
        )
        return 2
    # Confirmation contract (shared with purge): --yes means "the operator already
    # confirmed". Without it, a TTY gets an interactive prompt; a NON-TTY must
    # REFUSE — silently proceeding would make --yes decorative in exactly the
    # environment this tool usually runs in (an assistant-driven shell).
    if not args.yes:
        if not sys.stdin.isatty():
            print(f"\nRefused: confirmation required to write {args.env}, but this "
                  "shell is non-interactive.\nConfirm the derived tenant/base URL "
                  "with the user, then re-run with --yes.")
            return 2
        if input(f"\nWrite this to {args.env}? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted."); return 1
    try:
        data = cs.init_env(args.env, key, github_token=args.github_token,
                           base_url=base_url, tenant=tenant, force=args.force)
    except cs.TenantConflict as exc:
        print(f"\nRefused: {exc}")
        return 2
    from cxone import get_version
    print(f"\nWrote {args.env} for tenant '{data['CXONE_TENANT']}' "
          f"({data['CXONE_BASE_URL']}).  ·  Multi-Tool v{get_version()}")
    return 0


def cmd_show(args) -> int:
    data = cs.read_env_file(args.env)
    if not data:
        print(f"No .env at {args.env}. Run: env init --api-key <key>")
        return 0
    secrets = {"CXONE_API_KEY", "CXONE_GITHUB_TOKEN", "CXONE_AZURE_TOKEN",
               "CXONE_GITLAB_TOKEN", "CXONE_BITBUCKET_TOKEN"}
    from cxone import get_version
    print(f"Tenant configured in {args.env} (Multi-Tool v{get_version()}):")
    for k, v in data.items():
        print(f"  {k} = {cs.mask_secret(v) if k in secrets else v}")
    return 0


def cmd_set(args) -> int:
    try:
        cs.set_var(args.env, args.key, args.value, force=args.force)
    except cs.TenantConflict as exc:
        print(f"Refused: {exc}"); return 2
    print(f"Set {args.key.upper()}.")
    return 0


def cmd_set_token(args) -> int:
    try:
        var = cs.set_token(args.env, args.provider, args.value)
    except ValueError as exc:
        print(str(exc)); return 1
    print(f"Set {var}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="env", description="Manage single-tenant credentials")
    p.add_argument("--env", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("derive"); d.add_argument("--api-key", default=None)
    i = sub.add_parser("init")
    i.add_argument("--api-key", default=None)
    i.add_argument("--github-token", default=None)
    i.add_argument("--base-url", default=None)
    i.add_argument("--tenant", default=None)
    i.add_argument("--yes", action="store_true", help="skip interactive confirmation")
    i.add_argument("--force", action="store_true", help="replace a different tenant")
    sub.add_parser("show")
    s = sub.add_parser("set"); s.add_argument("key"); s.add_argument("value")
    s.add_argument("--force", action="store_true")
    t = sub.add_parser("set-token"); t.add_argument("provider"); t.add_argument("value")

    args = p.parse_args(argv)
    # Resolve the concrete file: explicit --env wins, else CXONE_ENV_FILE, else .env.
    args.env = args.env or default_env_file()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return {
        "derive": cmd_derive, "init": cmd_init, "show": cmd_show,
        "set": cmd_set, "set-token": cmd_set_token,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
