"""
Manage the multi-identity pool (secondary API keys used to attribute scans and
triage to different users — see cxone/identity_pool.py for the file format).

Read-only:
  identities list                    show registered identities (masked keys)
  identities test                    authenticate each identity and report
Writes the sidecar (validated; foreign-tenant keys refused; skill-dir refused):
  identities add --api-key <KEY> [--name X] [--replace]   register one ('-' = stdin)
  identities remove <name>                                unregister one
  identities import --file <path> [--replace]             bulk: sidecar-format
                                     YAML/JSON, or plain text one key per line
"""

from __future__ import annotations

import sys
import logging
import argparse

from cxone import CxConfig
from cxone.identity_pool import (IdentityPool, PRIMARY, add_identity,
                                 remove_identity, import_identities)
import config_setup as cs

logger = logging.getLogger("cxone.identities")


def cmd_list(pool: IdentityPool) -> int:
    path = pool.sidecar_path()
    print(f"Identities file: {path if path else '(unresolvable — no env file source)'}"
          f"{'' if path and path.is_file() else '  [not present]' if path else ''}")
    print(f"  {PRIMARY:<20} key={cs.mask_secret(pool.cfg.api_key)}  (from cxone.env)")
    for name in pool.names(include_primary=False):
        ident = pool.identity(name)
        print(f"  {name:<20} key={cs.mask_secret(ident.api_key)}  user_id={ident.user_id or '?'}")
    if not pool.has_secondaries():
        print("  (no secondary identities registered — scans/triage all run as "
              "primary; add entries to the identities file to enable --as)")
    return 0


def cmd_test(pool: IdentityPool) -> int:
    """Authenticate every identity. Failures don't abort — report all."""
    failures = 0
    for name in pool.names():
        try:
            client = pool.client_for(name)
            # FallbackClient would mask a secondary auth failure by falling back,
            # so for the TEST we go to the underlying client's auth directly.
            raw = getattr(client, "_secondary", client)
            raw.auth.token()
            print(f"  {name:<20} OK")
        except Exception as exc:
            failures += 1
            print(f"  {name:<20} FAILED — {type(exc).__name__}: {exc}")
    if failures:
        print(f"{failures} identit{'y' if failures == 1 else 'ies'} failed to "
              "authenticate — their keys are expired, revoked, or wrong-tenant.")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="identities",
                                description="Inspect and manage secondary identities")
    p.add_argument("--env", default=None)
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show registered identities")
    sub.add_parser("test", help="authenticate each identity and report")
    ap = sub.add_parser("add", help="validate and register one identity")
    ap.add_argument("--api-key", required=True,
                    help="the user's API key; pass '-' to read it from stdin "
                         "(keeps it out of shell history)")
    ap.add_argument("--name", default=None,
                    help="label; derived from the key's JWT if omitted")
    ap.add_argument("--replace", action="store_true",
                    help="overwrite an existing same-name entry's key")
    rp = sub.add_parser("remove", help="unregister an identity by name")
    rp.add_argument("name")
    ip = sub.add_parser("import", help="bulk-register from a file")
    ip.add_argument("--file", required=True,
                    help="sidecar-format YAML/JSON, or plain text one key per line")
    ip.add_argument("--replace", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)

    if args.cmd == "add":
        key = args.api_key
        if key == "-":
            key = sys.stdin.readline().strip()
            if not key:
                print("error: no API key on stdin", file=sys.stderr)
                return 2
        try:
            name = add_identity(cfg, key, args.name, replace=args.replace)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Registered identity '{name}'. Verify with: identities test")
        return 0
    if args.cmd == "remove":
        try:
            removed = remove_identity(cfg, args.name)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Identity '{args.name}' {'removed' if removed else 'not found'}.")
        return 0 if removed else 1
    if args.cmd == "import":
        try:
            added, errors = import_identities(cfg, args.file, replace=args.replace)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for name in added:
            print(f"Registered identity '{name}'.")
        for err in errors:
            print(f"skipped: {err}", file=sys.stderr)
        print(f"Imported {len(added)} identit{'y' if len(added) == 1 else 'ies'}"
              f"{f', {len(errors)} skipped' if errors else ''}."
              f"{' Verify with: identities test' if added else ''}")
        return 0 if added and not errors else (1 if errors else 0)

    pool = IdentityPool(cfg)
    return cmd_list(pool) if args.cmd == "list" else cmd_test(pool)


if __name__ == "__main__":
    sys.exit(main())
