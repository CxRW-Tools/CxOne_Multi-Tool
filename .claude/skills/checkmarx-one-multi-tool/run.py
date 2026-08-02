#!/usr/bin/env python3
"""
Self-locating launcher for the Checkmarx One Multi-Tool.

Why this exists
---------------
The skill is staged in an ephemeral, per-session folder (on Windows, deep under
%APPDATA%\\...\\skills-plugin\\<guids>\\). Two things repeatedly broke direct
`python .../scripts/multitool.py ...` invocations:

  1. Stale path — the absolute path carries per-session GUIDs, so a path captured
     in one session may not exist in the next.
  2. Wrong interpreter — on Windows, the bare `python` often resolves to the
     Microsoft Store app-execution stub under
     %LOCALAPPDATA%\\Microsoft\\WindowsApps\\python.exe, which is sandboxed and
     can't open files under %APPDATA%\\...\\skills-plugin\\... .

This launcher removes both. It finds `scripts/multitool.py` relative to *its own*
location (so no path needs to be hardcoded or remembered), detects whether it's
running under the Store stub and re-executes under a real interpreter (`py -3`)
when one is available, then hands off to multitool with all arguments forwarded.

Usage (from anywhere — the launcher locates itself):
    python run.py welcome
    python run.py scan --project-names WebGoat --no-overrides
    py -3 run.py env derive --api-key <KEY>        # Windows, explicit real Python

If `python run.py` fails to start on Windows because `python` is the Store stub,
use `py -3 run.py ...` (the Python launcher, installed with python.org CPython),
or install python.org CPython so a real interpreter is first on PATH.
"""

from __future__ import annotations

import os
import sys
import runpy
import platform
import subprocess


# --- Locate ourselves and the real entry point ---------------------------------
# __file__ resolves to wherever this launcher actually lives *this session*, so we
# never depend on a remembered absolute path. multitool.py sits in scripts/ next
# to us.
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(HERE, "scripts")
MULTITOOL = os.path.join(SCRIPTS_DIR, "multitool.py")


def _is_windows_store_stub(executable: str) -> bool:
    """True if the current interpreter is the Windows Store app-execution alias.

    Those stubs live under ...\\Microsoft\\WindowsApps\\ and are sandboxed such
    that they can't reliably open files under %APPDATA%\\...\\skills-plugin\\... .
    """
    if platform.system() != "Windows":
        return False
    exe = (executable or "").replace("/", "\\").lower()
    return "\\microsoft\\windowsapps\\" in exe


def _find_real_python() -> list[str] | None:
    """Return a launch prefix for a genuine (non-stub) interpreter, or None.

    Prefers the Windows `py` launcher (`py -3`), which python.org CPython installs
    and which bypasses the Store alias. Falls back to `python3`/`python` on PATH
    if they resolve to something other than the stub.
    """
    import shutil

    py = shutil.which("py")
    if py and not _is_windows_store_stub(py):
        return [py, "-3"]

    for name in ("python3", "python"):
        cand = shutil.which(name)
        if cand and not _is_windows_store_stub(cand):
            return [cand]
    return None


def main() -> int:
    if not os.path.isfile(MULTITOOL):
        sys.stderr.write(
            "ERROR: could not find multitool.py next to this launcher.\n"
            f"  Launcher: {os.path.abspath(__file__)}\n"
            f"  Expected: {MULTITOOL}\n"
            "This launcher must stay in the skill root, with scripts/ beside it.\n"
        )
        return 2

    # If we were started by the Windows Store stub, re-exec under a real
    # interpreter so file access under %APPDATA% works. Guard against loops with
    # an env flag so we only ever re-exec once.
    if _is_windows_store_stub(sys.executable) and not os.environ.get("CXONE_RELAUNCHED"):
        real = _find_real_python()
        if real:
            env = dict(os.environ, CXONE_RELAUNCHED="1")
            cmd = real + [os.path.abspath(__file__)] + sys.argv[1:]
            sys.stderr.write(
                f"[run] Windows Store Python detected; re-running via: {' '.join(real)}\n"
            )
            return subprocess.call(cmd, env=env)
        sys.stderr.write(
            "[run] WARNING: running under the Windows Store Python stub and no real\n"
            "      interpreter (py -3 / python3) was found on PATH. If this fails to\n"
            "      open files, install python.org CPython or run: py -3 run.py ...\n"
        )

    # Make scripts/ importable (cxone, ops, etc. resolve as top-level modules,
    # exactly as when running multitool.py from inside scripts/), then hand off.
    if SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SCRIPTS_DIR)
    # multitool.py reads sys.argv[1:]; drop our own name so argv looks native.
    sys.argv = [MULTITOOL] + sys.argv[1:]
    # Running with run_name="__main__" triggers multitool's own
    # `sys.exit(main())`, which raises SystemExit. Catch it and return the code
    # so the propagation is explicit rather than an implicit exception fly-by
    # (previously an unreachable `return 0` sat here, implying codes were lost).
    try:
        runpy.run_path(MULTITOOL, run_name="__main__")
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else (0 if code is None else 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
