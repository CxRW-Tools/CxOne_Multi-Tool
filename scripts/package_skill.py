#!/usr/bin/env python3
"""Package a skill directory under .claude/skills/ into a .skill zip for upload
to surfaces that require a packaged artifact (Claude.ai, Desktop, API skill
upload). Claude Code itself reads the unpacked directory directly and does
not need this.

Usage:
    python scripts/package_skill.py [skill-name]

If skill-name is omitted and exactly one skill exists under .claude/skills/,
that one is used.
"""
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
DIST_DIR = REPO_ROOT / "dist"

# Local runtime state and credentials. These are gitignored, so a CI build from
# a fresh checkout never sees them — but a LOCAL `package_skill.py` run zips the
# working directory as it stands, which is how one machine's state would
# otherwise ride along into a .skill someone else installs.
EXCLUDE_NAMES = {
    "__pycache__", ".venv", ".DS_Store", "Thumbs.db",
    ".env", "cxone.env", "cxone-identities.yaml", ".agent_state.json",
    ".selfcheck_state.json",
}
EXCLUDE_SUFFIXES = {".pyc", ".skill"}
EXCLUDE_PREFIXES = ("agent.log",)


def should_exclude(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return True
    if path.suffix in EXCLUDE_SUFFIXES:
        return True
    if path.name.startswith(EXCLUDE_PREFIXES):
        return True
    return False


def resolve_skill_dir(name: str | None) -> Path:
    if name:
        skill_dir = SKILLS_DIR / name
        if not skill_dir.is_dir():
            sys.exit(f"error: no skill directory at {skill_dir}")
        return skill_dir

    candidates = [p for p in SKILLS_DIR.iterdir() if p.is_dir()]
    if len(candidates) == 1:
        return candidates[0]
    sys.exit(
        f"error: multiple skills found under {SKILLS_DIR}, "
        f"specify one: {', '.join(p.name for p in candidates)}"
    )


def main() -> None:
    name_arg = sys.argv[1] if len(sys.argv) > 1 else None
    skill_dir = resolve_skill_dir(name_arg)
    skill_name = skill_dir.name

    version_file = skill_dir / "VERSION"
    version = version_file.read_text().strip() if version_file.exists() else "0.0.0"

    DIST_DIR.mkdir(exist_ok=True)
    out_path = DIST_DIR / f"{skill_name}-v{version}.skill"

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(skill_dir.rglob("*")):
            if path.is_dir():
                continue
            if any(should_exclude(part) for part in [path, *path.parents]):
                continue
            arcname = path.relative_to(skill_dir)
            zf.write(path, arcname)

    print(f"packaged {skill_name} v{version} -> {out_path}")


if __name__ == "__main__":
    main()
