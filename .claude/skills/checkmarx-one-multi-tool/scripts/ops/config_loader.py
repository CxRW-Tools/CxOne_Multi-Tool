"""Load YAML rule configs (scan_rules.yaml / triage_rules.yaml) from the
skill's config/ directory. Falls back to an empty dict if absent."""
from pathlib import Path
import yaml

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def load_yaml_config(filename: str) -> dict:
    path = _CONFIG_DIR / filename
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}
