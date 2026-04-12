from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

def _policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "catalog" / "policy.yml"

@lru_cache(maxsize=1)
def load_policy() -> dict[str, Any]:
    path = _policy_path()
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("Policy file must be a mapping")

    data.setdefault("required_scans", {})
    data.setdefault("verdict_rules", {})
    return data