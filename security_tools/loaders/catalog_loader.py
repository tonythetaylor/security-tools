from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

def _catalog_path() -> Path:
    return Path(__file__).resolve().parent.parent / "catalog" / "finding_catalog.yml"

@lru_cache(maxsize=1)
def load_finding_catalog() -> dict[str, Any]:
    path = _catalog_path()
    if not path.exists():
        raise FileNotFoundError(f"Finding catalog not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("Finding catalog must be a mapping")

    data.setdefault("default", {})
    data.setdefault("findings", {})
    data.setdefault("rules", {})
    return data