from __future__ import annotations

import yaml
from pathlib import Path


def load_runtime_contract() -> dict:
    path = Path("runtime-contract.yml")

    if not path.exists():
        return {}

    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def merge_contract(profile, contract: dict):
    if not contract:
        return profile

    service = contract.get("service", {})
    readiness = service.get("readiness", {})
    startup = service.get("startup", {})

    if startup.get("port"):
        profile.expected_ports = [startup["port"]]
        profile.candidate_http_ports = [startup["port"]]

    if readiness.get("http_paths"):
        profile.candidate_http_paths = readiness["http_paths"]

    return profile