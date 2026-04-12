from __future__ import annotations

import yaml
from pathlib import Path

from security_tools.runtime.models import RuntimeReport


DEFAULT = {
    "rules": {
        "block_on_container_exit": True,
        "block_if_no_readiness": True,
    }
}


def load_runtime_policy():
    path = Path("runtime_policy.yml")

    if not path.exists():
        return DEFAULT

    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return DEFAULT


def apply_runtime_policy(report: RuntimeReport, policy: dict):
    rules = policy.get("rules", {})

    if rules.get("block_on_container_exit"):
        if report.startup.container_running is False:
            report.verdict = "BLOCK"

    if rules.get("block_if_no_readiness"):
        if not report.listening_ports and not report.errors:
            report.verdict = "WARN"

    return report