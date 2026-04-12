from __future__ import annotations

import yaml
from pathlib import Path

from security_tools.runtime.models import RuntimeReport


DEFAULT_POLICY = {
    "timeouts": {
        "startup_seconds": 45,
    },
    "rules": {
        "block_on_container_exit": True,
        "block_if_no_readiness": True,
    },
}


def load_runtime_policy() -> dict:
    policy_path = Path("runtime_policy.yml")

    if not policy_path.exists():
        return DEFAULT_POLICY

    try:
        with open(policy_path, "r") as f:
            data = yaml.safe_load(f)

        return data or DEFAULT_POLICY

    except Exception:
        return DEFAULT_POLICY


def apply_runtime_policy(report: RuntimeReport, policy: dict) -> RuntimeReport:
    rules = policy.get("rules", {})

    if rules.get("block_on_container_exit"):
        if report.startup.container_running is False:
            report.verdict = "BLOCK"

    if rules.get("block_if_no_readiness"):
        if not report.listening_ports and not report.errors:
            if report.verdict == "PASS":
                report.verdict = "WARN"

    return report