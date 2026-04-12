from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from security_tools.runtime.models import RuntimeReport


def load_runtime_policy() -> dict[str, Any]:
    path = Path(__file__).resolve().parent.parent / "catalog" / "runtime_policy.yml"
    if not path.exists():
        return {
            "timeouts": {"startup_seconds": 45},
            "verdict_rules": {
                "block_on_container_exit": True,
                "block_if_no_ports_and_no_http_success": False,
                "warn_if_profile_unknown": True,
            },
        }

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return data if isinstance(data, dict) else {}


def apply_runtime_policy(report: RuntimeReport, policy: dict[str, Any]) -> RuntimeReport:
    verdict_rules = policy.get("verdict_rules", {}) if isinstance(policy, dict) else {}

    if report.errors:
        report.verdict = "BLOCK"

    if report.startup.container_started and not report.startup.container_running:
        if verdict_rules.get("block_on_container_exit", True):
            report.verdict = "BLOCK"
            if "Container exited during startup validation." not in report.errors:
                report.errors.append("Container exited during startup validation.")

    http_pass = any(check.status == "PASS" for check in report.http_checks)
    port_pass = any(check.status == "PASS" for check in report.port_checks)

    if not http_pass and not port_pass and verdict_rules.get(
        "block_if_no_ports_and_no_http_success", False
    ):
        report.verdict = "BLOCK"
        report.errors.append("No successful port or HTTP readiness checks.")

    if report.profile.name == "generic" and verdict_rules.get("warn_if_profile_unknown", True):
        if report.verdict == "PASS":
            report.verdict = "WARN"
        report.warnings.append(
            "Generic runtime profile used; stack-specific validation was limited."
        )

    return report