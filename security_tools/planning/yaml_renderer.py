from __future__ import annotations

from security_tools.planning.models import ScanPlan


def _include_block(file_path: str) -> list[str]:
    return [
        '  - project: "root/security-tools"',
        '    ref: "main"',
        f'    file: "{file_path}"',
    ]


def render_child_pipeline(plan: ScanPlan) -> str:
    lines: list[str] = []

    lines.append("include:")

    if "dependency_scan" in plan.jobs:
        lines.extend(_include_block("/templates/scans/dependency-scan.yml"))

    if "secret_detection" in plan.jobs:
        lines.extend(_include_block("/templates/scans/secret-detection.yml"))

    if "container_scanning" in plan.jobs:
        lines.extend(_include_block("/templates/scans/container-scanning.yml"))

    if "dockerfile_scan" in plan.jobs:
        lines.extend(_include_block("/templates/scans/dockerfile-scan.yml"))

    if "iac_scanning" in plan.jobs:
        lines.extend(_include_block("/templates/scans/iac-scanning.yml"))

    if "container_runtime_verify" in plan.jobs:
        lines.extend(_include_block("/templates/runtime/container-runtime-verify.yml"))
    
    if "sast" in plan.jobs:
        lines.extend(_include_block("/templates/scans/sast.yml"))

    lines.extend(_include_block("/templates/review/security-review.yml"))
    lines.append("")
    lines.append("stages:")
    lines.append("  - security")
    lines.append("  - review")
    lines.append("")

    return "\n".join(lines)