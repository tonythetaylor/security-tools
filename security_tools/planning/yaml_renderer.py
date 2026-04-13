from __future__ import annotations

from security_tools.planning.models import ScanPlan


def render_child_pipeline(plan: ScanPlan) -> str:
    lines: list[str] = []

    lines.append("include:")
    lines.append('  - local: "/templates/base/security-rules.yml"')
    lines.append("")

    lines.append("stages:")
    lines.append("  - security")
    lines.append("  - review")
    lines.append("")

    if "dependency_scan" in plan.jobs:
        lines.append("dependency_scan:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/scans/dependency-scan.yml" } ], strategy: depend }')
        lines.append("")

    if "secret_detection" in plan.jobs:
        lines.append("secret_detection:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/scans/secret-detection.yml" } ], strategy: depend }')
        lines.append("")

    if "container_scanning" in plan.jobs:
        lines.append("container_scanning:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/scans/container-scanning.yml" } ], strategy: depend }')
        lines.append("")

    if "dockerfile_scan" in plan.jobs:
        lines.append("dockerfile_scan:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/scans/dockerfile-scan.yml" } ], strategy: depend }')
        lines.append("")

    if "iac_scanning" in plan.jobs:
        lines.append("iac_scanning:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/scans/iac-scanning.yml" } ], strategy: depend }')
        lines.append("")

    if "container_runtime_verify" in plan.jobs:
        lines.append("container_runtime_verify:")
        lines.append("  extends: .security_base")
        lines.append("  stage: security")
        lines.append('  trigger: { include: [ { local: "/templates/runtime/container-runtime-verify.yml" } ], strategy: depend }')
        lines.append("")

    lines.append("security_review:")
    lines.append("  extends: .security_base")
    lines.append("  stage: review")
    lines.append('  trigger: { include: [ { local: "/templates/review/security-review.yml" } ], strategy: depend }')
    lines.append("")

    return "\n".join(lines)