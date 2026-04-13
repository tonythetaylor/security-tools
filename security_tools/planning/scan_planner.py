from __future__ import annotations

from security_tools.planning.models import ScanPlan, StackDetection


def build_scan_plan(detected: StackDetection) -> ScanPlan:
    jobs: list[str] = []

    jobs.append("secret_detection")

    if any(lang in detected.languages for lang in ["python", "node", "java"]):
        jobs.append("dependency_scan")

    if detected.has_dockerfile:
        jobs.append("dockerfile_scan")
        jobs.append("container_scanning")

    if detected.has_terraform or detected.has_kubernetes or detected.has_helm or detected.has_ansible:
        jobs.append("iac_scanning")

    if detected.has_dockerfile and (
        detected.has_runtime_contract or detected.service_type != "unknown"
    ):
        jobs.append("container_runtime_verify")

    jobs.append("security_review")

    jobs = list(dict.fromkeys(jobs))
    return ScanPlan(detected=detected, jobs=jobs)