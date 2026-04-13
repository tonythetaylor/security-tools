from __future__ import annotations

from pathlib import Path

from security_tools.planning.models import StackDetection


def _exists(root: Path, *names: str) -> bool:
    return any((root / name).exists() for name in names)


def _glob_exists(root: Path, pattern: str) -> bool:
    return any(root.rglob(pattern))


def detect_stack(root: str | Path = ".") -> StackDetection:
    root = Path(root)

    has_dockerfile = _exists(root, "Dockerfile", "dockerfile")
    has_runtime_contract = _exists(root, "runtime-contract.yml")
    has_kubernetes = (
        _glob_exists(root, "*deployment*.yml")
        or _glob_exists(root, "*deployment*.yaml")
        or _exists(root, "k8s", "manifests")
        or _exists(root, "kustomization.yaml")
    )
    has_helm = _exists(root, "Chart.yaml") or _glob_exists(root, "Chart.yaml")
    has_terraform = _glob_exists(root, "*.tf")
    has_ansible = _glob_exists(root, "*.playbook.yml") or _glob_exists(root, "*.playbook.yaml") or _exists(root, "ansible")
    has_compose = _exists(root, "docker-compose.yml", "compose.yml")

    detection = StackDetection(
        has_dockerfile=has_dockerfile,
        has_runtime_contract=has_runtime_contract,
        has_kubernetes=has_kubernetes,
        has_helm=has_helm,
        has_terraform=has_terraform,
        has_ansible=has_ansible,
        has_compose=has_compose,
    )

    if _exists(root, "requirements.txt", "pyproject.toml", "Pipfile"):
        detection.languages.append("python")
    if _exists(root, "package.json"):
        detection.languages.append("node")
    if _exists(root, "pom.xml", "build.gradle", "build.gradle.kts"):
        detection.languages.append("java")

    if _exists(root, "package.json"):
        pkg = (root / "package.json").read_text(encoding="utf-8", errors="ignore").lower()
        if "react" in pkg:
            detection.frameworks.append("react")
        if "vite" in pkg:
            detection.frameworks.append("vite")
        if "express" in pkg:
            detection.frameworks.append("express")
        if "next" in pkg:
            detection.frameworks.append("nextjs")

    if _exists(root, "requirements.txt"):
        reqs = (root / "requirements.txt").read_text(encoding="utf-8", errors="ignore").lower()
        if "flask" in reqs:
            detection.frameworks.append("flask")
        if "fastapi" in reqs:
            detection.frameworks.append("fastapi")
        if "uvicorn" in reqs:
            detection.frameworks.append("uvicorn")
        if "django" in reqs:
            detection.frameworks.append("django")

    if _exists(root, "pom.xml", "build.gradle", "build.gradle.kts"):
        if _glob_exists(root, "server.xml"):
            detection.frameworks.append("tomcat")
        if _glob_exists(root, "application.yml") or _glob_exists(root, "application.properties"):
            detection.frameworks.append("spring")

    if has_dockerfile:
        detection.repo_types.append("containerized_application")
    if has_terraform or has_ansible or has_kubernetes or has_helm:
        detection.repo_types.append("deployment_or_iac")

    if "python" in detection.languages:
        detection.service_type = "python_web"
    if "node" in detection.languages and "react" in detection.frameworks:
        detection.service_type = "node_frontend"
    if "java" in detection.languages and "spring" in detection.frameworks:
        detection.service_type = "spring_boot"
    if "java" in detection.languages and "tomcat" in detection.frameworks:
        detection.service_type = "tomcat"

    if has_kubernetes or has_helm:
        detection.deploy_targets.append("kubernetes")
    if has_terraform:
        detection.deploy_targets.append("cloud_or_hybrid_iac")
    if has_ansible:
        detection.deploy_targets.append("onprem_or_vm_config")
    if has_compose:
        detection.deploy_targets.append("compose_local_or_server")
    if not detection.deploy_targets:
        detection.deploy_targets.append("unknown")

    detection.languages = sorted(set(detection.languages))
    detection.frameworks = sorted(set(detection.frameworks))
    detection.repo_types = sorted(set(detection.repo_types))
    detection.deploy_targets = sorted(set(detection.deploy_targets))

    return detection