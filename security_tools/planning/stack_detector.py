from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from security_tools.planning.models import StackDetection


EXCLUDED_DIRS = {
    ".git",
    ".security-tools",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".idea",
    ".vscode",
}


def _exists(root: Path, *names: str) -> bool:
    return any((root / name).exists() for name in names)


def _walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        current = Path(dirpath)
        for filename in filenames:
            yield current / filename


def _glob_exists(root: Path, pattern: str) -> bool:
    pattern = pattern.lower()
    for path in _walk_files(root):
        if fnmatch.fnmatch(path.name.lower(), pattern):
            return True
    return False


def _read_if_exists(root: Path, *names: str) -> str:
    for name in names:
        path = root / name
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8", errors="ignore")
    return ""


def detect_stack(root: str | Path = ".") -> StackDetection:
    root = Path(root)

    has_dockerfile = _exists(root, "Dockerfile", "dockerfile")
    has_runtime_contract = _exists(root, "runtime-contract.yml", "runtime-contract.yaml")

    has_kubernetes = (
        _glob_exists(root, "*deployment*.yml")
        or _glob_exists(root, "*deployment*.yaml")
        or _exists(root, "k8s", "manifests")
        or _exists(root, "kustomization.yaml", "kustomization.yml")
    )
    has_helm = _exists(root, "Chart.yaml") or _glob_exists(root, "Chart.yaml")
    has_terraform = _glob_exists(root, "*.tf")
    has_ansible = (
        _glob_exists(root, "*.playbook.yml")
        or _glob_exists(root, "*.playbook.yaml")
        or _exists(root, "ansible")
    )
    has_compose = _exists(
        root,
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    )

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
    if _exists(root, "go.mod"):
        detection.languages.append("go")
    if _exists(root, "Gemfile"):
        detection.languages.append("ruby")
    if _exists(root, "composer.json"):
        detection.languages.append("php")

    package_json = _read_if_exists(root, "package.json").lower()
    if package_json:
        if "react" in package_json:
            detection.frameworks.append("react")
        if "vite" in package_json:
            detection.frameworks.append("vite")
        if '"next"' in package_json or "next" in package_json:
            detection.frameworks.append("nextjs")
        if "express" in package_json:
            detection.frameworks.append("express")
        if "nestjs" in package_json:
            detection.frameworks.append("nestjs")

    python_deps = (
        _read_if_exists(root, "requirements.txt", "Pipfile").lower()
        + "\n"
        + _read_if_exists(root, "pyproject.toml").lower()
    )
    if python_deps:
        if "flask" in python_deps:
            detection.frameworks.append("flask")
        if "fastapi" in python_deps:
            detection.frameworks.append("fastapi")
        if "uvicorn" in python_deps:
            detection.frameworks.append("uvicorn")
        if "django" in python_deps:
            detection.frameworks.append("django")

    if "java" in detection.languages:
        if _glob_exists(root, "server.xml"):
            detection.frameworks.append("tomcat")
        if _glob_exists(root, "application.yml") or _glob_exists(root, "application.properties"):
            detection.frameworks.append("spring")

    if has_dockerfile:
        detection.repo_types.append("containerized_application")
    if has_terraform or has_ansible or has_kubernetes or has_helm:
        detection.repo_types.append("deployment_or_iac")
    if not detection.repo_types:
        detection.repo_types.append("application_only")

    if "python" in detection.languages:
        if "fastapi" in detection.frameworks:
            detection.service_type = "fastapi_service"
        elif "django" in detection.frameworks:
            detection.service_type = "django_service"
        else:
            detection.service_type = "python_web"

    if "node" in detection.languages and "react" in detection.frameworks:
        detection.service_type = "node_frontend"
    elif "node" in detection.languages and ("express" in detection.frameworks or "nestjs" in detection.frameworks):
        detection.service_type = "node_service"

    if "java" in detection.languages and "spring" in detection.frameworks:
        detection.service_type = "spring_boot"
    elif "java" in detection.languages and "tomcat" in detection.frameworks:
        detection.service_type = "tomcat"

    if has_kubernetes or has_helm:
        detection.deploy_targets.append("kubernetes")
    if has_terraform:
        detection.deploy_targets.append("cloud_or_hybrid_iac")
    if has_ansible:
        detection.deploy_targets.append("onprem_or_vm_config")
    if has_compose:
        detection.deploy_targets.append("compose_local_or_server")
    if has_dockerfile:
        detection.deploy_targets.append("container_runtime")
    if not detection.deploy_targets:
        detection.deploy_targets.append("unknown")

    detection.languages = sorted(set(detection.languages))
    detection.frameworks = sorted(set(detection.frameworks))
    detection.repo_types = sorted(set(detection.repo_types))
    detection.deploy_targets = sorted(set(detection.deploy_targets))

    return detection