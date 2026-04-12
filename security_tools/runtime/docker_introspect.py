from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def docker_available() -> bool:
    try:
        _run(["docker", "version"], check=True)
        return True
    except Exception:
        return False


def image_exists(image: str) -> bool:
    try:
        _run(["docker", "image", "inspect", image], check=True)
        return True
    except Exception:
        return False


def inspect_image(image: str) -> dict[str, Any]:
    cp = _run(["docker", "image", "inspect", image], check=True)
    data = json.loads(cp.stdout)
    if not isinstance(data, list) or not data:
        return {}
    first = data[0]
    return first if isinstance(first, dict) else {}


def parse_dockerfile(dockerfile_path: str | Path = "Dockerfile") -> dict[str, Any]:
    path = Path(dockerfile_path)
    if not path.exists():
        return {
            "base_images": [],
            "exposed_ports": [],
            "entrypoint": None,
            "cmd": None,
            "raw": "",
        }

    raw = path.read_text(encoding="utf-8", errors="ignore")
    base_images = re.findall(r"(?im)^\\s*FROM\\s+([^\\s]+)", raw)
    expose_matches = re.findall(r"(?im)^\\s*EXPOSE\\s+(.+)$", raw)

    exposed_ports: list[int] = []
    for line in expose_matches:
        for token in line.split():
            token = token.split("/")[0].strip()
            if token.isdigit():
                exposed_ports.append(int(token))

    entrypoint_match = re.search(r"(?im)^\\s*ENTRYPOINT\\s+(.+)$", raw)
    cmd_match = re.search(r"(?im)^\\s*CMD\\s+(.+)$", raw)

    return {
        "base_images": base_images,
        "exposed_ports": sorted(set(exposed_ports)),
        "entrypoint": entrypoint_match.group(1).strip() if entrypoint_match else None,
        "cmd": cmd_match.group(1).strip() if cmd_match else None,
        "raw": raw,
    }


def repo_hints(root: str | Path = ".") -> dict[str, Any]:
    root_path = Path(root)

    ignored_dir_names = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
        ".security-tools",
    }

    ignored_file_names = {
        "runtime-report.json",
        "runtime-summary.md",
    }

    file_names: set[str] = set()

    for path in root_path.rglob("*"):
        if any(part in ignored_dir_names for part in path.parts):
            continue
        if path.is_file():
            name = path.name.lower()
            if name in ignored_file_names:
                continue
            file_names.add(name)

    return {
        "has_package_json": "package.json" in file_names,
        "has_requirements_txt": "requirements.txt" in file_names,
        "has_nginx_conf": "nginx.conf" in file_names,
        "has_server_xml": "server.xml" in file_names,
        "has_application_yml": "application.yml" in file_names or "application.yaml" in file_names,
        "has_application_properties": "application.properties" in file_names,
        "file_names": sorted(file_names),
    }

def derive_ports_from_image_inspect(image_inspect: dict[str, Any]) -> list[int]:
    cfg = image_inspect.get("Config", {}) if isinstance(image_inspect, dict) else {}
    exposed = cfg.get("ExposedPorts", {}) if isinstance(cfg, dict) else {}
    ports: list[int] = []

    if isinstance(exposed, dict):
        for key in exposed.keys():
            token = str(key).split("/")[0]
            if token.isdigit():
                ports.append(int(token))

    return sorted(set(ports))