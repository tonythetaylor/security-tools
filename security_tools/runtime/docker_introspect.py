from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=True)


def docker_available() -> bool:
    try:
        _run(["docker", "version"])
        return True
    except Exception:
        return False


def image_exists(image: str) -> bool:
    try:
        _run(["docker", "image", "inspect", image])
        return True
    except Exception:
        return False


def inspect_image(image: str) -> dict:
    cp = _run(["docker", "image", "inspect", image])
    data = json.loads(cp.stdout)
    return data[0] if data else {}


def parse_dockerfile(path: str = "Dockerfile") -> dict:
    dockerfile = Path(path)

    if not dockerfile.exists():
        return {
            "base_images": [],
            "exposed_ports": [],
            "entrypoint": None,
            "cmd": None,
            "raw": "",
        }

    raw = dockerfile.read_text()

    base_images = re.findall(r"^FROM\s+([^\s]+)", raw, re.MULTILINE)

    exposed_ports = []
    for match in re.findall(r"^EXPOSE\s+(.+)", raw, re.MULTILINE):
        for port in match.split():
            try:
                exposed_ports.append(int(port.split("/")[0]))
            except Exception:
                pass

    entrypoint_match = re.search(r"^ENTRYPOINT\s+(.+)", raw, re.MULTILINE)
    cmd_match = re.search(r"^CMD\s+(.+)", raw, re.MULTILINE)

    return {
        "base_images": base_images,
        "exposed_ports": sorted(set(exposed_ports)),
        "entrypoint": entrypoint_match.group(1) if entrypoint_match else None,
        "cmd": cmd_match.group(1) if cmd_match else None,
        "raw": raw,
    }


def repo_hints(context_dir: str = ".") -> dict:
    hints = {
        "has_package_json": False,
        "has_requirements_txt": False,
        "has_nginx_conf": False,
        "has_server_xml": False,
        "has_application_yml": False,
        "has_application_properties": False,
        "file_names": [],
    }

    ignore_dirs = {
        ".git",
        ".security-tools",
        ".venv",
        "__pycache__",
        ".pytest_cache",
    }

    for root, dirs, files in os.walk(context_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for f in files:
            hints["file_names"].append(f)

            if f == "package.json":
                hints["has_package_json"] = True

            if f == "requirements.txt":
                hints["has_requirements_txt"] = True

            if f == "nginx.conf":
                hints["has_nginx_conf"] = True

            if f == "server.xml":
                hints["has_server_xml"] = True

            if f == "application.yml":
                hints["has_application_yml"] = True

            if f == "application.properties":
                hints["has_application_properties"] = True

    hints["file_names"] = sorted(set(hints["file_names"]))
    return hints