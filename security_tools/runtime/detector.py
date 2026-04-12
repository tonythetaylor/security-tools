from __future__ import annotations

from typing import Any

from security_tools.runtime.docker_introspect import derive_ports_from_image_inspect
from security_tools.runtime.models import RuntimeProfile
from security_tools.runtime.profiles.generic import generic_profile
from security_tools.runtime.profiles.nginx import nginx_profile
from security_tools.runtime.profiles.node_web import node_web_profile
from security_tools.runtime.profiles.python_web import python_web_profile
from security_tools.runtime.profiles.spring_boot import spring_boot_profile
from security_tools.runtime.profiles.tomcat import tomcat_profile


def detect_runtime_profile(
    image_inspect: dict[str, Any] | None = None,
    dockerfile_info: dict[str, Any] | None = None,
    repo_hint_info: dict[str, Any] | None = None,
) -> RuntimeProfile:
    image_inspect = image_inspect or {}
    dockerfile_info = dockerfile_info or {}
    repo_hint_info = repo_hint_info or {}

    ports = sorted(
        set(
            derive_ports_from_image_inspect(image_inspect)
            + dockerfile_info.get("exposed_ports", [])
        )
    )

    cfg = image_inspect.get("Config", {}) if isinstance(image_inspect, dict) else {}
    cmd_blob = " ".join(str(x) for x in (cfg.get("Cmd") or []))
    entry_blob = " ".join(str(x) for x in (cfg.get("Entrypoint") or []))
    raw = " ".join(dockerfile_info.get("base_images", []))
    raw = f"{raw} {dockerfile_info.get('entrypoint') or ''} {dockerfile_info.get('cmd') or ''} {cmd_blob} {entry_blob}".lower()

    if "nginx" in raw or repo_hint_info.get("has_nginx_conf"):
        return nginx_profile(ports)

    if "tomcat" in raw or "catalina" in raw or repo_hint_info.get("has_server_xml"):
        return tomcat_profile(ports)

    if (
        "spring" in raw
        or repo_hint_info.get("has_application_yml")
        or repo_hint_info.get("has_application_properties")
    ) and ("java" in raw or "jar" in raw):
        return spring_boot_profile(ports)

    if (
        any(token in raw for token in ["uvicorn", "gunicorn", "flask", "fastapi"])
        or repo_hint_info.get("has_requirements_txt")
    ):
        return python_web_profile(ports)

    if (
        "node" in raw
        or repo_hint_info.get("has_package_json")
        or "npm" in raw
        or "yarn" in raw
    ):
        return node_web_profile(ports)

    return generic_profile(ports)