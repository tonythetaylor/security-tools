from __future__ import annotations

import json
import random
import subprocess
import time

from security_tools.runtime.detector import detect_runtime_profile
from security_tools.runtime.docker_introspect import (
    docker_available,
    image_exists,
    inspect_image,
    parse_dockerfile,
    repo_hints,
)
from security_tools.runtime.models import RuntimeReport, RuntimeStartup
from security_tools.runtime.policy import apply_runtime_policy, load_runtime_policy
from security_tools.runtime.probes import http_check, wait_for_tcp


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def _tail_container_logs(container_name: str, lines: int = 200) -> str:
    try:
        cp = _run(["docker", "logs", "--tail", str(lines), container_name], check=False)
        combined = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        return combined.strip()
    except Exception as exc:
        return f"<failed to get logs: {exc}>"


def _container_running(container_name: str) -> tuple[bool, int | None]:
    try:
        cp = _run(["docker", "inspect", container_name], check=True)
        data = json.loads(cp.stdout)
        state = data[0].get("State", {}) if isinstance(data, list) and data else {}
        return bool(state.get("Running")), state.get("ExitCode")
    except Exception:
        return False, None


def _container_ip(container_name: str) -> str | None:
    try:
        cp = _run(["docker", "inspect", container_name], check=True)
        data = json.loads(cp.stdout)
        if not isinstance(data, list) or not data:
            return None

        networks = data[0].get("NetworkSettings", {}).get("Networks", {})
        if isinstance(networks, dict):
            for _, cfg in networks.items():
                ip = cfg.get("IPAddress")
                if ip:
                    return str(ip)

        return None
    except Exception:
        return None


def _cleanup(container_name: str) -> None:
    _run(["docker", "rm", "-f", container_name], check=False)


def _build_if_missing(
    image: str,
    dockerfile_path: str = "Dockerfile",
    context_dir: str = ".",
) -> None:
    if image_exists(image):
        return
    _run(["docker", "build", "-t", image, "-f", dockerfile_path, context_dir], check=True)


def run_runtime_verification(
    image: str,
    startup_timeout_seconds: int = 45,
    dockerfile_path: str = "Dockerfile",
    context_dir: str = ".",
    build_if_missing: bool = True,
) -> RuntimeReport:
    if not docker_available():
        return RuntimeReport(
            verdict="OPERATIONAL_ERROR",
            image=image,
            profile=detect_runtime_profile(),
            startup=RuntimeStartup(),
            errors=["Docker CLI is not available in the execution environment."],
        )

    if build_if_missing:
        try:
            _build_if_missing(image, dockerfile_path=dockerfile_path, context_dir=context_dir)
        except Exception as exc:
            return RuntimeReport(
                verdict="OPERATIONAL_ERROR",
                image=image,
                profile=detect_runtime_profile(),
                startup=RuntimeStartup(),
                errors=[f"Failed to build image: {exc}"],
            )

    try:
        image_inspect = inspect_image(image)
    except Exception as exc:
        return RuntimeReport(
            verdict="OPERATIONAL_ERROR",
            image=image,
            profile=detect_runtime_profile(),
            startup=RuntimeStartup(),
            errors=[f"Failed to inspect image: {exc}"],
        )

    dockerfile_info = parse_dockerfile(dockerfile_path)
    repo_hint_info = repo_hints(context_dir)
    profile = detect_runtime_profile(image_inspect, dockerfile_info, repo_hint_info)
    policy = load_runtime_policy()
    startup_timeout_seconds = int(
        policy.get("timeouts", {}).get("startup_seconds", startup_timeout_seconds)
    )

    container_name = f"runtime-verify-{random.randint(10000, 99999)}"

    # Bind only the most likely ports instead of every guessed port.
    port_args: list[str] = []
    candidate_ports = sorted(set(profile.candidate_http_ports or profile.expected_ports))
    for port in candidate_ports[:2]:
        if 1 <= port <= 65535:
            port_args += ["-p", f"{port}:{port}"]

    start = time.time()
    startup = RuntimeStartup()
    report = RuntimeReport(
        verdict="PASS",
        image=image,
        profile=profile,
        startup=startup,
        exposed_ports=sorted(set(profile.expected_ports)),
        metadata={
            "dockerfile": dockerfile_info,
            "repo_hints": repo_hint_info,
        },
    )

    cp = _run(["docker", "run", "-d", "--name", container_name, *port_args, image], check=False)
    if cp.returncode != 0:
        report.verdict = "BLOCK"
        report.errors.append(
            f"Failed to start container: {cp.stderr.strip() or cp.stdout.strip() or 'docker run failed'}"
        )
        return apply_runtime_policy(report, policy)

    container_id = cp.stdout.strip()
    startup.container_started = True
    report.metadata["container_id"] = container_id

    time.sleep(3)
    running, exit_code = _container_running(container_name)
    startup.container_running = running
    startup.container_exit_code = exit_code
    startup.startup_seconds = round(time.time() - start, 2)

    if not running:
        report.verdict = "BLOCK"
        report.errors.append("Container exited before readiness checks completed.")
        report.logs_tail = _tail_container_logs(container_name)
        _cleanup(container_name)
        return apply_runtime_policy(report, policy)

    # Probe the container IP instead of 127.0.0.1 so DinD jobs work correctly.
    target_host = _container_ip(container_name) or "127.0.0.1"
    report.metadata["probe_target_host"] = target_host

    listening_ports: list[int] = []
    checked_ports = sorted(set(profile.expected_ports or profile.candidate_http_ports))
    for port in checked_ports:
        check = wait_for_tcp(
            target_host,
            port,
            timeout_seconds=min(startup_timeout_seconds, 15),
        )
        report.port_checks.append(check)
        if check.status == "PASS":
            listening_ports.append(port)

    report.listening_ports = listening_ports

    for port in sorted(set(profile.candidate_http_ports)):
        for path in profile.candidate_http_paths:
            url = f"http://{target_host}:{port}{path}"
            check = http_check(url)
            report.http_checks.append(check)
            if check.status == "PASS":
                break

    report.logs_tail = _tail_container_logs(container_name)
    _cleanup(container_name)
    return apply_runtime_policy(report, policy)