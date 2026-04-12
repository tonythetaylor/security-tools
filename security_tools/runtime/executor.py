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


def _logs_indicate_ready(logs: str) -> bool:
    markers = [
        "Running on http://",
        "Uvicorn running on",
        "Tomcat started",
        "Started Application",
        "Listening on",
        "Server started",
        "Ready to accept connections",
        "nginx/",
    ]
    return any(marker in logs for marker in markers)


def _exec_http_probe(container_name: str, port: int, path: str) -> bool:
    url = f"http://127.0.0.1:{port}{path}"

    commands = [
        ["docker", "exec", container_name, "sh", "-lc", f"curl -fsS {url}"],
        ["docker", "exec", container_name, "sh", "-lc", f"wget -qO- {url}"],
        ["docker", "exec", container_name, "sh", "-lc", f"python - <<'PY'\nimport urllib.request\nurllib.request.urlopen('{url}')\nPY"],
    ]

    for cmd in commands:
        cp = _run(cmd, check=False)
        if cp.returncode == 0:
            return True

    return False


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
            _build_if_missing(image, dockerfile_path, context_dir)
        except Exception as exc:
            return RuntimeReport(
                verdict="OPERATIONAL_ERROR",
                image=image,
                profile=detect_runtime_profile(),
                startup=RuntimeStartup(),
                errors=[f"Failed to build image: {exc}"],
            )

    image_inspect = inspect_image(image)
    dockerfile_info = parse_dockerfile(dockerfile_path)
    repo_hint_info = repo_hints(context_dir)

    profile = detect_runtime_profile(image_inspect, dockerfile_info, repo_hint_info)
    policy = load_runtime_policy()

    container_name = f"runtime-verify-{random.randint(10000,99999)}"

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

    try:
        cp = _run(
            ["docker", "run", "-d", "--name", container_name, image],
            check=True,
        )
        container_id = cp.stdout.strip()
        startup.container_started = True
        report.metadata["container_id"] = container_id

    except Exception as exc:
        report.verdict = "BLOCK"
        report.errors.append(f"Failed to start container: {exc}")
        return apply_runtime_policy(report, policy)

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

    # -----------------------------
    # PRIMARY: In-container probing
    # -----------------------------
    listening_ports = []

    for port in profile.candidate_http_ports:
        for path in profile.candidate_http_paths:
            if _exec_http_probe(container_name, port, path):
                listening_ports.append(port)
                report.http_checks.append(
                    http_check(f"http://127.0.0.1:{port}{path}")
                )
                break

    report.listening_ports = listening_ports

    # -----------------------------
    # Fallback: External probing
    # -----------------------------
    if not listening_ports:
        container_logs = _tail_container_logs(container_name)

        if _logs_indicate_ready(container_logs):
            report.warnings.append(
                "Logs indicate service startup, but readiness probe inconclusive."
            )
            report.verdict = "WARN"

    report.logs_tail = _tail_container_logs(container_name)

    _cleanup(container_name)

    return apply_runtime_policy(report, policy)