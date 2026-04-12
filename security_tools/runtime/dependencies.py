from __future__ import annotations

import subprocess
import time


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def start_postgres(name: str = "runtime-postgres"):
    _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-e",
            "POSTGRES_PASSWORD=test",
            "-e",
            "POSTGRES_USER=test",
            "-e",
            "POSTGRES_DB=test",
            "postgres:16",
        ]
    )

    for _ in range(30):
        cp = _run(
            [
                "docker",
                "exec",
                name,
                "pg_isready",
            ]
        )

        if cp.returncode == 0:
            return True

        time.sleep(1)

    return False


def start_dependencies(contract: dict):
    deps = contract.get("dependencies", [])

    started = []

    for dep in deps:
        if dep.get("type") == "postgres":
            if start_postgres():
                started.append("postgres")

    return started