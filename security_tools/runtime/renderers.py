from __future__ import annotations

from pathlib import Path

from security_tools.runtime.models import RuntimeReport


def write_json_report(report: RuntimeReport, path: str | Path) -> None:
    Path(path).write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_markdown_summary(report: RuntimeReport, path: str | Path) -> None:
    lines = [
        "# Container Runtime Verification Summary",
        "",
        f"- **Verdict:** {report.verdict}",
        f"- **Image:** `{report.image}`",
        f"- **Profile:** `{report.profile.name}`",
        f"- **Container Started:** `{report.startup.container_started}`",
        f"- **Container Running:** `{report.startup.container_running}`",
        f"- **Startup Seconds:** `{report.startup.startup_seconds}`",
        f"- **Listening Ports:** `{', '.join(map(str, report.listening_ports)) if report.listening_ports else 'none'}`",
        "",
        "## Warnings",
    ]

    if report.warnings:
        lines.extend([f"- {w}" for w in report.warnings])
    else:
        lines.append("- None")

    lines.extend(["", "## Errors"])

    if report.errors:
        lines.extend([f"- {e}" for e in report.errors])
    else:
        lines.append("- None")

    Path(path).write_text("\n".join(lines), encoding="utf-8")