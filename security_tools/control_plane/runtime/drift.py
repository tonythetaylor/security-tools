from __future__ import annotations

from security_tools.control_plane.runtime.config_model import RuntimeConfigEnvelope


def detect_runtime_drift(
    approved: RuntimeConfigEnvelope,
    deployed: RuntimeConfigEnvelope,
) -> dict[str, list[str]]:
    drift: dict[str, list[str]] = {
        "artifact_digest": [],
        "env_vars": [],
        "secret_refs": [],
        "config_refs": [],
        "manifest_hash": [],
    }

    if approved.artifact_digest != deployed.artifact_digest:
        drift["artifact_digest"].append(
            "Deployed artifact digest differs from approved artifact digest."
        )

    if approved.env_vars != deployed.env_vars:
        drift["env_vars"].append(
            "Environment variables differ from approved runtime envelope."
        )

    if sorted(approved.secret_refs) != sorted(deployed.secret_refs):
        drift["secret_refs"].append(
            "Secret references differ from approved runtime envelope."
        )

    if sorted(approved.config_refs) != sorted(deployed.config_refs):
        drift["config_refs"].append(
            "Config references differ from approved runtime envelope."
        )

    if approved.manifest_hash != deployed.manifest_hash:
        drift["manifest_hash"].append(
            "Deployment manifest hash differs from approved runtime envelope."
        )

    return drift


def drift_detected(drift: dict[str, list[str]]) -> bool:
    return any(bool(items) for items in drift.values())