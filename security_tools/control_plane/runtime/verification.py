from __future__ import annotations

from security_tools.control_plane.models.deployment import DeploymentRecord


def deployment_matches_approved_digest(
    approved_digest: str,
    deployment: DeploymentRecord,
) -> bool:
    return approved_digest == deployment.artifact_digest