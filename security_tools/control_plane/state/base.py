from __future__ import annotations

from typing import Protocol

from security_tools.control_plane.models.artifact import ArtifactRecord
from security_tools.control_plane.models.deployment import DeploymentRecord
from security_tools.control_plane.models.promotion import PromotionRecord


class ControlPlaneStateStore(Protocol):
    def save_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        ...

    def get_artifact_by_key(self, key: str) -> ArtifactRecord | None:
        ...

    def list_artifacts(self) -> list[ArtifactRecord]:
        ...

    def save_promotion(self, promotion: PromotionRecord) -> PromotionRecord:
        ...

    def list_promotions(self) -> list[PromotionRecord]:
        ...

    def save_deployment(self, deployment: DeploymentRecord) -> DeploymentRecord:
        ...

    def list_deployments(self) -> list[DeploymentRecord]:
        ...