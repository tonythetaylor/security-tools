from __future__ import annotations

from security_tools.control_plane.models.artifact import ArtifactRecord
from security_tools.control_plane.models.config import ArtifactTypeConfig
from security_tools.control_plane.state.base import ControlPlaneStateStore


class ArtifactService:
    def __init__(
        self,
        artifact_types: dict[str, ArtifactTypeConfig],
        state_store: ControlPlaneStateStore,
    ) -> None:
        self.artifact_types = artifact_types
        self.state_store = state_store

    def identity_key(self, artifact: ArtifactRecord) -> str:
        identity = artifact.identity
        return "|".join(
            [
                identity.artifact_type or "",
                identity.name or "",
                identity.version or "",
                identity.digest or "",
                identity.checksum or "",
            ]
        )

    def validate_artifact(self, artifact: ArtifactRecord) -> None:
        cfg = self.artifact_types.get(artifact.identity.artifact_type)
        if cfg is None:
            raise ValueError(f"Unknown artifact type: {artifact.identity.artifact_type}")

        identity_rules = cfg.identity

        if identity_rules.get("require_digest") and not artifact.identity.digest:
            raise ValueError(f"{artifact.identity.artifact_type} requires digest")

        if identity_rules.get("require_version") and not artifact.identity.version:
            raise ValueError(f"{artifact.identity.artifact_type} requires version")

        if identity_rules.get("require_checksum") and not artifact.identity.checksum:
            raise ValueError(f"{artifact.identity.artifact_type} requires checksum")

    def register_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        self.validate_artifact(artifact)
        return self.state_store.save_artifact(artifact)

    def get_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord | None:
        return self.state_store.get_artifact_by_key(self.identity_key(artifact))

    def list_artifacts(self) -> list[ArtifactRecord]:
        return self.state_store.list_artifacts()