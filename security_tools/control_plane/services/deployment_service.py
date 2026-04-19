from __future__ import annotations

from security_tools.control_plane.models.deployment import DeploymentRecord
from security_tools.control_plane.runtime.config_model import RuntimeConfigEnvelope
from security_tools.control_plane.runtime.drift import detect_runtime_drift, drift_detected
from security_tools.control_plane.state.base import ControlPlaneStateStore


class DeploymentService:
    def __init__(self, state_store: ControlPlaneStateStore) -> None:
        self.state_store = state_store

    def record_deployment(self, deployment: DeploymentRecord) -> DeploymentRecord:
        return self.state_store.save_deployment(deployment)

    def list_deployments(self) -> list[DeploymentRecord]:
        return self.state_store.list_deployments()

    def build_runtime_envelope_from_deployment(
        self,
        deployment: DeploymentRecord,
        secret_refs: list[str] | None = None,
    ) -> RuntimeConfigEnvelope:
        return RuntimeConfigEnvelope(
            environment=deployment.environment,
            artifact_digest=deployment.artifact_digest,
            env_vars=dict(deployment.env_vars),
            secret_refs=list(secret_refs or []),
            config_refs=list(deployment.runtime_config_refs),
            manifest_hash=deployment.manifest_hash,
        )

    def verify_drift(
        self,
        approved: RuntimeConfigEnvelope,
        deployed: RuntimeConfigEnvelope,
    ) -> tuple[bool, dict[str, list[str]]]:
        drift = detect_runtime_drift(approved=approved, deployed=deployed)
        return (not drift_detected(drift), drift)