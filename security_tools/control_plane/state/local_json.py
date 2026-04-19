from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from security_tools.control_plane.models.artifact import ArtifactIdentity, ArtifactRecord
from security_tools.control_plane.models.deployment import DeploymentRecord
from security_tools.control_plane.models.promotion import PromotionRecord


def _datetime_parser(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return value
    return value


class LocalJsonStateStore:
    def __init__(self, base_dir: str | Path = "data/control_plane_state") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.artifacts_file = self.base_dir / "artifacts.json"
        self.promotions_file = self.base_dir / "promotions.json"
        self.deployments_file = self.base_dir / "deployments.json"

        for path in (self.artifacts_file, self.promotions_file, self.deployments_file):
            if not path.exists():
                path.write_text("[]", encoding="utf-8")

    def _read_list(self, path: Path) -> list[dict[str, Any]]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_list(self, path: Path, data: list[dict[str, Any]]) -> None:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _artifact_key(self, artifact: ArtifactRecord) -> str:
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

    def _artifact_from_dict(self, raw: dict[str, Any]) -> ArtifactRecord:
        identity_raw = raw["identity"]
        identity = ArtifactIdentity(**identity_raw)

        return ArtifactRecord(
            identity=identity,
            source_repo=raw.get("source_repo"),
            source_commit=raw.get("source_commit"),
            build_pipeline_id=raw.get("build_pipeline_id"),
            sbom_present=raw.get("sbom_present", False),
            signature_present=raw.get("signature_present", False),
            attestation_present=raw.get("attestation_present", False),
            security_verdict=raw.get("security_verdict"),
            risk_score=raw.get("risk_score"),
            metadata=raw.get("metadata", {}),
            created_at=_datetime_parser(raw.get("created_at")) or datetime.utcnow(),
        )

    def _promotion_from_dict(self, raw: dict[str, Any]) -> PromotionRecord:
        return PromotionRecord(
            artifact_digest=raw["artifact_digest"],
            source_environment=raw["source_environment"],
            target_environment=raw["target_environment"],
            requested_by=raw.get("requested_by"),
            approved_by=raw.get("approved_by", []),
            status=raw.get("status", "requested"),
            policy_snapshot=raw.get("policy_snapshot", {}),
            decision_reason=raw.get("decision_reason"),
            created_at=_datetime_parser(raw.get("created_at")) or datetime.utcnow(),
            updated_at=_datetime_parser(raw.get("updated_at")) or datetime.utcnow(),
        )

    def _deployment_from_dict(self, raw: dict[str, Any]) -> DeploymentRecord:
        return DeploymentRecord(
            artifact_digest=raw["artifact_digest"],
            environment=raw["environment"],
            runtime_config_refs=raw.get("runtime_config_refs", []),
            manifest_hash=raw.get("manifest_hash"),
            runtime_verification_verdict=raw.get("runtime_verification_verdict"),
            drift_verification_verdict=raw.get("drift_verification_verdict"),
            deployed_by=raw.get("deployed_by"),
            deployed_at=_datetime_parser(raw.get("deployed_at")) or datetime.utcnow(),
            metadata=raw.get("metadata", {}),
        )

    def save_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        rows = self._read_list(self.artifacts_file)
        key = self._artifact_key(artifact)

        artifact_dict = asdict(artifact)
        artifact_dict["_key"] = key

        updated = False
        for idx, row in enumerate(rows):
            if row.get("_key") == key:
                rows[idx] = artifact_dict
                updated = True
                break

        if not updated:
            rows.append(artifact_dict)

        self._write_list(self.artifacts_file, rows)
        return artifact

    def get_artifact_by_key(self, key: str) -> ArtifactRecord | None:
        rows = self._read_list(self.artifacts_file)
        for row in rows:
            if row.get("_key") == key:
                return self._artifact_from_dict(row)
        return None

    def list_artifacts(self) -> list[ArtifactRecord]:
        return [self._artifact_from_dict(row) for row in self._read_list(self.artifacts_file)]

    def save_promotion(self, promotion: PromotionRecord) -> PromotionRecord:
        rows = self._read_list(self.promotions_file)
        rows.append(asdict(promotion))
        self._write_list(self.promotions_file, rows)
        return promotion

    def list_promotions(self) -> list[PromotionRecord]:
        return [self._promotion_from_dict(row) for row in self._read_list(self.promotions_file)]

    def save_deployment(self, deployment: DeploymentRecord) -> DeploymentRecord:
        rows = self._read_list(self.deployments_file)
        rows.append(asdict(deployment))
        self._write_list(self.deployments_file, rows)
        return deployment

    def list_deployments(self) -> list[DeploymentRecord]:
        return [self._deployment_from_dict(row) for row in self._read_list(self.deployments_file)]