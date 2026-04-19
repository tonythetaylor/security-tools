#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from textwrap import dedent


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "security_tools" / "control_plane"


FILES: dict[str, str] = {
    "__init__.py": dedent(
        '''\
        """Artifact-centric promotion control plane."""
        '''
    ),
    "models/__init__.py": dedent(
        '''\
        from security_tools.control_plane.models.artifact import ArtifactRecord
        from security_tools.control_plane.models.deployment import DeploymentRecord
        from security_tools.control_plane.models.policy import PolicyDecision, PromotionPolicy
        from security_tools.control_plane.models.promotion import PromotionRecord

        __all__ = [
            "ArtifactRecord",
            "DeploymentRecord",
            "PolicyDecision",
            "PromotionPolicy",
            "PromotionRecord",
        ]
        '''
    ),
    "models/artifact.py": dedent(
        '''\
        from __future__ import annotations

        from dataclasses import dataclass, field
        from datetime import datetime
        from typing import Any


        @dataclass(slots=True)
        class ArtifactRecord:
            digest: str
            name: str
            tag: str | None = None
            source_repo: str | None = None
            source_commit: str | None = None
            build_pipeline_id: str | None = None
            registry_backend: str | None = None
            registry_location: str | None = None
            sbom_present: bool = False
            signature_present: bool = False
            attestation_present: bool = False
            security_verdict: str | None = None
            risk_score: int | None = None
            metadata: dict[str, Any] = field(default_factory=dict)
            created_at: datetime = field(default_factory=datetime.utcnow)
        '''
    ),
    "models/promotion.py": dedent(
        '''\
        from __future__ import annotations

        from dataclasses import dataclass, field
        from datetime import datetime
        from typing import Any


        @dataclass(slots=True)
        class PromotionRecord:
            artifact_digest: str
            source_environment: str
            target_environment: str
            requested_by: str | None = None
            approved_by: list[str] = field(default_factory=list)
            status: str = "requested"
            policy_snapshot: dict[str, Any] = field(default_factory=dict)
            decision_reason: str | None = None
            created_at: datetime = field(default_factory=datetime.utcnow)
            updated_at: datetime = field(default_factory=datetime.utcnow)
        '''
    ),
    "models/deployment.py": dedent(
        '''\
        from __future__ import annotations

        from dataclasses import dataclass, field
        from datetime import datetime
        from typing import Any


        @dataclass(slots=True)
        class DeploymentRecord:
            artifact_digest: str
            environment: str
            runtime_config_refs: list[str] = field(default_factory=list)
            manifest_hash: str | None = None
            runtime_verification_verdict: str | None = None
            drift_verification_verdict: str | None = None
            deployed_by: str | None = None
            deployed_at: datetime = field(default_factory=datetime.utcnow)
            metadata: dict[str, Any] = field(default_factory=dict)
        '''
    ),
    "models/policy.py": dedent(
        '''\
        from __future__ import annotations

        from dataclasses import dataclass, field
        from typing import Any


        @dataclass(slots=True)
        class PromotionPolicy:
            environment: str
            require: list[str] = field(default_factory=list)
            limits: dict[str, int] = field(default_factory=dict)
            approvals: list[str] = field(default_factory=list)
            metadata: dict[str, Any] = field(default_factory=dict)


        @dataclass(slots=True)
        class PolicyDecision:
            eligible: bool
            environment: str
            reasons: list[str] = field(default_factory=list)
            evaluated_requirements: dict[str, bool] = field(default_factory=dict)
            metadata: dict[str, Any] = field(default_factory=dict)
        '''
    ),
    "registry/__init__.py": dedent(
        '''\
        from security_tools.control_plane.registry.base import ArtifactRegistryAdapter

        __all__ = ["ArtifactRegistryAdapter"]
        '''
    ),
    "registry/base.py": dedent(
        '''\
        from __future__ import annotations

        from typing import Protocol


        class ArtifactRegistryAdapter(Protocol):
            def push_image(self, image_ref: str) -> str:
                """Push an image and return its immutable digest."""
                ...

            def get_digest(self, image_ref: str) -> str:
                """Resolve a tag or image reference to an immutable digest."""
                ...

            def promote_digest(self, digest: str, target_repo: str | None = None) -> str:
                """Promote an existing digest to a target repository or namespace."""
                ...

            def pull_metadata(self, digest: str) -> dict:
                """Return registry metadata for a digest."""
                ...

            def attach_artifact(self, digest: str, name: str, path: str) -> None:
                """Attach evidence or metadata to an artifact."""
                ...

            def fetch_artifact(self, digest: str, name: str) -> bytes:
                """Fetch an attached artifact by name."""
                ...
        '''
    ),
    "registry/oci.py": dedent(
        '''\
        from __future__ import annotations


        class OCIRegistryAdapter:
            def __init__(self, registry_url: str) -> None:
                self.registry_url = registry_url

            def push_image(self, image_ref: str) -> str:
                raise NotImplementedError

            def get_digest(self, image_ref: str) -> str:
                raise NotImplementedError

            def promote_digest(self, digest: str, target_repo: str | None = None) -> str:
                raise NotImplementedError

            def pull_metadata(self, digest: str) -> dict:
                raise NotImplementedError

            def attach_artifact(self, digest: str, name: str, path: str) -> None:
                raise NotImplementedError

            def fetch_artifact(self, digest: str, name: str) -> bytes:
                raise NotImplementedError
        '''
    ),
    "registry/artifactory.py": dedent(
        '''\
        from __future__ import annotations


        class ArtifactoryRegistryAdapter:
            def __init__(self, base_url: str, repository: str) -> None:
                self.base_url = base_url
                self.repository = repository

            def push_image(self, image_ref: str) -> str:
                raise NotImplementedError

            def get_digest(self, image_ref: str) -> str:
                raise NotImplementedError

            def promote_digest(self, digest: str, target_repo: str | None = None) -> str:
                raise NotImplementedError

            def pull_metadata(self, digest: str) -> dict:
                raise NotImplementedError

            def attach_artifact(self, digest: str, name: str, path: str) -> None:
                raise NotImplementedError

            def fetch_artifact(self, digest: str, name: str) -> bytes:
                raise NotImplementedError
        '''
    ),
    "registry/harbor.py": dedent(
        '''\
        from __future__ import annotations


        class HarborRegistryAdapter:
            def __init__(self, harbor_url: str, project: str) -> None:
                self.harbor_url = harbor_url
                self.project = project

            def push_image(self, image_ref: str) -> str:
                raise NotImplementedError

            def get_digest(self, image_ref: str) -> str:
                raise NotImplementedError

            def promote_digest(self, digest: str, target_repo: str | None = None) -> str:
                raise NotImplementedError

            def pull_metadata(self, digest: str) -> dict:
                raise NotImplementedError

            def attach_artifact(self, digest: str, name: str, path: str) -> None:
                raise NotImplementedError

            def fetch_artifact(self, digest: str, name: str) -> bytes:
                raise NotImplementedError
        '''
    ),
    "evidence/__init__.py": dedent(
        '''\
        from security_tools.control_plane.evidence.store import EvidenceStore

        __all__ = ["EvidenceStore"]
        '''
    ),
    "evidence/store.py": dedent(
        '''\
        from __future__ import annotations

        from typing import Protocol


        class EvidenceStore(Protocol):
            def put_file(self, artifact_digest: str, name: str, path: str) -> str:
                """Store an evidence file and return its logical location."""
                ...

            def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
                """Store evidence content and return its logical location."""
                ...

            def get_file(self, artifact_digest: str, name: str) -> bytes:
                """Retrieve a stored evidence file."""
                ...

            def list_files(self, artifact_digest: str) -> list[str]:
                """List evidence files associated with an artifact digest."""
                ...
        '''
    ),
    "evidence/object_store.py": dedent(
        '''\
        from __future__ import annotations


        class ObjectStoreEvidenceStore:
            def __init__(self, bucket_name: str) -> None:
                self.bucket_name = bucket_name

            def put_file(self, artifact_digest: str, name: str, path: str) -> str:
                raise NotImplementedError

            def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
                raise NotImplementedError

            def get_file(self, artifact_digest: str, name: str) -> bytes:
                raise NotImplementedError

            def list_files(self, artifact_digest: str) -> list[str]:
                raise NotImplementedError
        '''
    ),
    "evidence/generic_repo.py": dedent(
        '''\
        from __future__ import annotations


        class GenericRepositoryEvidenceStore:
            def __init__(self, base_url: str, repository: str) -> None:
                self.base_url = base_url
                self.repository = repository

            def put_file(self, artifact_digest: str, name: str, path: str) -> str:
                raise NotImplementedError

            def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
                raise NotImplementedError

            def get_file(self, artifact_digest: str, name: str) -> bytes:
                raise NotImplementedError

            def list_files(self, artifact_digest: str) -> list[str]:
                raise NotImplementedError
        '''
    ),
    "policy/__init__.py": dedent(
        '''\
        from security_tools.control_plane.policy.engine import PolicyEngine

        __all__ = ["PolicyEngine"]
        '''
    ),
    "policy/engine.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.artifact import ArtifactRecord
        from security_tools.control_plane.models.policy import PolicyDecision, PromotionPolicy


        class PolicyEngine:
            def evaluate(
                self,
                artifact: ArtifactRecord,
                policy: PromotionPolicy,
                runtime_verification_passed: bool = False,
            ) -> PolicyDecision:
                reasons: list[str] = []
                evaluated: dict[str, bool] = {}

                for requirement in policy.require:
                    if requirement == "sbom_present":
                        ok = artifact.sbom_present
                    elif requirement == "signature_present":
                        ok = artifact.signature_present
                    elif requirement == "attestation_present":
                        ok = artifact.attestation_present
                    elif requirement == "runtime_verification_pass":
                        ok = runtime_verification_passed
                    else:
                        ok = False

                    evaluated[requirement] = ok
                    if not ok:
                        reasons.append(f"Missing required control: {requirement}")

                eligible = not reasons
                return PolicyDecision(
                    eligible=eligible,
                    environment=policy.environment,
                    reasons=reasons,
                    evaluated_requirements=evaluated,
                )
        '''
    ),
    "policy/rules.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.policy import PromotionPolicy


        def default_policy_for_environment(environment: str) -> PromotionPolicy:
            env = environment.lower()

            if env == "dev":
                return PromotionPolicy(
                    environment=env,
                    require=["sbom_present"],
                    limits={"critical": 0},
                )

            if env in {"ite", "qa"}:
                return PromotionPolicy(
                    environment=env,
                    require=["sbom_present", "runtime_verification_pass"],
                    limits={"critical": 0, "high": 0},
                )

            if env in {"stage", "prod"}:
                return PromotionPolicy(
                    environment=env,
                    require=[
                        "sbom_present",
                        "signature_present",
                        "attestation_present",
                        "runtime_verification_pass",
                    ],
                    limits={"critical": 0, "high": 0, "medium": 0},
                    approvals=["security", "operations"],
                )

            return PromotionPolicy(environment=env)
        '''
    ),
    "runtime/__init__.py": dedent(
        '''\
        from security_tools.control_plane.runtime.config_model import RuntimeConfigEnvelope

        __all__ = ["RuntimeConfigEnvelope"]
        '''
    ),
    "runtime/config_model.py": dedent(
        '''\
        from __future__ import annotations

        from dataclasses import dataclass, field


        @dataclass(slots=True)
        class RuntimeConfigEnvelope:
            environment: str
            env_vars: dict[str, str] = field(default_factory=dict)
            secret_refs: list[str] = field(default_factory=list)
            config_refs: list[str] = field(default_factory=list)
            manifest_hash: str | None = None
        '''
    ),
    "runtime/drift.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.runtime.config_model import RuntimeConfigEnvelope


        def detect_runtime_drift(
            approved: RuntimeConfigEnvelope,
            deployed: RuntimeConfigEnvelope,
        ) -> dict[str, list[str]]:
            drift: dict[str, list[str]] = {
                "env_vars": [],
                "secret_refs": [],
                "config_refs": [],
            }

            if approved.env_vars != deployed.env_vars:
                drift["env_vars"].append("Environment variables differ from approved envelope.")

            if sorted(approved.secret_refs) != sorted(deployed.secret_refs):
                drift["secret_refs"].append("Secret references differ from approved envelope.")

            if sorted(approved.config_refs) != sorted(deployed.config_refs):
                drift["config_refs"].append("Config references differ from approved envelope.")

            return drift
        '''
    ),
    "runtime/verification.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.deployment import DeploymentRecord


        def deployment_matches_approved_digest(
            approved_digest: str,
            deployment: DeploymentRecord,
        ) -> bool:
            return approved_digest == deployment.artifact_digest
        '''
    ),
    "services/__init__.py": dedent(
        '''\
        from security_tools.control_plane.services.artifact_service import ArtifactService
        from security_tools.control_plane.services.deployment_service import DeploymentService
        from security_tools.control_plane.services.promotion_service import PromotionService

        __all__ = [
            "ArtifactService",
            "DeploymentService",
            "PromotionService",
        ]
        '''
    ),
    "services/artifact_service.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.artifact import ArtifactRecord


        class ArtifactService:
            def register_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
                """Persist and return the registered artifact."""
                return artifact
        '''
    ),
    "services/promotion_service.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.artifact import ArtifactRecord
        from security_tools.control_plane.models.policy import PolicyDecision, PromotionPolicy
        from security_tools.control_plane.policy.engine import PolicyEngine


        class PromotionService:
            def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
                self.policy_engine = policy_engine or PolicyEngine()

            def evaluate_promotion(
                self,
                artifact: ArtifactRecord,
                policy: PromotionPolicy,
                runtime_verification_passed: bool = False,
            ) -> PolicyDecision:
                return self.policy_engine.evaluate(
                    artifact=artifact,
                    policy=policy,
                    runtime_verification_passed=runtime_verification_passed,
                )
        '''
    ),
    "services/deployment_service.py": dedent(
        '''\
        from __future__ import annotations

        from security_tools.control_plane.models.deployment import DeploymentRecord


        class DeploymentService:
            def record_deployment(self, deployment: DeploymentRecord) -> DeploymentRecord:
                """Persist and return the deployment record."""
                return deployment
        '''
    ),
    "api/__init__.py": dedent(
        '''\
        """API routes for the control plane."""
        '''
    ),
    "api/routes_artifacts.py": dedent(
        '''\
        from __future__ import annotations


        def register_artifact_route() -> dict[str, str]:
            return {"route": "/artifacts/register", "status": "not_implemented"}
        '''
    ),
    "api/routes_promotions.py": dedent(
        '''\
        from __future__ import annotations


        def request_promotion_route() -> dict[str, str]:
            return {"route": "/promotions/request", "status": "not_implemented"}
        '''
    ),
    "api/routes_deployments.py": dedent(
        '''\
        from __future__ import annotations


        def record_deployment_route() -> dict[str, str]:
            return {"route": "/deployments/record", "status": "not_implemented"}
        '''
    ),
}


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)

    for relative_path, content in FILES.items():
        path = BASE / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            print(f"Skipping existing file: {path.relative_to(ROOT)}")
            continue

        path.write_text(content, encoding="utf-8")
        print(f"Created {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()