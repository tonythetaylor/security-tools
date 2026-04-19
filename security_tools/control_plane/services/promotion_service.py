from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from security_tools.control_plane.models.artifact import ArtifactRecord
from security_tools.control_plane.models.execution import PromotionExecutionResult
from security_tools.control_plane.models.policy import PolicyDecision
from security_tools.control_plane.models.promotion import PromotionRecord
from security_tools.control_plane.policy.engine import PolicyEngine
from security_tools.control_plane.state.base import ControlPlaneStateStore


class PromotionService:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        state_store: ControlPlaneStateStore,
    ) -> None:
        self.policy_engine = policy_engine
        self.state_store = state_store

    def evaluate_promotion(
        self,
        artifact: ArtifactRecord,
        target_environment: str,
        runtime_verification_passed: bool = False,
    ) -> PolicyDecision:
        policy = self.policy_engine.build_policy(
            artifact=artifact,
            environment=target_environment,
        )
        return self.policy_engine.evaluate(
            artifact=artifact,
            policy=policy,
            runtime_verification_passed=runtime_verification_passed,
        )

    def execute_promotion(
        self,
        artifact: ArtifactRecord,
        source_environment: str,
        target_environment: str,
        requested_by: str | None,
        registry_adapter,
        runtime_verification_passed: bool = False,
        target_repo: str | None = None,
        target_tag: str | None = None,
        dry_run: bool = False,
        evidence_service=None,
        evidence_payload=None,
    ) -> tuple[PolicyDecision, PromotionRecord, PromotionExecutionResult | None]:
        decision = self.evaluate_promotion(
            artifact=artifact,
            target_environment=target_environment,
            runtime_verification_passed=runtime_verification_passed,
        )

        execution_result: PromotionExecutionResult | None = None
        status = "denied"
        decision_reason = "; ".join(decision.reasons) if decision.reasons else "Eligible for promotion"

        if decision.eligible:
            if evidence_service and evidence_payload:
                evidence_service.store_evidence_json(
                    artifact_identity=asdict(artifact.identity),
                    evidence_type="promotion_evidence",
                    data=evidence_payload,
                )

            if artifact.identity.artifact_type == "container_image":
                execution_result = registry_adapter.promote_digest(
                    digest=artifact.identity.digest or "",
                    target_repo=target_repo,
                    target_tag=target_tag,
                    dry_run=dry_run,
                )
            else:
                execution_result = registry_adapter.promote_package(
                    package_name=artifact.identity.name,
                    version=artifact.identity.version or "",
                    target_repo=target_repo,
                    dry_run=dry_run,
                )

            if execution_result is None:
                status = "execution_failed"
                decision_reason = "Registry adapter returned no execution result"
            else:
                if evidence_service:
                    evidence_service.store_evidence_json(
                        artifact_identity=asdict(artifact.identity),
                        evidence_type="execution_result",
                        data={
                            "success": execution_result.success,
                            "backend": execution_result.backend_name,
                            "target": execution_result.target_ref,
                            "details": execution_result.details,
                            "error": execution_result.error,
                        },
                    )

                if execution_result.success:
                    status = "approved"
                    decision_reason = execution_result.details.get(
                        "message",
                        "Promotion executed successfully",
                    )
                else:
                    status = "execution_failed"
                    decision_reason = execution_result.error or "Promotion execution failed"

        now = datetime.now(UTC)

        promotion = PromotionRecord(
            artifact_digest=artifact.identity.digest
            or artifact.identity.checksum
            or artifact.identity.version
            or artifact.identity.name,
            source_environment=source_environment,
            target_environment=target_environment,
            requested_by=requested_by,
            status=status,
            policy_snapshot={
                **decision.metadata,
                "execution": execution_result.details if execution_result else {},
            },
            decision_reason=decision_reason,
            created_at=now,
            updated_at=now,
        )

        self.state_store.save_promotion(promotion)
        return decision, promotion, execution_result