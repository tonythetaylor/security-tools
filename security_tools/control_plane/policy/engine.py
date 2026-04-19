from __future__ import annotations

from security_tools.control_plane.models.artifact import ArtifactRecord
from security_tools.control_plane.models.config import ArtifactTypeConfig, EnvironmentConfig
from security_tools.control_plane.models.policy import PolicyDecision, PromotionPolicy


class PolicyEngine:
    def __init__(
        self,
        artifact_types: dict[str, ArtifactTypeConfig],
        environments: dict[str, EnvironmentConfig],
    ) -> None:
        self.artifact_types = artifact_types
        self.environments = environments

    def build_policy(self, artifact: ArtifactRecord, environment: str) -> PromotionPolicy:
        artifact_cfg = self.artifact_types[artifact.identity.artifact_type]
        env_cfg = self.environments[environment]

        required = list(artifact_cfg.evidence.get("required", []))

        for control in env_cfg.required_controls:
            if control not in required:
                required.append(control)

        approvals = list(env_cfg.approvals_required)

        return PromotionPolicy(
            environment=environment,
            require=required,
            approvals=approvals,
            metadata={
                "artifact_type": artifact.identity.artifact_type,
                "policy_profile": artifact_cfg.policy_profile,
                "build_allowed": env_cfg.build_allowed,
                "deploy_allowed": env_cfg.deploy_allowed,
                "required_controls": list(env_cfg.required_controls),
                "approvals_required": approvals,
            },
        )

    def evaluate(
        self,
        artifact: ArtifactRecord,
        policy: PromotionPolicy,
        runtime_verification_passed: bool = False,
    ) -> PolicyDecision:
        reasons: list[str] = []
        evaluated: dict[str, bool] = {}

        for requirement in policy.require:
            if requirement == "sbom":
                ok = artifact.sbom_present
            elif requirement == "signature":
                ok = artifact.signature_present
            elif requirement == "attestation":
                ok = artifact.attestation_present
            elif requirement == "runtime_report":
                ok = runtime_verification_passed
            elif requirement in {"security_review", "dependency_scan", "iac_scan"}:
                ok = True
            else:
                ok = False

            evaluated[requirement] = ok
            if not ok:
                reasons.append(f"Missing required evidence or control: {requirement}")

        eligible = not reasons
        return PolicyDecision(
            eligible=eligible,
            environment=policy.environment,
            reasons=reasons,
            evaluated_requirements=evaluated,
            metadata=policy.metadata,
        )