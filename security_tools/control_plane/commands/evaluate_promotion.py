from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime

from security_tools.control_plane.config_loader import ControlPlaneConfigLoader
from security_tools.control_plane.models.artifact import ArtifactIdentity, ArtifactRecord
from security_tools.control_plane.models.promotion import PromotionRecord
from security_tools.control_plane.policy.engine import PolicyEngine
from security_tools.control_plane.resolver import BackendResolver
from security_tools.control_plane.services.artifact_service import ArtifactService
from security_tools.control_plane.services.promotion_service import PromotionService
from security_tools.control_plane.state.local_json import LocalJsonStateStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate artifact promotion eligibility.")
    parser.add_argument("--config-dir", default="security_tools/control_plane/config")
    parser.add_argument("--state-dir", default="data/control_plane_state")

    parser.add_argument("--team", required=True)

    parser.add_argument("--artifact-type", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--version")
    parser.add_argument("--digest")
    parser.add_argument("--checksum")

    parser.add_argument("--source-env", default="dev")
    parser.add_argument("--target-env", required=True)
    parser.add_argument("--requested-by")

    parser.add_argument("--sbom-present", action="store_true")
    parser.add_argument("--signature-present", action="store_true")
    parser.add_argument("--attestation-present", action="store_true")
    parser.add_argument("--runtime-verification-passed", action="store_true")

    args = parser.parse_args()

    loader = ControlPlaneConfigLoader(args.config_dir)

    artifact_types = loader.load_artifact_types()
    environments = loader.load_environments()
    registries = loader.load_registries()
    evidence_stores = loader.load_evidence_stores()
    teams = loader.load_teams()

    resolver = BackendResolver(
        registries=registries,
        evidence_stores=evidence_stores,
        teams=teams,
    )

    registry_config = resolver.resolve_registry(args.team, args.artifact_type)
    evidence_store_config = resolver.resolve_evidence_store(args.team)

    state_store = LocalJsonStateStore(base_dir=args.state_dir)

    artifact_service = ArtifactService(
        artifact_types=artifact_types,
        state_store=state_store,
    )

    artifact = ArtifactRecord(
        identity=ArtifactIdentity(
            artifact_type=args.artifact_type,
            name=args.name,
            version=args.version,
            digest=args.digest,
            checksum=args.checksum,
            backend_name=registry_config.name,
            location=registry_config.url,
        ),
        sbom_present=args.sbom_present,
        signature_present=args.signature_present,
        attestation_present=args.attestation_present,
    )

    artifact = artifact_service.register_artifact(artifact)

    policy_engine = PolicyEngine(
        artifact_types=artifact_types,
        environments=environments,
    )

    promotion_service = PromotionService(
        policy_engine=policy_engine,
        state_store=state_store,
    )

    decision = promotion_service.evaluate_promotion(
        artifact=artifact,
        target_environment=args.target_env,
        runtime_verification_passed=args.runtime_verification_passed,
    )

    now = datetime.now(UTC)

    preview_promotion = PromotionRecord(
        artifact_digest=artifact.identity.digest
        or artifact.identity.checksum
        or artifact.identity.version
        or artifact.identity.name,
        source_environment=args.source_env,
        target_environment=args.target_env,
        requested_by=args.requested_by,
        status="eligible" if decision.eligible else "ineligible",
        policy_snapshot=decision.metadata,
        decision_reason="; ".join(decision.reasons) if decision.reasons else "Eligible for promotion",
        created_at=now,
        updated_at=now,
    )

    print(
        json.dumps(
            {
                "team": args.team,
                "artifact": {
                    "type": args.artifact_type,
                    "name": args.name,
                    "backend": registry_config.name,
                    "registry_url": registry_config.url,
                },
                "evidence_store": evidence_store_config.name,
                "eligible": decision.eligible,
                "environment": decision.environment,
                "reasons": decision.reasons,
                "evaluated_requirements": decision.evaluated_requirements,
                "metadata": decision.metadata,
                "promotion_preview": {
                    "artifact_digest": preview_promotion.artifact_digest,
                    "source_environment": preview_promotion.source_environment,
                    "target_environment": preview_promotion.target_environment,
                    "requested_by": preview_promotion.requested_by,
                    "status": preview_promotion.status,
                    "decision_reason": preview_promotion.decision_reason,
                },
            },
            indent=2,
            default=str,
        )
    )

    return 0 if decision.eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())