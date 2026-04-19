from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from security_tools.control_plane.config_loader import ControlPlaneConfigLoader
from security_tools.control_plane.factory import EvidenceStoreFactory, RegistryFactory
from security_tools.control_plane.models.artifact import ArtifactIdentity, ArtifactRecord
from security_tools.control_plane.policy.engine import PolicyEngine
from security_tools.control_plane.resolver import BackendResolver
from security_tools.control_plane.services.artifact_service import ArtifactService
from security_tools.control_plane.services.evidence_service import EvidenceService
from security_tools.control_plane.services.promotion_service import PromotionService
from security_tools.control_plane.state.local_json import LocalJsonStateStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute artifact promotion through the control plane.")
    parser.add_argument("--config-dir", default="security_tools/control_plane/config")
    parser.add_argument("--state-dir", default="data/control_plane_state")

    parser.add_argument("--team", required=True)
    parser.add_argument("--artifact-type", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--version")
    parser.add_argument("--digest")
    parser.add_argument("--checksum")

    parser.add_argument("--source-env", required=True)
    parser.add_argument("--target-env", required=True)
    parser.add_argument("--requested-by")

    parser.add_argument("--target-repo")
    parser.add_argument("--target-tag")

    parser.add_argument("--sbom-present", action="store_true")
    parser.add_argument("--signature-present", action="store_true")
    parser.add_argument("--attestation-present", action="store_true")
    parser.add_argument("--runtime-verification-passed", action="store_true")
    parser.add_argument("--dry-run", action="store_true")

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
    registry_adapter = RegistryFactory.create(registry_config)
    evidence_store = EvidenceStoreFactory.create(evidence_store_config)
    evidence_service = EvidenceService(evidence_store)

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

    evidence_payload = {
        "artifact": asdict(artifact.identity),
        "security": {
            "sbom": args.sbom_present,
            "signature": args.signature_present,
            "attestation": args.attestation_present,
            "runtime_verified": args.runtime_verification_passed,
        },
        "request": {
            "team": args.team,
            "source_env": args.source_env,
            "target_env": args.target_env,
            "requested_by": args.requested_by,
        },
    }

    decision, promotion, execution = promotion_service.execute_promotion(
        artifact=artifact,
        source_environment=args.source_env,
        target_environment=args.target_env,
        requested_by=args.requested_by,
        registry_adapter=registry_adapter,
        runtime_verification_passed=args.runtime_verification_passed,
        target_repo=args.target_repo,
        target_tag=args.target_tag,
        dry_run=args.dry_run,
        evidence_service=evidence_service,
        evidence_payload=evidence_payload,
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
                "promotion_record": {
                    "artifact_digest": promotion.artifact_digest,
                    "source_environment": promotion.source_environment,
                    "target_environment": promotion.target_environment,
                    "requested_by": promotion.requested_by,
                    "status": promotion.status,
                    "decision_reason": promotion.decision_reason,
                },
                "execution": None
                if execution is None
                else {
                    "success": execution.success,
                    "backend_name": execution.backend_name,
                    "backend_type": execution.backend_type,
                    "source_ref": execution.source_ref,
                    "target_ref": execution.target_ref,
                    "promoted_identity": execution.promoted_identity,
                    "action": execution.action,
                    "dry_run": execution.dry_run,
                    "details": execution.details,
                    "error": execution.error,
                },
            },
            indent=2,
            default=str,
        )
    )

    if not decision.eligible:
        return 1

    if execution and not execution.success:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())