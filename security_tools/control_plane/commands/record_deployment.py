from __future__ import annotations

import argparse
import json

from security_tools.control_plane.models.deployment import DeploymentRecord
from security_tools.control_plane.services.deployment_service import DeploymentService
from security_tools.control_plane.state.local_json import LocalJsonStateStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a deployment in the control plane.")
    parser.add_argument("--state-dir", default="data/control_plane_state")

    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--deployed-by")
    parser.add_argument("--manifest-hash")
    parser.add_argument("--runtime-verification-verdict", default="UNKNOWN")
    parser.add_argument("--drift-verification-verdict", default="NOT_RUN")

    parser.add_argument(
        "--config-ref",
        action="append",
        dest="config_refs",
        default=[],
        help="Approved or deployed config reference. Can be used multiple times.",
    )
    parser.add_argument(
        "--env-var",
        action="append",
        dest="env_vars",
        default=[],
        help="Environment variable in KEY=VALUE form. Can be used multiple times.",
    )

    args = parser.parse_args()

    parsed_env_vars: dict[str, str] = {}
    for item in args.env_vars:
        if "=" not in item:
            raise ValueError(f"Invalid --env-var value '{item}'. Expected KEY=VALUE.")
        key, value = item.split("=", 1)
        parsed_env_vars[key] = value

    state_store = LocalJsonStateStore(base_dir=args.state_dir)
    deployment_service = DeploymentService(state_store=state_store)

    deployment = DeploymentRecord(
        artifact_digest=args.artifact_digest,
        environment=args.environment,
        runtime_config_refs=list(args.config_refs),
        env_vars=parsed_env_vars,
        manifest_hash=args.manifest_hash,
        runtime_verification_verdict=args.runtime_verification_verdict,
        drift_verification_verdict=args.drift_verification_verdict,
        deployed_by=args.deployed_by,
    )

    deployment = deployment_service.record_deployment(deployment)

    print(
        json.dumps(
            {
                "recorded": True,
                "deployment": {
                    "artifact_digest": deployment.artifact_digest,
                    "environment": deployment.environment,
                    "runtime_config_refs": deployment.runtime_config_refs,
                    "env_vars": deployment.env_vars,
                    "manifest_hash": deployment.manifest_hash,
                    "runtime_verification_verdict": deployment.runtime_verification_verdict,
                    "drift_verification_verdict": deployment.drift_verification_verdict,
                    "deployed_by": deployment.deployed_by,
                    "deployed_at": str(deployment.deployed_at),
                },
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())