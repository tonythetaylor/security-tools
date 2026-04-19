from __future__ import annotations

import argparse
import json

from security_tools.control_plane.runtime.config_model import RuntimeConfigEnvelope
from security_tools.control_plane.services.deployment_service import DeploymentService
from security_tools.control_plane.state.local_json import LocalJsonStateStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Check drift between approved and deployed runtime state.")
    parser.add_argument("--state-dir", default="data/control_plane_state")

    parser.add_argument("--approved-environment", required=True)
    parser.add_argument("--approved-artifact-digest", required=True)
    parser.add_argument("--approved-manifest-hash")
    parser.add_argument(
        "--approved-config-ref",
        action="append",
        dest="approved_config_refs",
        default=[],
    )
    parser.add_argument(
        "--approved-secret-ref",
        action="append",
        dest="approved_secret_refs",
        default=[],
    )
    parser.add_argument(
        "--approved-env-var",
        action="append",
        dest="approved_env_vars",
        default=[],
        help="KEY=VALUE; can be used multiple times.",
    )

    parser.add_argument("--deployed-environment", required=True)
    parser.add_argument("--deployed-artifact-digest", required=True)
    parser.add_argument("--deployed-manifest-hash")
    parser.add_argument(
        "--deployed-config-ref",
        action="append",
        dest="deployed_config_refs",
        default=[],
    )
    parser.add_argument(
        "--deployed-secret-ref",
        action="append",
        dest="deployed_secret_refs",
        default=[],
    )
    parser.add_argument(
        "--deployed-env-var",
        action="append",
        dest="deployed_env_vars",
        default=[],
        help="KEY=VALUE; can be used multiple times.",
    )

    args = parser.parse_args()

    def parse_env(items: list[str]) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for item in items:
            if "=" not in item:
                raise ValueError(f"Invalid env var '{item}'. Expected KEY=VALUE.")
            key, value = item.split("=", 1)
            parsed[key] = value
        return parsed

    approved = RuntimeConfigEnvelope(
        environment=args.approved_environment,
        artifact_digest=args.approved_artifact_digest,
        env_vars=parse_env(args.approved_env_vars),
        secret_refs=list(args.approved_secret_refs),
        config_refs=list(args.approved_config_refs),
        manifest_hash=args.approved_manifest_hash,
    )

    deployed = RuntimeConfigEnvelope(
        environment=args.deployed_environment,
        artifact_digest=args.deployed_artifact_digest,
        env_vars=parse_env(args.deployed_env_vars),
        secret_refs=list(args.deployed_secret_refs),
        config_refs=list(args.deployed_config_refs),
        manifest_hash=args.deployed_manifest_hash,
    )

    state_store = LocalJsonStateStore(base_dir=args.state_dir)
    deployment_service = DeploymentService(state_store=state_store)

    matches, drift = deployment_service.verify_drift(
        approved=approved,
        deployed=deployed,
    )

    print(
        json.dumps(
            {
                "matches": matches,
                "approved_environment": approved.environment,
                "deployed_environment": deployed.environment,
                "drift": drift,
            },
            indent=2,
        )
    )

    return 0 if matches else 1


if __name__ == "__main__":
    raise SystemExit(main())