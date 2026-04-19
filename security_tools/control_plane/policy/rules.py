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
