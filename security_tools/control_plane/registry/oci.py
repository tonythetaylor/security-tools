from __future__ import annotations

from security_tools.control_plane.models.execution import PromotionExecutionResult


class OCIRegistryAdapter:
    def __init__(self, registry_url: str) -> None:
        self.registry_url = registry_url

    def push_image(self, image_ref: str) -> str:
        raise NotImplementedError

    def get_digest(self, image_ref: str) -> str:
        raise NotImplementedError

    def promote_digest(
        self,
        digest: str,
        target_repo: str | None = None,
        target_tag: str | None = None,
        dry_run: bool = False,
    ) -> PromotionExecutionResult:
        target = f"{self.registry_url}/{target_repo}" if target_repo else self.registry_url
        if target_tag:
            target = f"{target}:{target_tag}"

        return PromotionExecutionResult(
            success=True,
            backend_name=self.registry_url,
            backend_type="oci",
            source_ref=digest,
            target_ref=target,
            promoted_identity=digest,
            action="promote_digest",
            dry_run=dry_run,
            details={
                "message": "OCI promotion stub executed",
                "target_repo": target_repo,
                "target_tag": target_tag,
            },
        )

    def promote_package(
        self,
        package_name: str,
        version: str,
        target_repo: str | None = None,
        dry_run: bool = False,
    ) -> PromotionExecutionResult:
        return PromotionExecutionResult(
            success=False,
            backend_name=self.registry_url,
            backend_type="oci",
            action="promote_package",
            dry_run=dry_run,
            error="OCI adapter does not support package promotion",
        )

    def pull_metadata(self, digest_or_ref: str) -> dict:
        raise NotImplementedError

    def attach_artifact(self, identity: str, name: str, path: str) -> None:
        raise NotImplementedError

    def fetch_artifact(self, identity: str, name: str) -> bytes:
        raise NotImplementedError