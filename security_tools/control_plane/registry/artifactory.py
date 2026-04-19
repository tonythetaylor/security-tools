from __future__ import annotations

from security_tools.control_plane.models.execution import PromotionExecutionResult


class ArtifactoryRegistryAdapter:
    def __init__(self, base_url: str, repository: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.repository = repository

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
        repo = target_repo or self.repository
        target_ref = f"{self.base_url}/{repo}"
        if target_tag:
            target_ref = f"{target_ref}:{target_tag}"

        return PromotionExecutionResult(
            success=True,
            backend_name=self.repository,
            backend_type="artifactory",
            source_ref=digest,
            target_ref=target_ref,
            promoted_identity=digest,
            action="promote_digest",
            dry_run=dry_run,
            details={
                "message": "Artifactory promotion stub executed",
                "target_repo": repo,
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
        repo = target_repo or self.repository
        target_ref = f"{self.base_url}/{repo}/{package_name}/{version}"

        return PromotionExecutionResult(
            success=True,
            backend_name=self.repository,
            backend_type="artifactory",
            source_ref=f"{package_name}:{version}",
            target_ref=target_ref,
            promoted_identity=f"{package_name}:{version}",
            action="promote_package",
            dry_run=dry_run,
            details={
                "message": "Artifactory package promotion stub executed",
                "target_repo": repo,
                "package_name": package_name,
                "version": version,
            },
        )

    def pull_metadata(self, digest_or_ref: str) -> dict:
        raise NotImplementedError

    def attach_artifact(self, identity: str, name: str, path: str) -> None:
        raise NotImplementedError

    def fetch_artifact(self, identity: str, name: str) -> bytes:
        raise NotImplementedError