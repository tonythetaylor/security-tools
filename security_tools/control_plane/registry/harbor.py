from __future__ import annotations

from security_tools.control_plane.models.execution import PromotionExecutionResult


class HarborRegistryAdapter:
    def __init__(self, harbor_url: str, project: str) -> None:
        self.harbor_url = harbor_url.rstrip("/")
        self.project = project

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
        repo = target_repo or self.project
        target_ref = f"{self.harbor_url}/{repo}"
        if target_tag:
            target_ref = f"{target_ref}:{target_tag}"

        return PromotionExecutionResult(
            success=True,
            backend_name=self.project,
            backend_type="harbor",
            source_ref=digest,
            target_ref=target_ref,
            promoted_identity=digest,
            action="promote_digest",
            dry_run=dry_run,
            details={
                "message": "Harbor promotion stub executed",
                "project": self.project,
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
        return PromotionExecutionResult(
            success=False,
            backend_name=self.project,
            backend_type="harbor",
            action="promote_package",
            dry_run=dry_run,
            error="Harbor adapter does not support package promotion in this adapter",
        )

    def pull_metadata(self, digest_or_ref: str) -> dict:
        raise NotImplementedError

    def attach_artifact(self, identity: str, name: str, path: str) -> None:
        raise NotImplementedError

    def fetch_artifact(self, identity: str, name: str) -> bytes:
        raise NotImplementedError