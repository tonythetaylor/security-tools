from __future__ import annotations

from typing import Protocol

from security_tools.control_plane.models.execution import PromotionExecutionResult


class ArtifactRegistryAdapter(Protocol):
    def push_image(self, image_ref: str) -> str:
        ...

    def get_digest(self, image_ref: str) -> str:
        ...

    def promote_digest(
        self,
        digest: str,
        target_repo: str | None = None,
        target_tag: str | None = None,
        dry_run: bool = False,
    ) -> PromotionExecutionResult:
        ...

    def promote_package(
        self,
        package_name: str,
        version: str,
        target_repo: str | None = None,
        dry_run: bool = False,
    ) -> PromotionExecutionResult:
        ...

    def pull_metadata(self, digest_or_ref: str) -> dict:
        ...

    def attach_artifact(self, identity: str, name: str, path: str) -> None:
        ...

    def fetch_artifact(self, identity: str, name: str) -> bytes:
        ...