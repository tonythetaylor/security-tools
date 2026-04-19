from __future__ import annotations

from typing import Protocol


class EvidenceStore(Protocol):
    def put_file(self, artifact_digest: str, name: str, path: str) -> str:
        """Store an evidence file and return its logical location."""
        ...

    def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
        """Store evidence content and return its logical location."""
        ...

    def get_file(self, artifact_digest: str, name: str) -> bytes:
        """Retrieve a stored evidence file."""
        ...

    def list_files(self, artifact_digest: str) -> list[str]:
        """List evidence files associated with an artifact digest."""
        ...
