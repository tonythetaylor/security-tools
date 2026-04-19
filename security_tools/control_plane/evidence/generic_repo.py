from __future__ import annotations


class GenericRepositoryEvidenceStore:
    def __init__(self, base_url: str, repository: str) -> None:
        self.base_url = base_url
        self.repository = repository

    def put_file(self, artifact_digest: str, name: str, path: str) -> str:
        raise NotImplementedError

    def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
        raise NotImplementedError

    def get_file(self, artifact_digest: str, name: str) -> bytes:
        raise NotImplementedError

    def list_files(self, artifact_digest: str) -> list[str]:
        raise NotImplementedError
