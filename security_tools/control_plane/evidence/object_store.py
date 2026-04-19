from __future__ import annotations

from pathlib import Path


class ObjectStoreEvidenceStore:
    def __init__(self, bucket_name: str) -> None:
        # For local filesystem mode, bucket_name is really a base path.
        self.base_path = Path(bucket_name)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _artifact_dir(self, artifact_digest: str) -> Path:
        # Make the path safe for local filesystems.
        safe_name = (
            artifact_digest.replace(":", "_")
            .replace("/", "_")
            .replace("|", "__")
        )
        artifact_dir = self.base_path / safe_name
        artifact_dir.mkdir(parents=True, exist_ok=True)
        return artifact_dir

    def put_file(self, artifact_digest: str, name: str, path: str) -> str:
        source = Path(path)
        if not source.exists():
            raise FileNotFoundError(f"Evidence source file not found: {path}")

        target = self._artifact_dir(artifact_digest) / name
        target.write_bytes(source.read_bytes())
        return str(target)

    def put_bytes(self, artifact_digest: str, name: str, data: bytes) -> str:
        target = self._artifact_dir(artifact_digest) / name
        target.write_bytes(data)
        return str(target)

    def get_file(self, artifact_digest: str, name: str) -> bytes:
        target = self._artifact_dir(artifact_digest) / name
        if not target.exists():
            raise FileNotFoundError(
                f"Evidence file not found for artifact '{artifact_digest}': {name}"
            )
        return target.read_bytes()

    def list_files(self, artifact_digest: str) -> list[str]:
        artifact_dir = self._artifact_dir(artifact_digest)
        return sorted(
            str(path) for path in artifact_dir.iterdir() if path.is_file()
        )