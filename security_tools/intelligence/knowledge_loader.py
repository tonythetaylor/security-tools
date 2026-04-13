from __future__ import annotations

from pathlib import Path

import yaml

from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


def _parse_doc(path: Path) -> KnowledgeDocument | None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    refs = []
    for item in raw.get("compliance_refs", []) or []:
        if isinstance(item, dict) and item.get("framework") and item.get("control"):
            refs.append(
                ComplianceReference(
                    framework=str(item["framework"]),
                    control=str(item["control"]),
                    note=str(item["note"]) if item.get("note") else None,
                )
            )

    try:
        return KnowledgeDocument(
            id=str(raw.get("id") or path.stem),
            title=str(raw.get("title") or path.stem),
            category=str(raw.get("category") or "general"),
            applies_to=list(raw.get("applies_to", []) or []),
            tags=list(raw.get("tags", []) or []),
            severity_guidance=str(raw.get("severity_guidance") or "unknown"),
            description=str(raw.get("description") or ""),
            rationale=str(raw.get("rationale") or ""),
            developer_guidance=str(raw.get("developer_guidance") or ""),
            recommended_patterns=list(raw.get("recommended_patterns", []) or []),
            bad_examples=list(raw.get("bad_examples", []) or []),
            good_examples=list(raw.get("good_examples", []) or []),
            compliance_refs=refs,
            risk_context=dict(raw.get("risk_context", {}) or {}),
            ownership=dict(raw.get("ownership", {}) or {}),
            remediation=dict(raw.get("remediation", {}) or {}),
            source_path=str(raw.get("source_path")) if raw.get("source_path") else str(path),
            source_type=str(raw.get("source_type") or "knowledge"),
        )
    except Exception:
        return None


def load_knowledge_documents(root: str | Path | None = None) -> list[KnowledgeDocument]:
    if root is None:
        root = Path(__file__).parent / "knowledge"

    root_path = Path(root)
    if not root_path.exists():
        return []

    docs: list[KnowledgeDocument] = []

    for path in list(root_path.rglob("*.yml")) + list(root_path.rglob("*.yaml")):
        doc = _parse_doc(path)
        if doc:
            docs.append(doc)

    return docs