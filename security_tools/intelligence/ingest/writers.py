from __future__ import annotations

from pathlib import Path

import yaml

from security_tools.intelligence.models import KnowledgeDocument


def write_knowledge_doc(doc: KnowledgeDocument, output_dir: str | Path) -> Path:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    path = out_dir / f"{doc.id}.yml"
    path.write_text(
        yaml.safe_dump(
            doc.model_dump(mode="python"),
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path