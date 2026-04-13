from __future__ import annotations

from pathlib import Path

import fitz  # PyMuPDF


def extract_pdf_text(path: str | Path) -> str:
    p = Path(path)
    parts: list[str] = []

    with fitz.open(p) as doc:
        for page_num, page in enumerate(doc, start=1):
            text = page.get_text("text")
            if text and text.strip():
                parts.append(f"\n--- PAGE {page_num} ---\n{text.strip()}")

    return "\n".join(parts).strip()


def extract_plain_text(path: str | Path) -> str:
    p = Path(path)
    return p.read_text(encoding="utf-8", errors="ignore")


def extract_text(path: str | Path) -> str:
    p = Path(path)

    suffix = p.suffix.lower()

    if suffix == ".pdf":
        return extract_pdf_text(p)

    if suffix in {
        ".txt",
        ".md",
        ".rst",
        ".log",
        ".yml",
        ".yaml",
    }:
        return extract_plain_text(p)

    raise ValueError(f"Unsupported file type: {suffix or '<none>'}")