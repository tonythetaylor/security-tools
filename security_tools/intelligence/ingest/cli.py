from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_tools.intelligence.ingest.models import IngestResult
from security_tools.intelligence.ingest.registry import ingest_document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingest security guidance into YAML knowledge docs."
    )
    parser.add_argument("--input", required=True, help="Input file path.")
    parser.add_argument(
        "--framework",
        required=True,
        help=(
            "Framework name, e.g. cis, cis_safeguards, cis_all, "
            "nist_800_53, nist_800_190, stig, fedramp."
        ),
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where generated YAML knowledge docs will be written.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print structured ingest result as JSON.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    if not input_path.exists():
        print(f"Input not found: {input_path}")
        return 2

    try:
        result: IngestResult = ingest_document(
            input_file=input_path,
            framework=args.framework,
            output_dir=output_dir,
        )
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 2
    except Exception as exc:
        print(f"Ingest failed: {exc}")
        return 2

    if args.print_json:
        print(json.dumps(result.model_dump(mode="python"), indent=2, default=str))
    else:
        print(f"Wrote {len(result.written_files)} knowledge docs to {result.output_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())