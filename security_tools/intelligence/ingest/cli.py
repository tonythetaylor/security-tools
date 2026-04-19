from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from security_tools.intelligence.ingest.models import IngestResult
from security_tools.intelligence.ingest.registry import ingest_document


def _enrich_nist_800_53_dir(path: Path) -> int:
    from security_tools.intelligence.ingest.enrichers.nist_800_53_enricher import (
        enrich_nist_800_53_directory,
    )

    return enrich_nist_800_53_directory(path)


ENRICHERS: dict[str, Callable[[Path], int]] = {
    "nist_800_53": _enrich_nist_800_53_dir,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingest and enrich security guidance into YAML knowledge docs."
    )

    parser.add_argument(
        "--stage",
        choices=["parse", "enrich", "full"],
        default="full",
        help=(
            "Pipeline stage to run: "
            "'parse' writes YAML knowledge docs from the source framework document, "
            "'enrich' enriches existing YAML docs in place, "
            "'full' runs parse followed by enrich when an enricher is available."
        ),
    )

    parser.add_argument(
        "--input",
        help="Input source document path (required for parse/full).",
    )

    parser.add_argument(
        "--input-dir",
        help="Directory containing existing YAML docs to enrich (used by enrich stage).",
    )

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
        help="Directory where generated YAML knowledge docs are written or enriched.",
    )

    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print structured result as JSON.",
    )

    return parser


def _validate_args(args: argparse.Namespace) -> str | None:
    if args.stage in {"parse", "full"} and not args.input:
        return "--input is required for --stage parse and --stage full."

    if args.stage == "enrich" and not args.input_dir:
        return "--input-dir is required for --stage enrich."

    return None


def _run_parse(
    *,
    input_path: Path,
    framework: str,
    output_dir: Path,
) -> IngestResult:
    return ingest_document(
        input_file=input_path,
        framework=framework,
        output_dir=output_dir,
    )


def _run_enrich(
    *,
    framework: str,
    target_dir: Path,
) -> dict:
    enricher = ENRICHERS.get(framework)
    if enricher is None:
        raise ValueError(
            f"No enricher is registered for framework '{framework}'."
        )

    if not target_dir.exists():
        raise ValueError(f"Enrichment target directory not found: {target_dir}")

    total = enricher(target_dir)
    return {
        "framework": framework,
        "output_dir": str(target_dir),
        "enriched_files": total,
    }


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    validation_error = _validate_args(args)
    if validation_error:
        print(validation_error)
        return 2

    output_dir = Path(args.output_dir)

    try:
        if args.stage == "parse":
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"Input not found: {input_path}")
                return 2

            result = _run_parse(
                input_path=input_path,
                framework=args.framework,
                output_dir=output_dir,
            )

            if args.print_json:
                print(json.dumps(result.model_dump(mode="python"), indent=2, default=str))
            else:
                print(
                    f"Wrote {len(result.written_files)} knowledge docs to {result.output_dir}"
                )
            return 0

        if args.stage == "enrich":
            target_dir = Path(args.input_dir)
            result = _run_enrich(
                framework=args.framework,
                target_dir=target_dir,
            )

            if args.print_json:
                print(json.dumps(result, indent=2))
            else:
                print(
                    f"Enriched {result['enriched_files']} knowledge docs in {result['output_dir']}"
                )
            return 0

        # full
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Input not found: {input_path}")
            return 2

        parse_result = _run_parse(
            input_path=input_path,
            framework=args.framework,
            output_dir=output_dir,
        )

        enrich_result = None
        if args.framework in ENRICHERS:
            enrich_result = _run_enrich(
                framework=args.framework,
                target_dir=output_dir,
            )

        if args.print_json:
            payload = {
                "stage": "full",
                "framework": args.framework,
                "parse_result": parse_result.model_dump(mode="python"),
                "enrich_result": enrich_result,
            }
            print(json.dumps(payload, indent=2, default=str))
        else:
            message = (
                f"Wrote {len(parse_result.written_files)} knowledge docs to {parse_result.output_dir}"
            )
            if enrich_result is not None:
                message += (
                    f" and enriched {enrich_result['enriched_files']} docs"
                )
            print(message)

        return 0

    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 2
    except Exception as exc:
        print(f"Operation failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())