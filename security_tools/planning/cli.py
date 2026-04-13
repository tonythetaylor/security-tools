from __future__ import annotations

import argparse
from pathlib import Path

from security_tools.planning.scan_planner import build_scan_plan
from security_tools.planning.stack_detector import detect_stack
from security_tools.planning.yaml_renderer import render_child_pipeline


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a dynamic child security pipeline.")
    parser.add_argument("--root", default=".", help="Repo root to inspect.")
    parser.add_argument(
        "--output",
        default="generated-security-pipeline.yml",
        help="Output child pipeline file.",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    detected = detect_stack(args.root)
    plan = build_scan_plan(detected)
    yaml_text = render_child_pipeline(plan)

    Path(args.output).write_text(yaml_text, encoding="utf-8")

    print(plan.model_dump_json(indent=2))
    print(f"\nGenerated child pipeline: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())