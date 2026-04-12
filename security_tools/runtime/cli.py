from __future__ import annotations

import argparse

from security_tools.runtime.executor import run_runtime_verification
from security_tools.runtime.renderers import write_json_report, write_markdown_summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Container runtime verification for built images."
    )
    parser.add_argument("--image", required=True, help="Image tag to verify.")
    parser.add_argument("--dockerfile", default="Dockerfile", help="Dockerfile path.")
    parser.add_argument("--context", default=".", help="Docker build context.")
    parser.add_argument(
        "--startup-timeout",
        type=int,
        default=45,
        help="Startup timeout in seconds.",
    )
    parser.add_argument(
        "--output-json",
        default="runtime-report.json",
        help="JSON report path.",
    )
    parser.add_argument(
        "--output-md",
        default="runtime-summary.md",
        help="Markdown summary path.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Do not build the image if missing.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    report = run_runtime_verification(
        image=args.image,
        startup_timeout_seconds=args.startup_timeout,
        dockerfile_path=args.dockerfile,
        context_dir=args.context,
        build_if_missing=not args.no_build,
    )

    write_json_report(report, args.output_json)
    write_markdown_summary(report, args.output_md)
    print(report.model_dump_json(indent=2))

    if report.verdict == "BLOCK":
        return 1
    if report.verdict == "OPERATIONAL_ERROR":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())