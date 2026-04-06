"""CLI entry point for xss-map."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="xss-map",
        description="Adaptive XSS scanner powered by AI/ML via Ollama",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── tag subcommand ───────────────────────────────────────────────────
    tag_parser = subparsers.add_parser(
        "tag",
        help="Classify payloads file into categories (instant, no Ollama needed)",
    )
    tag_parser.add_argument(
        "-f", "--file",
        default="payloads.txt",
        help="Path to raw payloads file (default: payloads.txt)",
    )
    tag_parser.add_argument(
        "-o", "--output",
        default="payloads_tagged.json",
        help="Output path for tagged JSON (default: payloads_tagged.json)",
    )

    # ── scan subcommand ──────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run adaptive XSS scan against a target URL",
    )
    scan_parser.add_argument(
        "url",
        help="Target URL to scan",
    )
    scan_parser.add_argument(
        "-p", "--param",
        action="append",
        help="Specify parameter(s) to test (can be repeated). "
             "If omitted, parameters are auto-discovered.",
    )
    scan_parser.add_argument(
        "-m", "--method",
        default=None,
        choices=["GET", "POST"],
        help="HTTP method for user-specified params (default: auto)",
    )
    scan_parser.add_argument(
        "--payloads",
        default="payloads_tagged.json",
        help="Path to tagged payloads JSON (default: payloads_tagged.json)",
    )
    scan_parser.add_argument(
        "--model",
        default="llama3",
        help="Ollama model for response analysis (default: llama3)",
    )
    scan_parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama API base URL (default: http://localhost:11434)",
    )

    # Auth options
    auth_group = scan_parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-c", "--cookie",
        action="append",
        help="Cookie in name=value format (can be repeated)",
    )
    auth_group.add_argument(
        "-H", "--header",
        action="append",
        help="Custom header in Name:Value format (can be repeated)",
    )
    auth_group.add_argument(
        "--bearer",
        dest="bearer",
        help="Bearer token for Authorization header",
    )

    # Scan tuning
    tuning_group = scan_parser.add_argument_group("scan tuning")
    tuning_group.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        help="Max requests per second (default: 10)",
    )
    tuning_group.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Payloads per round per injection point (default: 10)",
    )
    tuning_group.add_argument(
        "--max-rounds",
        type=int,
        default=10,
        help="Max adaptive rounds per injection point (default: 10)",
    )
    tuning_group.add_argument(
        "--batch",
        action="store_true",
        help="Non-interactive mode — skip all prompts during scan",
    )

    # Output
    output_group = scan_parser.add_argument_group("output")
    output_group.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for report files (default: reports/)",
    )

    # ── Parse and dispatch ───────────────────────────────────────────────
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "tag":
        from xss_map.tagger import tag_payloads
        from xss_map.utils import banner
        banner()
        ok = tag_payloads(args.file, args.output)
        sys.exit(0 if ok else 1)

    elif args.command == "scan":
        from xss_map.scanner import scan
        scan(args)


if __name__ == "__main__":
    main()
