"""CLI entry point for xsshunter."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="xsshunter",
        description="XSSHUNTER — Adaptive XSS scanner powered by AI/ML",
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
        epilog="Recommended Ollama models: llama3:8b (best default), mistral:7b, gemma2:9b. "
               "Pull with: ollama pull llama3:8b",
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
        "--provider",
        choices=["ollama", "anthropic"],
        default="ollama",
        help="LLM provider for AI strategy (default: ollama)",
    )
    scan_parser.add_argument(
        "--model",
        default=None,
        help="Model name (default: llama3:8b for ollama, claude-haiku-4-5-20251001 for anthropic). "
             "Ollama recommended: llama3:8b, mistral:7b, gemma2:9b.",
    )
    scan_parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key or OAuth token (sk-ant-oat01-...). "
             "Run 'claude setup-token' to get your OAuth token. "
             "Also reads ANTHROPIC_API_KEY env var.",
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
    tuning_group.add_argument(
        "--generate",
        action="store_true",
        help="Enable AI payload generation — LLM crafts new payloads based on scan results each round",
    )

    # Output
    output_group = scan_parser.add_argument_group("output")
    output_group.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for report files (default: reports/)",
    )

    # ── setup subcommand ──────────────────────────────────────────────────
    subparsers.add_parser(
        "setup",
        help="Configure API keys and default provider for xsshunter",
    )

    # ── Parse and dispatch ───────────────────────────────────────────────
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "tag":
        from xsshunter_ai.tagger import tag_payloads
        from xsshunter_ai.utils import banner
        banner()
        ok = tag_payloads(args.file, args.output)
        sys.exit(0 if ok else 1)

    elif args.command == "setup":
        from xsshunter_ai.config import run_setup
        run_setup()

    elif args.command == "scan":
        from xsshunter_ai.scanner import scan
        scan(args)


if __name__ == "__main__":
    main()
