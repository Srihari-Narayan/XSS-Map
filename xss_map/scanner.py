"""Scanner — main orchestrator with adaptive payload loop and interactive prompts."""

import json
import os
import random
import requests as req
from xss_map.analyzer import Analyzer
from xss_map.crawler import crawl, display_injection_points, InjectionPoint
from xss_map.injector import inject
from xss_map.reporter import Reporter
from xss_map.utils import (
    RateLimiter,
    banner,
    critical,
    error,
    info,
    prompt_select,
    prompt_yn,
    success,
    truncate,
    warning,
)


def _load_tagged_payloads(path):
    """Load tagged payloads JSON. Returns dict: category -> [payload_str, ...]."""
    with open(path, "r", encoding="utf-8") as f:
        entries = json.load(f)
    by_category = {}
    for entry in entries:
        cat = entry["category"]
        by_category.setdefault(cat, []).append(entry["payload"])
    return by_category


def _build_session(cookies, headers, bearer_token):
    """Build a requests.Session with auth configured."""
    session = req.Session()
    if cookies:
        for cookie_str in cookies:
            if "=" in cookie_str:
                name, _, value = cookie_str.partition("=")
                session.cookies.set(name.strip(), value.strip())
    if bearer_token:
        session.headers["Authorization"] = f"Bearer {bearer_token}"
    if headers:
        for h in headers:
            if ":" in h:
                name, _, value = h.partition(":")
                session.headers[name.strip()] = value.strip()
    return session


def _pick_payloads(payloads_by_cat, category, max_payloads):
    """Pick payloads from the suggested category, falling back to others."""
    if category in payloads_by_cat and payloads_by_cat[category]:
        pool = payloads_by_cat[category]
    else:
        pool = [p for plist in payloads_by_cat.values() for p in plist]

    if len(pool) <= max_payloads:
        return pool
    return random.sample(pool, max_payloads)


def scan(args):
    """Run the adaptive XSS scan."""
    banner()

    # ── Validate inputs ──────────────────────────────────────────────────
    payloads_file = args.payloads
    if not os.path.isfile(payloads_file):
        error(f"Tagged payloads file not found: {payloads_file}")
        error("Run 'xss-map tag' first to classify your payloads.")
        return

    info(f"Target URL: {args.url}")

    # ── Confirm target (sqlmap-style) ────────────────────────────────────
    if not prompt_yn(f"Are you sure you want to test: {args.url}?"):
        info("Aborting.")
        return

    # ── Build session ────────────────────────────────────────────────────
    session = _build_session(args.cookie, args.header, args.bearer)
    rate_limiter = RateLimiter(args.rate_limit)

    # ── Load payloads ────────────────────────────────────────────────────
    payloads_by_cat = _load_tagged_payloads(payloads_file)
    total_payloads = sum(len(v) for v in payloads_by_cat.values())
    info(f"Loaded {total_payloads} tagged payloads across {len(payloads_by_cat)} categories")

    # ── Discover injection points ────────────────────────────────────────
    if args.param:
        points = []
        for p in args.param:
            points.append(InjectionPoint(
                url=args.url, method=args.method or "GET",
                param_name=p, param_type="query",
            ))
        info(f"Using {len(points)} user-specified parameter(s)")
    else:
        info("Crawling page to discover injection points...")
        points = crawl(args.url, session)

    if not points:
        error("No injection points found. Try specifying params with --param.")
        return

    display_injection_points(points)

    # ── Let user select which injection points to test ───────────────────
    selected_indices = prompt_select("Select injection points to test:", [str(p) for p in points], already_displayed=True)
    if not selected_indices:
        info("No injection points selected. Aborting.")
        return
    points = [points[i] for i in selected_indices]

    # ── Resolve provider, model, and API key (CLI > env > config) ───────
    from xss_map.config import load_config
    config = load_config()

    provider = args.provider or config.get("provider", "ollama")
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY") or config.get("anthropic_api_key")
    ollama_url = args.ollama_url or config.get("ollama_url", "http://localhost:11434")

    model = args.model
    if not model:
        if provider == "anthropic":
            model = config.get("anthropic_model", "claude-haiku-4-5-20251001")
        else:
            model = config.get("ollama_model", "llama3:8b")

    if provider == "anthropic" and not api_key:
        error("Anthropic provider requires an API key or OAuth token.")
        info("Tip: Run 'xss-map setup' to configure, or pass --api-key")
        return

    info(f"AI provider: {provider} (model: {model})")

    # ── Initialize analyzer & reporter ───────────────────────────────────
    analyzer = Analyzer(
        model=model, ollama_url=ollama_url,
        provider=provider, api_key=api_key,
    )
    reporter = Reporter(target_url=args.url)

    # ── Scan each injection point ────────────────────────────────────────
    confirmed_xss = []
    payloads_per_round = args.batch_size
    max_rounds = args.max_rounds

    for ip_idx, ip in enumerate(points):
        info(f"\n{'=' * 55}")
        info(f"Testing injection point {ip_idx + 1}/{len(points)}: {ip}")
        info(f"{'=' * 55}")

        tested_payloads = set()
        xss_found_for_point = False
        focused_categories = set()
        stop_point = False

        for round_num in range(1, max_rounds + 1):
            # ── Pick category ────────────────────────────────────────
            if round_num == 1:
                # First round: sample broadly across all categories
                info(f"Round {round_num}: Broad sampling across categories")
                batch = _pick_payloads(payloads_by_cat, "__all__", payloads_per_round)
                current_category = "mixed"
            else:
                # Ask Ollama for strategy (ONE call per round)
                info(f"Round {round_num}: Asking AI for next strategy...")
                suggested = analyzer.suggest_next_category(focused_categories)
                if not suggested:
                    # Fallback: use heuristic
                    suggested = analyzer.get_best_category_heuristic()
                if suggested:
                    current_category = suggested
                    focused_categories.add(current_category)
                    info(f"Round {round_num}: Focusing on '{current_category}'")
                    batch = _pick_payloads(payloads_by_cat, current_category, payloads_per_round)
                else:
                    info(f"Round {round_num}: No clear suggestion, sampling broadly")
                    batch = _pick_payloads(payloads_by_cat, "__all__", payloads_per_round)
                    current_category = "mixed"

            # Filter already-tested
            batch = [p for p in batch if p not in tested_payloads]
            if not batch:
                warning("No untested payloads left for this strategy. Moving on.")
                break

            # ── Fire batch (all heuristic, fast) ─────────────────────
            round_reflected = 0
            round_total = 0

            for payload in batch:
                tested_payloads.add(payload)
                display_payload = truncate(payload, 70)
                round_total += 1

                result = inject(session, ip, payload, rate_limiter)
                if result is None:
                    warning(f"  Request failed: {display_payload}")
                    continue

                label = analyzer.classify(
                    payload, result.response_body, result.status_code,
                    category=current_category,
                )

                if label == "reflected":
                    success(f"  REFLECTED  {display_payload}")
                    confirmed_xss.append(result)
                    reporter.add_finding(ip, payload, label, result.status_code, result.snippet)
                    xss_found_for_point = True
                    round_reflected += 1
                elif label == "filtered":
                    warning(f"  FILTERED   {display_payload}")
                    reporter.add_finding(ip, payload, label, result.status_code, result.snippet)
                elif label == "blocked":
                    error(f"  BLOCKED    {display_payload}")
                else:
                    pass  # not_reflected — silent to reduce noise

            # ── Round summary ────────────────────────────────────────
            info(f"  Round {round_num} done: {round_reflected}/{round_total} reflected")

            # ── Ask user after round if XSS found ────────────────────
            if xss_found_for_point and not args.batch:
                if not prompt_yn("XSS found! Continue testing this injection point?", default=False):
                    stop_point = True
                    break

        # After finishing an injection point, ask about next
        if ip_idx < len(points) - 1 and not args.batch:
            if not prompt_yn("Continue to next injection point?"):
                info("Stopping scan at user request.")
                break

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    info(f"{'=' * 55}")
    if confirmed_xss:
        critical(f"Found {len(confirmed_xss)} confirmed XSS reflection(s)!")
    else:
        info("No confirmed XSS reflections found.")
    info(f"{'=' * 55}")

    # ── Generate reports ─────────────────────────────────────────────────
    if reporter.findings:
        report_dir = args.output_dir or "reports"
        os.makedirs(report_dir, exist_ok=True)
        reporter.save_json(os.path.join(report_dir, "xss_map_report.json"))
        reporter.save_html(os.path.join(report_dir, "xss_map_report.html"))

    # Category stats
    stats = analyzer.get_category_stats()
    if stats:
        info("\nCategory effectiveness:")
        for cat, s in sorted(stats.items(), key=lambda x: -x[1]["total"]):
            ref = s.get("reflected", 0)
            filt = s.get("filtered", 0)
            blk = s.get("blocked", 0)
            print(f"    {cat:25s}  reflected={ref}  filtered={filt}  blocked={blk}  total={s['total']}")
