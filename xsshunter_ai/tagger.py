"""Payload tagger — categorizes payloads using regex pattern matching."""

import json
import os
import re
from xsshunter_ai.utils import info, success, error

CATEGORIES = [
    "script_tag",
    "event_handler",
    "encoded",
    "svg_tag",
    "img_tag",
    "iframe_tag",
    "javascript_uri",
    "style_injection",
    "template_injection",
    "polyglot",
    "dom_manipulation",
    "tag_breakout",
    "other",
]

# Order matters — first match wins, so more specific patterns go first
_RULES = [
    # Template injection (Angular, Moustache, etc.)
    (re.compile(r"\{\{.*\}\}", re.I), "template_injection"),

    # Polyglots — long multi-vector payloads hitting several contexts at once
    (re.compile(
        r"(?=.*<)(?=.*on\w+=)(?=.*(?:javascript:|alert|confirm|prompt))",
        re.I | re.S,
    ), "polyglot"),

    # SVG tags
    (re.compile(r"<\s*/?svg[\s/>]", re.I), "svg_tag"),

    # IMG tags
    (re.compile(r"<\s*img[\s/>]", re.I), "img_tag"),

    # Iframe tags
    (re.compile(r"<\s*iframe[\s/>]", re.I), "iframe_tag"),

    # Script tags
    (re.compile(r"<\s*/?script[\s/>]", re.I), "script_tag"),

    # Style injection — expression(), background url(javascript:), etc.
    (re.compile(r"(expression\s*\(|style\s*=|background[:\-].*url\s*\()", re.I), "style_injection"),

    # javascript: URI scheme
    (re.compile(r"javascript\s*:", re.I), "javascript_uri"),

    # Heavily encoded payloads (>40% are %XX or &#xNN sequences)
    (re.compile(r"(?:%[0-9a-fA-F]{2}.*){5}"), "encoded"),
    (re.compile(r"(?:&#x?[0-9a-fA-F]+;.*){3}", re.I), "encoded"),

    # Event handlers (onerror, onload, onfocus, onclick, etc.)
    (re.compile(r"on[a-z]{3,}[\s]*=", re.I), "event_handler"),

    # DOM manipulation keywords
    (re.compile(
        r"(document\s*[\.\[]|window\s*[\.\[]|sessionStorage|localStorage|\.cookie|\.domain)",
        re.I,
    ), "dom_manipulation"),

    # Tag breakout — starts with ", '>, "> or closes a tag to escape context
    (re.compile(r"""^[\s]*['">\-/\\]*\s*[<>]"""), "tag_breakout"),
    (re.compile(r"</\s*\w+\s*>"), "tag_breakout"),
]


def _classify_payload(payload):
    """Classify a single payload using regex rules."""
    for pattern, category in _RULES:
        if pattern.search(payload):
            return category
    return "other"


def tag_payloads(payloads_file, output_file, **_kwargs):
    """Read payloads from file, classify with regex rules, write tagged JSON."""
    if not os.path.isfile(payloads_file):
        error(f"Payloads file not found: {payloads_file}")
        return False

    with open(payloads_file, "r", encoding="utf-8", errors="replace") as f:
        payloads = [line.strip() for line in f if line.strip()]

    info(f"Loaded {len(payloads)} payloads from {payloads_file}")
    info("Classifying with pattern matching...")

    tagged = []
    for payload in payloads:
        tagged.append({"payload": payload, "category": _classify_payload(payload)})

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(tagged, f, indent=2, ensure_ascii=False)

    cat_counts = {}
    for entry in tagged:
        cat_counts[entry["category"]] = cat_counts.get(entry["category"], 0) + 1

    success(f"Tagged {len(tagged)} payloads -> {output_file}")
    info("Category distribution:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:25s} {count}")

    return True
