"""Offline payload tagger — categorizes payloads via Ollama and saves to JSON."""

import json
import os
import requests as req
from xss_map.utils import info, success, warning, error, call_ollama_chat

# Payload categories the model should choose from
CATEGORIES = [
    "script_tag",           # <script>...</script>
    "event_handler",        # onerror, onload, onfocus, onclick, etc.
    "encoded",              # URL-encoded, hex-encoded, double-encoded, base64
    "svg_tag",              # <svg onload=...>
    "img_tag",              # <img src=x onerror=...>
    "iframe_tag",           # <iframe src=javascript:...>
    "javascript_uri",       # javascript:alert(1)
    "style_injection",      # expression(), background-image:url(js:...)
    "template_injection",   # {{constructor...}}, AngularJS sandbox escapes
    "polyglot",             # Multi-context payloads
    "dom_manipulation",     # document.cookie, document.domain, sessionStorage
    "tag_breakout",         # ">..., '>, closing tags to escape context
    "other",                # Anything that doesn't fit above
]

BATCH_SIZE = 10  # payloads per Ollama call

SYSTEM_PROMPT = f"""You are a cybersecurity payload classifier. Given a list of XSS payloads, classify each one into exactly ONE of these categories:

{chr(10).join(f"- {c}" for c in CATEGORIES)}

Rules:
- If a payload fits multiple categories, choose the MOST SPECIFIC one (e.g. an <img> with onerror is "img_tag", not "event_handler").
- "polyglot" is for payloads that intentionally target multiple contexts.
- "encoded" is for payloads where the primary evasion technique is encoding.
- "tag_breakout" is for payloads whose primary purpose is escaping an HTML attribute/tag context.

Respond with ONLY a JSON array of category strings, one per payload, in the same order.
Example input: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
Example output: ["script_tag", "img_tag"]
"""


def _call_ollama(payloads_batch, model, ollama_url):
    """Send a batch of payloads to Ollama for classification."""
    prompt = json.dumps(payloads_batch)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    try:
        content = call_ollama_chat(ollama_url, model, messages, timeout=300)
        # Extract JSON array from response (model may wrap it in markdown)
        if "```" in content:
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        categories = json.loads(content)
        # Validate
        validated = []
        for cat in categories:
            validated.append(cat if cat in CATEGORIES else "other")
        return validated
    except (req.RequestException, json.JSONDecodeError, KeyError, IndexError) as e:
        error(f"Ollama call failed: {e}")
        return None


def tag_payloads(payloads_file, output_file, model, ollama_url):
    """Read payloads from file, classify via Ollama in batches, write tagged JSON."""
    if not os.path.isfile(payloads_file):
        error(f"Payloads file not found: {payloads_file}")
        return False

    with open(payloads_file, "r", encoding="utf-8", errors="replace") as f:
        payloads = [line.strip() for line in f if line.strip()]

    info(f"Loaded {len(payloads)} payloads from {payloads_file}")
    info(f"Classifying in batches of {BATCH_SIZE} using model '{model}'...")

    tagged = []
    total_batches = (len(payloads) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(payloads), BATCH_SIZE):
        batch_num = i // BATCH_SIZE + 1
        batch = payloads[i : i + BATCH_SIZE]
        info(f"  Batch {batch_num}/{total_batches} ({len(batch)} payloads)...")

        categories = _call_ollama(batch, model, ollama_url)

        if categories is None or len(categories) != len(batch):
            warning(f"  Batch {batch_num} returned invalid results — tagging as 'other'")
            categories = ["other"] * len(batch)

        for payload, category in zip(batch, categories):
            tagged.append({"payload": payload, "category": category})

    # Write output
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(tagged, f, indent=2, ensure_ascii=False)

    # Summary
    cat_counts = {}
    for entry in tagged:
        cat_counts[entry["category"]] = cat_counts.get(entry["category"], 0) + 1

    success(f"Tagged {len(tagged)} payloads → {output_file}")
    info("Category distribution:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:25s} {count}")

    return True
