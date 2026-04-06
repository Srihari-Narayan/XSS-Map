"""Response analyzer — fast heuristic classification + Ollama for round-level strategy."""

import json
import requests as req
from xss_map.utils import info, warning, call_ollama_chat, call_anthropic_chat
from xss_map.tagger import CATEGORIES

RESULT_LABELS = ["reflected", "filtered", "blocked", "not_reflected"]

STRATEGY_SYSTEM = """You are a cybersecurity expert advising an adaptive XSS scanner.
Your job: given test results so far, pick the NEXT payload category to maximize XSS discovery.

Available categories (pick EXACTLY one):
""" + "\n".join(f"- {cat}" for cat in CATEGORIES) + """

Rules:
1. Favor categories with high reflected/total ratio — they indicate weak filtering.
2. Avoid categories with high blocked rate — the WAF catches those.
3. If "filtered" is high for a category, a related category with encoding or different tags may bypass the filter.
4. Prefer untested or under-tested categories over exhausted ones.

You MUST respond with ONLY a valid JSON object. No markdown, no explanation, no code fences.

Example response:
{"next_category": "event_handler", "reasoning": "script_tag is blocked but event handlers are less filtered"}

Another example:
{"next_category": "encoded", "reasoning": "svg_tag payloads are filtered, encoded variants may bypass"}
"""


class Analyzer:
    """Heuristic response classification + LLM for round-level strategy."""

    def __init__(self, model, ollama_url, provider="ollama", api_key=None):
        self.model = model
        self.ollama_url = ollama_url
        self.provider = provider
        self.api_key = api_key
        self.history = []  # list of {payload, category, result}

    def classify(self, payload, response_body, status_code, category="unknown"):
        """Fast heuristic classification — no Ollama call."""
        if status_code in (403, 406, 429, 503):
            result = "blocked"
        elif payload in response_body:
            result = "reflected"
        elif payload.lower() in response_body.lower():
            result = "filtered"
        else:
            # Check partial reflection
            triggers = ["alert", "confirm", "prompt", "onerror", "onload",
                        "onfocus", "onmouseover", "script", "svg", "img"]
            body_lower = response_body.lower()
            payload_lower = payload.lower()
            result = "not_reflected"
            for trigger in triggers:
                if trigger in payload_lower and trigger in body_lower:
                    result = "filtered"
                    break

        self.history.append({
            "payload": payload[:80],
            "category": category,
            "result": result,
        })
        return result

    def suggest_next_category(self, tested_categories=None):
        """
        Call Ollama ONCE to decide the next payload category based on round results.
        Returns category string, or None on failure.
        """
        if not self.history:
            return None

        # Build a compact summary of results by category
        cat_summary = {}
        for h in self.history:
            cat = h["category"]
            if cat not in cat_summary:
                cat_summary[cat] = {"reflected": 0, "filtered": 0, "blocked": 0, "not_reflected": 0, "total": 0}
            cat_summary[cat]["total"] += 1
            cat_summary[cat][h["result"]] += 1

        summary_lines = []
        for cat, s in cat_summary.items():
            summary_lines.append(
                f"  {cat}: {s['total']} tested, "
                f"{s['reflected']} reflected, {s['filtered']} filtered, "
                f"{s['blocked']} blocked, {s['not_reflected']} not reflected"
            )

        already_tried = ""
        if tested_categories:
            already_tried = f"\nCategories already focused on: {', '.join(tested_categories)}"

        user_prompt = f"""Results so far:
{chr(10).join(summary_lines)}
{already_tried}

Which category should we focus on next to maximize our chances of finding XSS? Pick a category we haven't exhausted yet."""

        messages = [
            {"role": "system", "content": STRATEGY_SYSTEM},
            {"role": "user", "content": user_prompt},
        ]

        try:
            if self.provider == "anthropic":
                content = call_anthropic_chat(
                    self.api_key, self.model, messages, timeout=120,
                )
            else:
                content = call_ollama_chat(
                    self.ollama_url, self.model, messages, timeout=120,
                )

            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            result = json.loads(content)
            next_cat = result.get("next_category", "")
            reasoning = result.get("reasoning", "")

            if next_cat in CATEGORIES:
                if reasoning:
                    info(f"  AI reasoning: {reasoning}")
                return next_cat

            return None

        except (req.RequestException, json.JSONDecodeError, KeyError) as e:
            warning(f"AI strategy call failed: {e}")
            return None

    def get_best_category_heuristic(self):
        """Fallback: pick the category with the highest reflected ratio."""
        cat_stats = {}
        for h in self.history:
            cat = h["category"]
            if cat not in cat_stats:
                cat_stats[cat] = {"reflected": 0, "total": 0}
            cat_stats[cat]["total"] += 1
            if h["result"] == "reflected":
                cat_stats[cat]["reflected"] += 1

        best_cat = None
        best_ratio = -1
        for cat, s in cat_stats.items():
            ratio = s["reflected"] / s["total"] if s["total"] > 0 else 0
            if ratio > best_ratio:
                best_ratio = ratio
                best_cat = cat
        return best_cat

    def get_category_stats(self):
        """Return stats per category from history."""
        stats = {}
        for h in self.history:
            cat = h["category"]
            if cat not in stats:
                stats[cat] = {"reflected": 0, "filtered": 0, "blocked": 0, "total": 0}
            stats[cat]["total"] += 1
            if h["result"] in stats[cat]:
                stats[cat][h["result"]] += 1
        return stats
