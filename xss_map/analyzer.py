"""Ollama-powered response analyzer — classifies injection results and suggests next category."""

import json
import requests as req
from xss_map.utils import info, warning, error
from xss_map.tagger import CATEGORIES

# Classification labels for server responses
RESULT_LABELS = [
    "reflected",      # Payload appears in response unmodified
    "filtered",       # Payload partially stripped / sanitized but still present
    "blocked",        # WAF / server rejected the request entirely
    "encoded_back",   # Payload was HTML-entity / URL-encoded by the server
    "not_reflected",  # Payload does not appear in the response at all
    "executed",       # Evidence the payload would execute (for stored XSS confirmation)
]

CLASSIFY_SYSTEM = f"""You are a cybersecurity analyst reviewing HTTP response snippets after an XSS payload was injected.

Classify the server's handling of the payload into ONE of these labels:
{chr(10).join(f"- {lbl}" for lbl in RESULT_LABELS)}

Then, given the classification and the history of previous attempts, recommend which payload CATEGORY to try next from this list:
{chr(10).join(f"- {cat}" for cat in CATEGORIES)}

Respond with ONLY a JSON object: {{"result": "<label>", "next_category": "<category>", "reasoning": "<1 sentence>"}}
"""


class Analyzer:
    """Uses Ollama to classify injection responses and adapt strategy."""

    def __init__(self, model, ollama_url):
        self.model = model
        self.ollama_url = ollama_url
        self.history = []  # list of {payload, category, result_label}

    def classify(self, payload, category, response_snippet, status_code):
        """
        Classify the server response and get next-category suggestion.

        Returns:
            dict with keys: result, next_category, reasoning
            or None on failure.
        """
        history_summary = ""
        if self.history:
            recent = self.history[-10:]  # last 10 attempts
            lines = []
            for h in recent:
                lines.append(f"  - [{h['category']}] → {h['result']}")
            history_summary = "Recent attempt history:\n" + "\n".join(lines)

        user_prompt = f"""Payload sent: {payload}
Payload category: {category}
HTTP status code: {status_code}

Response snippet around injection point:
---
{response_snippet[:1500]}
---

{history_summary}

Classify this result and recommend the next payload category to try."""

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": CLASSIFY_SYSTEM},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }

        try:
            resp = req.post(f"{self.ollama_url}/api/chat", json=body, timeout=60)
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()

            # Parse JSON from response
            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            result = json.loads(content)

            # Validate
            if result.get("result") not in RESULT_LABELS:
                result["result"] = "not_reflected"
            if result.get("next_category") not in CATEGORIES:
                result["next_category"] = "other"

            # Record history
            self.history.append({
                "payload": payload[:80],
                "category": category,
                "result": result["result"],
            })

            return result

        except (req.RequestException, json.JSONDecodeError, KeyError) as e:
            warning(f"Analyzer call failed: {e}")
            return None

    def quick_classify(self, payload, response_body, status_code):
        """
        Fast heuristic classification without calling Ollama.
        Used as fallback or for rate-limited scenarios.
        """
        result = "not_reflected"

        if status_code in (403, 406, 429, 503):
            result = "blocked"
        elif payload in response_body:
            result = "reflected"
        elif payload.lower() in response_body.lower():
            result = "filtered"
        else:
            # Check for partial reflection (common filter behavior)
            # Strip tags and check if core trigger word is present
            triggers = ["alert", "confirm", "prompt", "onerror", "onload"]
            body_lower = response_body.lower()
            for trigger in triggers:
                if trigger in payload.lower() and trigger in body_lower:
                    result = "filtered"
                    break

        self.history.append({
            "payload": payload[:80],
            "category": "unknown",
            "result": result,
        })
        return result

    def get_category_stats(self):
        """Return success/failure stats per category from history."""
        stats = {}
        for h in self.history:
            cat = h["category"]
            if cat not in stats:
                stats[cat] = {"reflected": 0, "filtered": 0, "blocked": 0, "total": 0}
            stats[cat]["total"] += 1
            if h["result"] in stats[cat]:
                stats[cat][h["result"]] += 1
        return stats
