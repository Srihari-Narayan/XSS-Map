"""Utility helpers: rate limiting, terminal colors, interactive prompts."""

import time
import sys
import threading
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ── Terminal colors / prefixes ───────────────────────────────────────────────

def info(msg):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def critical(msg):
    border = f"{Fore.RED}{'═' * 55}{Style.RESET_ALL}"
    print(border)
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
    print(border)

def banner():
    art = rf"""
{Fore.RED}
 ██╗  ██╗███████╗███████╗      ███╗   ███╗ █████╗ ██████╗
 ╚██╗██╔╝██╔════╝██╔════╝      ████╗ ████║██╔══██╗██╔══██╗
  ╚███╔╝ ███████╗███████╗█████╗██╔████╔██║███████║██████╔╝
  ██╔██╗ ╚════██║╚════██║╚════╝██║╚██╔╝██║██╔══██║██╔═══╝
 ██╔╝ ██╗███████║███████║      ██║ ╚═╝ ██║██║  ██║██║
 ╚═╝  ╚═╝╚══════╝╚══════╝      ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
{Style.RESET_ALL}
 {Fore.CYAN}Adaptive XSS Scanner powered by AI/ML{Style.RESET_ALL}
 {Fore.CYAN}v0.1.0{Style.RESET_ALL}
"""
    print(art)

# ── Interactive prompts (sqlmap-style) ───────────────────────────────────────

def prompt_yn(question, default=True):
    """Yes/No prompt. Returns bool."""
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{Fore.BLUE}[?]{Style.RESET_ALL} {question} [{hint}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default
    return answer.startswith("y")


def prompt_choice(question, choices, default=None):
    """Multiple-choice prompt. Returns the selected choice string."""
    hint = "/".join(choices)
    if default:
        hint = hint.replace(default, default.upper())
    try:
        answer = input(f"{Fore.BLUE}[?]{Style.RESET_ALL} {question} [{hint}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default or choices[0]
    if not answer:
        return default or choices[0]
    # Match prefix
    for c in choices:
        if c.lower().startswith(answer.lower()):
            return c
    return default or choices[0]


def prompt_select(question, items, allow_all=True):
    """Select from numbered list. Returns list of selected indices (0-based)."""
    for i, item in enumerate(items, 1):
        print(f"    {Fore.CYAN}[{i}]{Style.RESET_ALL} {item}")
    hint = "All/1,2,3" if allow_all else "1,2,3"
    try:
        answer = input(f"{Fore.BLUE}[?]{Style.RESET_ALL} {question} [{hint}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return list(range(len(items)))
    if not answer or (allow_all and answer.lower() in ("all", "a")):
        return list(range(len(items)))
    try:
        indices = [int(x.strip()) - 1 for x in answer.split(",")]
        return [i for i in indices if 0 <= i < len(items)]
    except ValueError:
        return list(range(len(items)))


# ── Rate limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter."""

    def __init__(self, requests_per_second):
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait(self):
        """Block until the next request is allowed."""
        if self.min_interval == 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_request = time.monotonic()


# ── Misc helpers ─────────────────────────────────────────────────────────────

def extract_snippet(body, payload, context_chars=200):
    """Extract a snippet of the response body around where the payload appears."""
    idx = body.find(payload)
    if idx == -1:
        # Try URL-decoded / case-insensitive fallback
        idx = body.lower().find(payload.lower())
    if idx == -1:
        # Return first N chars as fallback
        return body[:context_chars * 2] if len(body) > context_chars * 2 else body
    start = max(0, idx - context_chars)
    end = min(len(body), idx + len(payload) + context_chars)
    snippet = body[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(body):
        snippet = snippet + "..."
    return snippet


def truncate(text, max_len=80):
    """Truncate text for display."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
