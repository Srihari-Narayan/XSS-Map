"""Config management — stores API keys and defaults in ~/.xsshunter/config.json."""

import json
import os
from pathlib import Path
from xsshunter_ai.utils import banner, info, success, warning, error, prompt_choice

CONFIG_DIR = Path.home() / ".xsshunter"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    """Load config from disk. Returns dict."""
    if CONFIG_FILE.is_file():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(config):
    """Save config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def run_setup():
    """Interactive setup wizard."""
    banner()
    info("xsshunter setup")
    info(f"Config will be saved to: {CONFIG_FILE}\n")

    config = load_config()

    # ── Provider ────────────────────────────────────────────────────────
    current_provider = config.get("provider", "ollama")
    provider = prompt_choice(
        f"Default LLM provider (current: {current_provider})",
        ["ollama", "anthropic"],
        default=current_provider,
    )
    config["provider"] = provider

    # ── Anthropic setup ─────────────────────────────────────────────────
    if provider == "anthropic":
        info("\nAnthropic API setup:")
        info("  Paste your API key (sk-ant-api03-...)\n")

        current_key = config.get("anthropic_api_key", "")
        masked = _mask_key(current_key) if current_key else "not set"

        try:
            key = input(f"[?] Anthropic API key [{masked}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            key = ""

        if key:
            config["anthropic_api_key"] = key
            success("API key saved.")
        elif current_key:
            info("Keeping existing key.")

        # Model
        current_model = config.get("anthropic_model", "claude-haiku-4-5-20251001")
        try:
            model = input(f"[?] Default Anthropic model [{current_model}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            model = ""
        config["anthropic_model"] = model if model else current_model

    # ── Ollama setup ────────────────────────────────────────────────────
    if provider == "ollama":
        current_url = config.get("ollama_url", "http://localhost:11434")
        try:
            url = input(f"[?] Ollama URL [{current_url}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            url = ""
        config["ollama_url"] = url if url else current_url

        current_model = config.get("ollama_model", "llama3:8b")
        try:
            model = input(f"[?] Default Ollama model [{current_model}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            model = ""
        config["ollama_model"] = model if model else current_model

    # ── Save ────────────────────────────────────────────────────────────
    save_config(config)
    print()
    success(f"Config saved to {CONFIG_FILE}")
    info("These defaults are used when --provider/--api-key/--model are not passed on the CLI.")


def _mask_key(key):
    """Mask a key for display, showing first 10 and last 4 chars."""
    if len(key) <= 16:
        return key[:4] + "..." + key[-4:]
    return key[:10] + "..." + key[-4:]
