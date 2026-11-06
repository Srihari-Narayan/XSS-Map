```
██╗  ██╗███████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
╚██╗██╔╝██╔════╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔██╗ ╚════██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██╔╝ ██╗███████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Adaptive XSS scanner powered by AI/ML.** Uses LLMs to intelligently select payload categories and generate new payloads at runtime based on how the target responds.

---

## Features

- **Adaptive payload selection** — LLM picks which payload category to try next based on what reflected/filtered/blocked
- **AI payload generation** — LLM crafts new payloads at runtime to bypass observed filters (`--generate`)
- **Heuristic response classification** — instant per-payload classification (reflected, filtered, blocked, not reflected)
- **Regex-based payload tagging** — categorizes payloads into 13 categories without needing an LLM
- **Single-page crawling** — auto-discovers query params, form fields, and header injection points
- **Authentication support** — cookies, bearer tokens, custom headers
- **Rate limiting** — configurable token-bucket rate limiter (default 10 req/s)
- **JSON + HTML reports** — dark-themed HTML report with collapsible details
- **Interactive or batch mode** — sqlmap-style prompts, or `--batch` for CI/automation
- **Multi-provider LLM** — Ollama (local) or Anthropic API (cloud)

## Requirements

- Python 3.9+
- An LLM provider (pick one):
  - **Ollama** (local, free) — [ollama.com](https://ollama.com)
  - **Anthropic API** (cloud, paid) — [console.anthropic.com](https://console.anthropic.com)
- Your own payloads file (`payloads.txt`)

## Installation

```bash
git clone https://github.com/Srihari-Narayan/XSS-Map.git
cd XSS-Map
pip install -e .
```

## Quick Start

### 1. Set up an LLM provider

**Option A: Ollama (recommended for local use)**

```bash
# Install Ollama (https://ollama.com)
# Then pull a model:
ollama pull llama3:8b
```

Recommended models (7B+ parameters):
| Model | Size | Notes |
|-------|------|-------|
| `llama3:8b` | ~4.7 GB | Best default, solid JSON output |
| `mistral:7b` | ~4.1 GB | Fast, good at following instructions |
| `gemma2:9b` | ~5.4 GB | Strong reasoning |

> Models below 7B params (e.g. `phi3:mini`) are too weak for structured output. Don't use them.

**Option B: Anthropic API**

Get an API key from [console.anthropic.com](https://console.anthropic.com), then either:

```bash
# Set env var
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Or run the setup wizard
xsshunter setup
```

### 2. Tag your payloads

Place your payloads file as `payloads.txt` in the project root, then:

```bash
xsshunter tag
```

This classifies all payloads into 13 categories using regex pattern matching (instant, no LLM needed). Output: `payloads_tagged.json`.

### 3. Scan a target

```bash
# Basic scan (Ollama, interactive)
xsshunter scan "http://target.com/page?q=test"

# With Anthropic
xsshunter scan "http://target.com" --provider anthropic

# Non-interactive with AI payload generation
xsshunter scan "http://target.com" --batch --generate

# With authentication
xsshunter scan "http://target.com" -c "session=abc123" --bearer "eyJhbG..."

# Specify parameters manually
xsshunter scan "http://target.com" -p username -p email -m POST
```

## Commands

### `xsshunter setup`

Interactive wizard to configure your default LLM provider and API key. Saves to `~/.xsshunter/config.json`.

```bash
xsshunter setup
```

### `xsshunter tag`

Classify payloads into categories using regex patterns.

```bash
xsshunter tag                           # default: payloads.txt -> payloads_tagged.json
xsshunter tag -f my_payloads.txt -o tagged.json
```

**Categories:** script_tag, event_handler, encoded, svg_tag, img_tag, iframe_tag, javascript_uri, style_injection, template_injection, polyglot, dom_manipulation, tag_breakout, other

### `xsshunter scan`

Run an adaptive XSS scan.

```
xsshunter scan <url> [options]
```

**LLM options:**

| Flag | Description |
|------|-------------|
| `--provider` | `ollama` (default) or `anthropic` |
| `--model` | Model name (default: `llama3:8b` / `claude-haiku-4-5-20251001`) |
| `--api-key` | Anthropic API key (or set `ANTHROPIC_API_KEY` env var) |
| `--ollama-url` | Ollama API URL (default: `http://localhost:11434`) |

**Scan tuning:**

| Flag | Description |
|------|-------------|
| `--batch-size` | Payloads per round (default: 10) |
| `--max-rounds` | Max rounds per injection point (default: 10) |
| `--rate-limit` | Max requests/second (default: 10) |
| `--batch` | Non-interactive mode, skip all prompts |
| `--generate` | Enable AI payload generation each round |

**Authentication:**

| Flag | Description |
|------|-------------|
| `-c, --cookie` | Cookie as `name=value` (repeatable) |
| `-H, --header` | Header as `Name:Value` (repeatable) |
| `--bearer` | Bearer token for Authorization header |

**Output:**

| Flag | Description |
|------|-------------|
| `--output-dir` | Report directory (default: `reports/`) |

## How It Works

```
Round 1: Sample broadly across all 13 categories
    -> Heuristic classifies each response (reflected/filtered/blocked)

Round 2+: LLM analyzes results, picks next category to focus on
    -> "script_tag is blocked, but event_handler gets through — focus there"

Round 2+ (with --generate): LLM generates NEW payloads
    -> Studies what reflected/filtered/blocked, crafts mutations to bypass filters
    -> AI-generated payloads labeled [AI-GEN] in output
```

The LLM is called **once per round** for strategy (not per-payload). Per-payload classification is instant heuristics. This keeps scans fast while getting strategic AI guidance.

## Configuration Priority

CLI flags > Environment variables > `~/.xsshunter/config.json` > Defaults

## Reports

Scans produce two report files in the output directory:

- `xsshunter_report.json` — machine-readable JSON with all findings
- `xsshunter_report.html` — dark-themed HTML report with status badges and collapsible response snippets

## Disclaimer

This tool is intended for **authorized security testing only** — bug bounty programs, vulnerability disclosure programs (VDPs), and penetration tests with explicit written permission. Unauthorized use against systems you do not own or have permission to test is illegal. The authors are not responsible for misuse.

