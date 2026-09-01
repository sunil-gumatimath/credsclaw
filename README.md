# 🔍 CredsClaw

> **Async Python CLI** that scans GitHub repositories, local directories, and git history for leaked API keys and secrets across **14 providers**. Features intelligent confidence scoring, deduplication, checkpoint/resume, and rich HTML reports.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](# )
[![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen)](# )
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](# )

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [GitHub Token Setup](#github-token-setup)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [Supported Providers](#supported-providers)
- [Confidence Scoring](#confidence-scoring)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Docker](#docker)
- [Pre-commit Hook](#pre-commit-hook)
- [Architecture](#architecture)
- [Development](#development)
- [FAQ](#faq)

---

## Features

| Feature | Description |
|---|---|
| **4 scan modes** | GitHub code search, commit messages, local directory, git history |
| **Recent-repo discovery** | Auto-discover repos pushed to in last N days and scan them |
| **14 provider patterns** | OpenAI, Anthropic, Google, AWS, GitHub, Slack, HuggingFace, Cloudflare, Azure, Replicate, Groq, OpenRouter, Together AI, Mistral AI |
| **Confidence scoring** | Multi-factor analysis: Shannon entropy, context keywords, length, character diversity, noise penalties |
| **Severity tiers** | CRITICAL (80+), HIGH (60-79), MEDIUM (40-59), LOW (<40) |
| **Live validation** | Ping provider APIs to confirm whether discovered keys are still active |
| **Deduplication** | SHA-256 fingerprinting prevents the same key from being reported twice |
| **Checkpoint / Resume** | Save progress mid-scan and resume later without re-scanning |
| **HTML reports** | Interactive, sortable, filterable HTML reports with severity bars |
| **Encrypted output** | Fernet-symmetric encryption for sensitive results |
| **Pre-commit integration** | Built in `.pre-commit-config.yaml` generation |
| **YAML config** | Persistent configuration with CLI override precedence |
| **Dry-run mode** | Estimate scope without fetching file contents |
| **Allow / deny patterns** | Regex-based filtering to include or exclude matches |
| **Shared validation sessions** | Reuses a single `aiohttp.ClientSession` per batch for efficient live validation |

---

## Quick Start

```bash
# 1. Install
git clone <repo-url> && cd credsclaw
pip install -e .

# 2. Set your GitHub token (see "GitHub Token Setup" below)
echo "GITHUB_TOKEN=ghp_..." > .env

# 3. Run a scan
python -m auditor --repo owner/repo --providers openai,github,aws

# 4. Try local directory scan
python -m auditor --mode local --dir . --providers all
```

---

## GitHub Token Setup

CredsClaw needs a GitHub personal access token to search code and commits. Here's how to create one:

1. **Go to** [GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)](https://github.com/settings/tokens)
2. **Click** *Generate new token* → *Generate new token (classic)*
3. **Give it a name** (e.g., `credsclaw`)
4. **Set expiration** — choose 30/60/90 days or *No expiration*
5. **Select scopes** — check **`repo`** (for private repos) or just **`public_repo`** (for public repos only) + **`read:org`** (optional, for org-wide search)
6. **Click** *Generate token* and **copy the token** (starts with `ghp_` or `github_pat_`)
7. **Save it** in a `.env` file in the project root:

   ```bash
   echo "GITHUB_TOKEN=your_token_here" > .env
   ```

> **Note:** The token is only used to authenticate with GitHub's API. It's never stored in results or sent anywhere else.

---

## Installation

### Standard

```bash
pip install -r requirements.txt
pip install -e .
```

### Dependencies

- `aiohttp` — async HTTP for GitHub API and live key validation
- `tqdm` — progress bars during scanning
- `python-dotenv` — `.env` file loading
- `pyyaml` — YAML config parsing
- `cryptography` — required for encrypted output

---

## Usage

```bash
python -m auditor [options]
```

### Basic Examples

```bash
# Scan a specific GitHub repository for OpenAI and AWS keys
python -m auditor --repo owner/repo --providers openai,aws

# Scan the current directory for all 14 provider patterns
python -m auditor --mode local --dir . --providers all

# Check your own git history for accidentally committed secrets
python -m auditor --mode git-history --dir . --providers github --confidence-threshold 60

# Generate an interactive HTML report
python -m auditor --mode local --dir ./project --providers all --output-format html

# Scan everything and validate live keys against provider APIs
python -m auditor --repo owner/repo --providers all --validate
```

### Common Options

| Flag | Default | Description |
|---|---|---|
| `--mode` | `code` | Scan mode: `code`, `commits`, `local`, `git-history` |
| `--providers` | `openai,anthropic` | Comma-separated provider list (or `all` for every provider) |
| `--repo` | (empty) | Specific repository: `owner/repo` |
| `--dir` | (empty) | Directory for local/git-history mode |
| `--output-format` | `json` | Output format: `json`, `csv`, `txt`, `html`, `sarif` |
| `--output-file` | `output/audit_results.{ext}` | Custom output path |
| `--confidence-threshold` | `50.0` | Minimum score (0-100) to report a finding |
| `--validate` | off | Ping provider APIs to confirm keys are live |
| `--dry-run` | off | Count matches without fetching contents |
| `--max-concurrency` | `10` | Parallel file processors |
| `--store-raw-keys` | off | Store raw keys in output (unsafe, use encryption) |
| `--encrypt-output` | off | Encrypt results with Fernet |
| `--encryption-key` | (unset) | ⚠️ Deprecated — use `OUTPUT_ENCRYPTION_KEY` env var instead |
| `--no-ssl-verify` | off | Disable SSL certificate verification (for corporate proxies) |
| `--config` | `auditor.yaml` | YAML configuration file path |
| `--recent-repos-days` | (empty) | Discover repos pushed to in last N days (mode: `code`/`commits` only) |
| `--resume` | off | Continue from previous checkpoint |
| `--checkpoint-file` | `output/progress.json` | Path to checkpoint file |
| `--since-checkpoint` | off | Only process items newer than checkpoint timestamp |
| `--checkpoint-interval` | `25` | Save checkpoint every N processed items |
| `--timeout` | `10` | Validation request timeout in seconds |
| `--allow-patterns` | (empty) | Comma-separated regex allow patterns |
| `--deny-patterns` | (empty) | Comma-separated regex deny patterns |
| `--generate-pre-commit-hook` | off | Write `.pre-commit-config.yaml` and exit |
| `--help` | | Show full argument reference |

### GitHub Filters

| Flag | Description |
|---|---|
| `--recent-repos-days` | Discover repos pushed to in last N days (disables `--repo`/`--dir`) |
| `--max-pages` | Maximum GitHub API pages |
| `--min-stars` | Minimum repository stars |
| `--language` | Programming language filter |
| `--updated-after` | Only repos updated after date (YYYY-MM-DD) |
| `--extensions` | File extension filter (e.g., `py,js,env`) |
| `--sort` | Sort mode for GitHub search (default: `indexed`) |

---

## Scan Modes

### `code` (default) — GitHub Code Search

Searches GitHub's code index for exposed keys. Requires a `GITHUB_TOKEN` (set in `.env` or pass on prompt).

```bash
python -m auditor --repo django/django --providers openai,aws
```

Use `--recent-repos-days` to auto-discover public repos pushed to recently:

```bash
python -m auditor --recent-repos-days 7 --providers all --mode code
```

> **Note:** `--recent-repos-days` discovers repos by push date, then searches those repos for key patterns. For best results, use `--language` to filter (e.g., `--language python`) and increase `--max-pages`.

### `commits` — GitHub Commit Message Search

Scans commit messages for keys accidentally described or included in commit text.

```bash
python -m auditor --mode commits --providers github
```

### `local` — Local Directory Scan

Recursively scans all files in a local directory. Automatically skips binary files, hidden directories (`.git`, `.venv`), and respects `--extensions` filters. **Does not require a GitHub token.**

```bash
python -m auditor --mode local --dir . --providers aws,github --output-format html
```

### `git-history` — Local Git History Scan

Runs `git log --all` and inspects every commit's diff content for exposed keys. Useful for finding keys that were committed and later removed.

```bash
python -m auditor --mode git-history --dir ./my-repo --providers github,slack
```

---

## Supported Providers

| Provider | Pattern Prefix(es) | Live Validation |
|---|---|---|
| **Anthropic** | `sk-ant-apiXX-`, `sk-ant-oatXX-`, `sk-ant-admin-` | ✓ |
| **OpenAI** | `sk-` (classic, allows `-`/`_`), `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-svc-`, `sk-session-` (with `T3BlbkFJ` marker) | ✓ |
| **Google AI** | `AIza...`, `AQ....`, `ya29....` | — |
| **AWS** | 11 prefixes: `AKIA`, `ASIA`, `ABIA`, `ACCA`, `APKA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `AGPA`, `ASCA` | — |
| **GitHub** | `ghp_`, `gho_`, `ghs_`, `ghr_`, `ghu_`, `github_pat_` | ✓ |
| **Slack** | `xoxb-`, `xoxp-`, `xoxa-`, `xoxs-`, `xoxo-`, `xoxr-`, `xoxe-`, `xapp-`, `xwfp-`, `hooks.slack.com` | ✓ |
| **HuggingFace** | `hf_` | ✓ |
| **Cloudflare** | `cfk_`, `cfut_`, `cfat_`, `cft_` (body allows `-`/`_`) | ✓ |
| **Azure** | Connection strings (`Endpoint=sb://` or `DefaultEndpointsProtocol`) | — |
| **Replicate** | `r8_` + exactly 37 chars (40 total) | ✓ |
| **Groq** | `gsk_` | ✓ |
| **OpenRouter** | `sk-or-` | ✓ |
| **Together AI** | `together_` (allows `-`/`_`) | ✓ |
| **Mistral AI** | `mist_` (allows `-`/`_`) | ✓ |

Live validatable providers ping their respective APIs to confirm whether the discovered key is still active.

---

## Confidence Scoring

Each potential secret is scored from **0–100** using a multi-factor model. The score determines both whether the result is reported (based on `--confidence-threshold`) and its severity label.

### Scoring Factors

| Factor | Max Points | Description |
|---|---|---|
| **Shannon Entropy** | 30 | Higher randomness = more likely a real key |
| **Context Keywords** | 25 | Surrounding text contains `api_key`, `secret`, `token`, etc. |
| **Noise Penalty** | 20 | Full score if no noise words (`example`, `dummy`, `changeme`…); 0 if detected |
| **Key Length** | 15 | Longer keys are more likely real: 32+ chars = 15pt |
| **Character Diversity** | 10 | Unique character ratio to total length |

### Severity Tiers

| Score | Label |
|---|---|
| 80–100 | 🔴 **CRITICAL** |
| 60–79 | 🟠 **HIGH** |
| 40–59 | 🟡 **MEDIUM** |
| 0–39 | 🟢 **LOW** |

---

## Configuration

### YAML Config File

Create `auditor.yaml` in the project root:

```yaml
providers: openai,github,aws
mode: local
dir: ./project
output_format: html
output_file: output/report.html
confidence_threshold: 60.0
max_concurrency: 5
validate: false
encrypt_output: false
recent_repos_days: 7
```

All config keys map to their CLI equivalents. CLI flags always take precedence over config file values.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | For GitHub modes | Personal access token with `repo` or `public_repo` scope ([how to create](#github-token-setup)) |
| `OUTPUT_ENCRYPTION_KEY` | For encrypted output | Fernet key (32 base64-encoded bytes) |

Both can be loaded from a `.env` file in the project root.

---

## Output Formats

### JSON (`output/audit_results.json`)

Full structured data including masked keys, hashes, timestamps, and validation status.

### SARIF (`output/audit_results.sarif`)

SARIF 2.1.0 for GitHub Code Scanning / VS Code SARIF Viewer.

### CSV (`output/audit_results.csv`)

Flat table suitable for spreadsheet analysis.

### TXT (`output/audit_results.txt`)

Human-readable text summary of each finding.

### HTML (`output/audit_results.html`)

Interactive report with:

- **Severity bar charts** — visual breakdown by severity
- **Sortable table** — click any column header to sort
- **Live filter** — type to filter by provider, severity, repo, or path
- **Expandable rows** — click to reveal commit hash, URL, timestamps, and raw key
- **Dark theme** — GitHub-dark inspired color scheme

### Encryption

All formats support `--encrypt-output` using Fernet symmetric encryption:

```bash
python -m auditor --mode local --dir . --store-raw-keys --encrypt-output
```

---

## Docker

### Build

```bash
docker build -t credsclaw .
```

### Run

```bash
# Local directory scan (mount target directory)
docker run --rm -v "$(pwd):/work" credsclaw --mode local --dir /work --providers all

# GitHub scan (pass token via env)
docker run --rm -e GITHUB_TOKEN=ghp_... credsclaw --repo owner/repo --providers openai

# With HTML output
docker run --rm -v "$(pwd):/work" credsclaw --mode local --dir /work --providers all --output-format html --output-file /work/output/report.html
```

### Docker Compose

```bash
docker-compose up
```

Output is written to `./docker-output/` by default.

---

## Pre-commit Hook

Generate a `.pre-commit-config.yaml` in one command:

```bash
python -m auditor --generate-pre-commit-hook
```

This creates a local pre-commit hook that runs a dry-run scan on all staged text files:

```yaml
repos:
  - repo: local
    hooks:
      - id: credsclaw
        name: CredsClaw
        description: Scans staged files for exposed API keys and secrets
        entry: python -m auditor --mode local --dir . --confidence-threshold 60.0 --dry-run
        language: system
        types: [text]
        pass_filenames: false
```

---

## Architecture

```
auditor/                        # Installable Python package
├── __init__.py                 # Package init, logging setup, re-exports
├── __main__.py                 # Entry point: argparse → dispatch → export
├── patterns.py                 # 14 regex patterns, noise list, provider registry
├── scoring.py                  # Shannon entropy, confidence scoring, severity, masking
├── scanner.py                  # APIAuditor class — all 4 scan modes
├── validator.py                # Live API validation for 11 providers
├── exporter.py                 # JSON/CSV/TXT/HTML export + summary printer
├── tracker.py                  # Checkpoint/resume state management
├── cli.py                      # Argparse builder, config merge, pre-commit hook
├── config.py                   # YAML config file loader
├── rate_limiter.py             # Token-bucket rate limiter (+ exponential backoff) to prevent concurrent-task quota exhaustion
└── utils.py                    # ISO-8601 parsing, UTC timestamp helper

tests/                          # Module-scoped test files (71 tests)
├── test_patterns.py            # Pattern matching tests
├── test_scoring.py             # Scoring, masking, fingerprinting tests
├── test_config.py              # Config loading and merging tests
├── test_cli.py                 # CLI parsing and pre-commit hook tests
├── test_exporter.py            # HTML export and format tests
└── test_scanner.py             # Noise/allow/deny filtering, git history tests
```

### Data Flow

```mermaid
flowchart TD
    A[".env → load_dotenv()"] --> B["YAML config → load_config()"]
    B --> C["CLI + config → parse_args()"]
    C --> D["ProgressTracker ← checkpoint/resume"]
    D --> E["RateLimiter ← init token bucket"]

    E --> F{"recent-repos-days?"}
    F -- Yes --> G["discover_recent_repositories()\n(calls _fetch_initial_rate_limit() internally)"]
    G --> H["Chunk repos (groups of 5)"]
    H --> I["Build query suffix per chunk\n(+ extension filter if --extensions)"]

    F -- No --> I
    I --> J["Expand 'all' providers →\nselected provider list"]

    J --> K["async with APIAuditor(...) as auditor:"]
    K --> L["For each (provider, suffix_chunk):\n create asyncio task"]

    L --> M{"Mode?"}
    M -- code --> N["audit_api_keys()"]
    M -- commits --> O["audit_commit_messages()"]
    M -- local --> P["audit_local_directory()"]
    M -- git-history --> Q["audit_git_history()"]

    N --> R["_fetch_initial_rate_limit()"]
    O --> R
    R --> S["rate_limiter.acquire()"]
    S --> T["GitHub API search request"]
    T --> U["Filter results (stars, language, date)"]

    P --> V["_run_item_loop() ← semaphore"]
    Q --> V
    U --> V

    V --> W["extract_candidates() ← regex\nconfidence scoring\nallow/deny filtering"]
    W --> X["batch_validate_keys()\n(shared aiohttp session)"]
    X --> Y["ProgressTracker.save_progress()\n(at --checkpoint-interval)"]

    Y --> Z["asyncio.gather() completes"]
    Z --> AA["export_results() / export_html_results()"]
    AA --> AB["output/audit_results.{json,csv,txt,html}"]
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Shared validation sessions** | `batch_validate_keys()` creates one `aiohttp.ClientSession` per provider batch, eliminating TCP connection spam |
| **`_run_item_loop` extracted** | Removes ~30 lines of duplicated loop/validation/save/log code from each scan method |
| **Rate-limit sync on non-discovery scans** | `_fetch_initial_rate_limit()` called in `audit_api_keys()` and `audit_commit_messages()` ensures the token bucket starts at the correct level |
| **`no_ssl_verify` forwarded** | SSL setting from CLI is passed to validators for corporate proxy environments |
| **`filter_repo` handles `None`** | `repo.get("language") or ""` prevents `"None"` string from appearing in filters |

---

## Development

### Setup

```bash
git clone <repo-url>
cd credsclaw
pip install -e .
pip install pytest
```

### Running Tests

```bash
python -m pytest tests/ -v        # 71 tests
python -m pytest tests/ -q        # compact output
```

### Codebase Stats

| Language | Files | Code | Comment |
|---|---|---|---|
| Python | 20 | ~2,800 | ~220 |
| TOML | 1 | 21 | 0 |
| Markdown | 1 | 0 | ~220 |
| **Total** | **26** | **~2,821** | **~440** |

### Project Layout Principles

- **Single Responsibility** — each module has one concern (scoring, validation, export…)
- **No Circular Imports** — dependency graph flows: `utils → patterns → scoring → scanner → exporter`
- **Async First** — `asyncio.gather` + `Semaphore` for parallel provider scans
- **Test Coverage** — all public methods tested, git history tests use real `git` commands

---

## FAQ

**Q: Why didn't the scan find the key in my `.env` file?**

Make sure you're using local mode (`--mode local --dir .`). Code search mode only looks at GitHub. If it still doesn't find it, check that the `.env` file isn't excluded by the hidden-directory filter — hidden files (like `.env`) are included, only hidden directories are skipped.

**Q: Does the tool upload my keys anywhere?**

**No.** All scanning is local. In GitHub code-search mode, the tool fetches file contents from GitHub's API, processes them locally, and never sends discovered keys anywhere. Live validation sends the key directly to the provider's API (e.g., `api.openai.com`) for a single validation request.

**Q: How do I avoid false positives from test keys?**

Increase `--confidence-threshold` (e.g., `--confidence-threshold 70`) or add deny patterns: `--deny-patterns test,mock,dummy`. Test keys with high entropy may still trigger — consider using placeholder values like `sk-test-...` which match the noise filter.

**Q: Can I scan a private repository?**

Yes. Your `GITHUB_TOKEN` needs `repo` scope for private repos. Ensure it has the appropriate permissions in GitHub Settings → Developer Settings → Personal Access Tokens.

**Q: What is the rate limit for GitHub API?**

GitHub allows 10–30 requests per minute for search, depending on your token's level. The tool handles rate limiting with exponential backoff (up to 5 retries, max 300s wait). For large scans, use `--max-pages` to limit scope.

**Q: Which providers were removed?**

Stripe, Twilio, SendGrid, and Supabase were removed. If you need them back, see the git history for their patterns and validators.

**Q: What are the new AI hosting providers?**

Replicate (`r8_` + 37 chars), Groq (`gsk_`), OpenRouter (`sk-or-`), Together AI (`together_`), and Mistral AI (`mist_`) — all with live validation support.

---

## License

MIT
