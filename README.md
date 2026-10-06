# 🔍 CredsClaw

> **Async Python CLI** that scans GitHub repositories, local directories, and git history for leaked API keys and secrets across **7 providers**. Features intelligent confidence scoring, deduplication, checkpoint/resume, and rich HTML reports.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](# )
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](# )
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
- [License](#license)

---

## Features

| Feature | Description |
| --- | --- |
| **4 scan modes** | GitHub code search, commit messages, local directory, git history |
| **Single-pass local scanning** | `local` and `git-history` walk their target once and apply every provider's pattern per file/commit, so cost scales with target size — not files × providers |
| **Recent-repo discovery** | Auto-discover repos pushed to in last N days and scan them |
| **7 provider patterns** | OpenAI, Anthropic, Google, AWS, GitHub, Slack, Azure |
| **Confidence scoring** | Multi-factor analysis: Shannon entropy, context keywords, noise handling, length, character diversity |
| **Severity tiers** | CRITICAL (80+), HIGH (60-79), MEDIUM (40-59), LOW (<40) |
| **Live validation** | Ping provider APIs to confirm whether discovered keys are still active; a reused secret is validated once and the verdict shared across its locations |
| **File content cache** | Code-search results are memoised per blob SHA, so a file holding several key types is downloaded once instead of once per matching provider (contents API: 1000 req/hr) |
| **Deduplication** | SHA-256 fingerprinting reports a secret once; every additional location is recorded in `locations` with an `occurrences` count. Merging is O(1) per sighting via a hash index, so large scans stay linear |
| **Checkpoint / Resume** | Save progress mid-scan and resume later without re-scanning. All four modes record every processed identifier, so a resumed run skips work it already covered |
| **HTML reports** | Interactive, sortable, filterable HTML reports with severity bars |
| **Encrypted output** | Fernet-symmetric encryption for sensitive results |
| **Pre-commit integration** | Built in `.pre-commit-config.yaml` generation |
| **YAML config** | Persistent configuration with CLI override precedence |
| **Dry-run mode** | Counts the items in scope and stops: no file reads, no matching, no validation, no export |
| **Allow / deny patterns** | Regex filtering — deny always wins; allow narrows scope and can surface noise-flagged candidates |
| **Shared validation sessions** | Reuses a single `aiohttp.ClientSession` per batch for efficient live validation |

---

## Quick Start

```bash
# 1. Install
git clone <repo-url> && cd credsclaw
pip install -e .

# 2. Set your GitHub token (see "GitHub Token Setup" below; appends so an existing .env is preserved)
grep -q GITHUB_TOKEN .env 2>/dev/null || echo "GITHUB_TOKEN=ghp_..." >> .env

# 3. Run a scan (after install, `credsclaw` / `auditor` work interchangeably with `python -m auditor`)
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
   grep -q GITHUB_TOKEN .env 2>/dev/null || echo "GITHUB_TOKEN=your_token_here" >> .env
   ```

> **Note:** The token is only used to authenticate with GitHub's API. It's never stored in results or sent anywhere else.

---

## Installation

### Standard

```bash
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
# after `pip install -e .`, `credsclaw` / `auditor` are identical shorthands
```

### Basic Examples

```bash
# Scan a specific GitHub repository for OpenAI and AWS keys
python -m auditor --repo owner/repo --providers openai,aws

# Scan the current directory for all 7 provider patterns
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
| --- | --- | --- |
| `--mode` | `code` | Scan mode: `code`, `commits`, `local`, `git-history` |
| `--providers` | `openai,anthropic` | Comma-separated provider list (or `all` for every provider) |
| `--repo` | (empty) | Specific repository: `owner/repo` |
| `--dir` | (empty) | Directory for local/git-history mode |
| `--output-format` | `json` | Output format: `json`, `csv`, `txt`, `html`, `sarif` |
| `--output-file` | `output/audit_results.{ext}` | Custom output path |
| `--confidence-threshold` | `50.0` | Minimum score (0-100) to report a finding |
| `--validate` | off | Ping provider APIs to confirm keys are live |
| `--dry-run` | off | Discovery only: counts the items in scope and stops. No file reads, no matching, no validation, no export, no checkpoint write (CI gates skipped, always exit 0). Enforced in all four modes |
| `--max-concurrency` | `10` | Parallel file processors |
| `--store-raw-keys` | off | Store raw keys in output (unsafe, use encryption) |
| `--encrypt-output` | off | Encrypt results with Fernet |
| `--encryption-key` | (unset) | ⚠️ Deprecated — use `OUTPUT_ENCRYPTION_KEY` env var instead |
| `--no-ssl-verify` | off | Disable SSL certificate verification (for corporate proxies) |
| `--fail-on-findings` | off | Exit with code 2 if any findings meet the confidence threshold (CI gatekeeper) |
| `--fail-on-severity` | (unset) | Exit with code 2 if findings reach this tier: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--config` | `auditor.yaml` | YAML configuration file path |
| `--recent-repos-days` | (empty) | Discover repos pushed to in last N days (mode: `code`/`commits` only) |
| `--resume` | off | Continue from previous checkpoint (without `--resume`/`--since-checkpoint`, an existing checkpoint file is deleted at startup; requesting a resume with no checkpoint warns and starts fresh). All four scan modes record every processed identifier, so a resumed run skips files it already covered instead of re-fetching them |
| `--checkpoint-file` | `output/progress.json` | Path to checkpoint file. Processed identifiers are written to a `<path>.processed` sidecar alongside it |
| `--since-checkpoint` | off | Only process items newer than checkpoint timestamp |
| `--checkpoint-interval` | `25` | Save checkpoint every N processed items. Findings are rewritten in full each time, so total I/O still grows quadratically with finding count — raise the interval (e.g. `200`) when scanning tens of thousands of files |
| `--timeout` | `10` | Validation request timeout in seconds |
| `--allow-patterns` | (empty) | Comma-separated regex allow patterns |
| `--deny-patterns` | (empty) | Comma-separated regex deny patterns |
| `--generate-pre-commit-hook` | off | Write `.pre-commit-config.yaml` and exit |
| `--force` | off | Overwrite existing files (e.g., re-generate the pre-commit hook) |
| `--help` | | Show full argument reference |

### GitHub Filters

| Flag | Description |
| --- | --- |
| `--recent-repos-days` | Discover repos pushed to in last N days (disables `--repo`/`--dir`; capped at 100 repos per run, most recently updated first) |
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

> **Note:** `--recent-repos-days` discovers repos by push date, then searches those repos for key patterns. Capped at 100 repos per run (most recently updated first). For best results, use `--language` to filter (e.g., `--language python`) and increase `--max-pages`.

#### File content cache

Each provider runs its own code search, so a single `.env` holding an AWS key, an OpenAI key, and a GitHub token is returned by three separate searches. Fetching its contents three times costs three round trips against an endpoint limited to **1000 requests/hour** authenticated, so decoded content is memoised in `APIAuditor` keyed on `(repo, path, blob_sha)`.

The blob SHA comes from the search result. Including it means an edited file is re-fetched rather than served stale, while an unchanged file is reused across every provider pass. A file that changes mid-scan therefore costs one extra fetch — the correct trade against silently reporting yesterday's contents.

The cache is bounded on both axes and evicts least-recently-used: `CONTENT_CACHE_MAX_CHARS` (32 M chars, since file sizes vary by orders of magnitude and an entry cap alone would still allow unbounded growth) and `CONTENT_CACHE_MAX_ENTRIES` (4096). A single file larger than the whole budget is not cached at all — it is still returned to the caller, just not memoised. Cache effectiveness is logged once per scan:

```
File content cache: 847/1153 requests served from cache (73%), 306 entries
```

Not enabled for `local` or `git-history` modes: those read from disk and already fetch each file once per scan.

### `commits` — GitHub Commit Message Search

Scans commit messages for keys accidentally described or included in commit text.

```bash
python -m auditor --mode commits --providers github
```

### `local` — Local Directory Scan

Recursively scans all files in a local directory. Skips symlinks, files larger than 5 MB, an extension blocklist of binaries/archives/media (not content sniffing — a binary blob named `.txt` is still scanned), and hidden directories except `.github/` (which *is* scanned); respects `--extensions` filters. **Does not require a GitHub token.**

```bash
python -m auditor --mode local --dir . --providers aws,github --output-format html
```

Implemented by `APIAuditor.audit_local_tree()`. The tree is walked **once** and each file read **once**, then every selected provider's pattern is applied to that content — so cost scales with the number of files rather than files × providers.

Only discovery and reading are shared. Each provider keeps its own findings, stats, checkpoint identifiers (`{provider}/{file}`), and validation pass, so `--resume`, per-provider `--validate`, and `--providers` semantics are unchanged. `audit_local_directory()` is a thin single-provider wrapper over the same method, so the two paths cannot drift.

With `--providers all` (7 providers) on a 47-file tree, this is 7 file reads instead of 329.

Candidate extraction also builds the file's newline-offset index once and reuses it across all seven provider patterns, so line/column reporting is paid for once per file rather than per (provider × match).

### `git-history` — Local Git History Scan

Runs `git log --all` and inspects every commit's diff content for exposed keys. Useful for finding keys that were committed and later removed.

```bash
python -m auditor --mode git-history --dir ./my-repo --providers github,slack
```

Implemented by `APIAuditor.audit_git_history_combined()`, which works the same way as `local` mode: one `git log --all`, then one `git show` per commit, with every provider's pattern applied to each diff.

Cost is `git log` once plus one `git show` per commit — not one `git log` per provider and one `git show` per (commit × provider). Measured on a 6-commit repo with 3 providers: **18 → 6** `git show` calls. On this repository (111 commits, 7 providers): 777 → 111.

Commit identifiers stay per provider (`{provider}/git-history/{sha}`), so `--resume` re-reads nothing: a resumed scan issues **zero** `git show` subprocesses. A commit whose diff cannot be read (git missing, timeout) is marked processed for every provider that wanted it, so a resume does not retry a broken commit.

`audit_git_history()` is retained as a thin single-provider wrapper. Git is invoked via `create_subprocess_exec` with an argument list (never a shell string), `core.fsmonitor=` and `diff.external=` are cleared, `--no-ext-diff` is passed, and every SHA is validated against `[0-9a-fA-F]{7,40}` before use.

### Filtering precedence (`--allow-patterns` / `--deny-patterns`)

Deny is checked first and always wins. Allow narrows scope when set (candidate must match it) and is the only way to surface noise-flagged candidates — those then score 5 pts on the noise factor instead of being dropped. Allow-matches bypass both the noise hard-reject and the `--confidence-threshold` gate (any allow-matched candidate is reported, scored normally).

Noise detection is scoped to **the line containing the key**, not the whole ±80-character context window. A doc sample on an adjacent line (`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`) therefore no longer suppresses a genuine key sitting on the line above it, while a real placeholder on the key's own line (`OPENAI_API_KEY = "sk-…" # example`) is still rejected.

Redaction markers are handled separately from the noise word list: an all-`x` or all-`*` value (`sk-xxxx…`) is always rejected, but a bare `xxx` substring is not — it collides with genuine random secrets roughly once in 2,000 AWS-style keys.

---

## Supported Providers

Formats verified against vendor documentation, October 2026. `tests/test_provider_formats.py` pins every row below with a positive fixture, a negative fixture, and a cross-provider non-overlap assertion.

| Provider | Pattern Prefix(es) | Live Validation |
| --- | --- | --- |
| **Anthropic** | `sk-ant-apiXX-`, `sk-ant-oatXX-`, `sk-ant-admin-`, `sk-ant-authXX-` (+ generic segments; 40+ char tail required) | ✓ |
| **OpenAI** | `sk-` (classic 48–51, allows `-`/`_`, excludes `sk-ant-`), `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-svc-`, `sk-session-` (with `T3BlbkFJ` marker, tails up to 120 chars to cover ~155-char project keys) | ✓ |
| **Google AI** | `AIza` + 35, `AQ.` + 35, `ya29.` + 30 | — |
| **AWS** | 11 prefixes: `AKIA`, `ASIA`, `ABIA`, `ACCA`, `APKA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `AGPA`, `ASCA`, each + 16 uppercase alphanumerics | — |
| **GitHub** | `ghp_` 36–40, `ghs_` 36–76, `gho_`/`ghr_`/`ghu_` fixed 36, `github_pat_` 22–30 + `_` + 59–100 | ✓ |
| **Slack** | Classic `xox[baprsoecde]-` three-field tokens, app-level `xoxa-<app>-<team>-<app>-<secret>`, `xapp-`/`xwfp-` (24+ chars), `hooks.slack.com` webhooks | ✓* |
| **Azure** | Connection strings (`Endpoint=sb://` or `DefaultEndpointsProtocol`; key material 32+ base64 chars with optional padding) | — |

Live validatable providers ping their respective APIs to confirm whether the discovered key is still active. \*Slack webhook URLs (`hooks.slack.com`) are detected but never live-validated. Google AI, AWS, and Azure have no lightweight validation endpoint (an AWS access key ID can't be verified without its secret), so `--validate` skips them instead of issuing a request that can only return "unknown" — see `auditor.validator.NON_VALIDATABLE_PROVIDERS`.

A secret found in several places is validated **once**; the verdict is written to every location it appears in.

---

## Confidence Scoring

Each potential secret is scored from **0–100** using a multi-factor model. The score determines both whether the result is reported (based on `--confidence-threshold`) and its severity label.

### Scoring Factors

| Factor | Max Points | Description |
| --- | --- | --- |
| **Shannon Entropy** | 30 | Higher randomness = more likely a real key |
| **Context Keywords** | 25 | Surrounding text contains `api_key`, `secret`, `token`, etc. |
| **Noise handling** | 20 | Hard-reject on noise words (`example`, `dummy`, `changeme`, …) found **on the key's own line**, plus unmistakably redacted values (all-`x`, all-`*`); allow-pattern override restores graduated scoring (clean 20 / noisy 5) |
| **Key Length** | 15 | Proportional: (len/32 capped at 1) × 15, e.g. 16 chars ≈ 7.5 pts, 32+ chars = 15 pts |
| **Character Diversity** | 10 | 0 pts for keys shorter than 12 chars; otherwise (unique/len ÷ 0.7 capped) × 10 |

### Severity Tiers

| Score | Label |
| --- | --- |
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

Most scan/output keys map to their CLI equivalents. CLI flags always take precedence over config file values. Exception: `--fail-on-findings` and `--fail-on-severity` are CLI-only (unknown YAML keys are ignored with a warning).

Boolean keys (`validate`, `dry_run`, `resume`, `since_checkpoint`, `no_ssl_verify`, `store_raw_keys`, `encrypt_output`) are coerced to real booleans, so `validate: no` disables validation instead of being read as the truthy string `"no"`. Accepted forms: `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`, any case. A value that can't be interpreted is logged as an error and the CLI default is kept.

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `GITHUB_TOKEN` | For GitHub modes | Personal access token with `repo` or `public_repo` scope ([how to create](#github-token-setup)) |
| `OUTPUT_ENCRYPTION_KEY` | For encrypted output | Fernet key (32 base64-encoded bytes) |

Both can be loaded from a `.env` file in the project root.

---

## Output Formats

### Logging

Every scan appends to `output/audit.log` (created automatically alongside `output/`; nothing to configure) in addition to the format-specific results file below.

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
- **Live filter** — type to filter by provider, severity, repo, path, or masked key
- **Expandable rows** — click to reveal commit hash, URL, timestamps, and raw key (raw key only when `--store-raw-keys` was used)
- **Dark theme** — GitHub-dark inspired color scheme

### Encryption

`--encrypt-output` hard-requires a Fernet key via `--encryption-key` (deprecated) or `OUTPUT_ENCRYPTION_KEY`. All formats support `--encrypt-output`:

```bash
export OUTPUT_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
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

`docker-compose.yml` mounts `./docker-output:/work` with `env_file: .env` (requires a `.env` with `GITHUB_TOKEN`, see `.env.example`) and defaults to `--help`. Override the command to scan:

```bash
docker compose run --rm auditor --mode local --dir /work --providers all
docker compose run --rm -e GITHUB_TOKEN=ghp_... auditor --repo owner/repo --providers openai
```

Output is written to `./docker-output/output/` by default (the `output/…` default resolved under the `/work` mount).

---

## Pre-commit Hook

Generate a `.pre-commit-config.yaml` in one command:

```bash
python -m auditor --generate-pre-commit-hook
```

This creates a local pre-commit hook that **fails the commit** whenever exposed credentials above the confidence threshold are found in the working tree (the `--generate-pre-commit-hook` template uses `--fail-on-findings`):

```yaml
repos:
  - repo: local
    hooks:
      - id: credsclaw
        name: CredsClaw
        description: Scans for exposed API keys and secrets before commit
        entry: python -m auditor --mode local --dir . --confidence-threshold 60.0 --fail-on-findings
        language: system
        types: [text]
        pass_filenames: false
```

> **Note:** this repo's own checked-in `.pre-commit-config.yaml` is different — ruff + ruff-format + mypy + a credsclaw `--dry-run` (estimate-only, never blocks), scoped to nothing in particular. In-repo, `--generate-pre-commit-hook` raises `FileExistsError` unless `--force`, and `--force` would overwrite the ruff/mypy hooks.

> **Note:** the generated hook scans the whole working tree, so on a repository whose tests contain synthetic key literals it will block every commit. Scope `--dir` to your shipped source (as this repo's CI does — see [Continuous Integration](#continuous-integration)) or raise `--confidence-threshold`.

---

## Architecture

```
auditor/                        # Installable Python package
├── __init__.py                 # Package init, logging setup, re-exports
├── __main__.py                 # Entry point: argparse → dispatch → export
├── patterns.py                 # 7 regex patterns, noise list, provider registry
├── scoring.py                  # Shannon entropy, confidence scoring, severity, masking
├── scanner.py                  # APIAuditor — all 4 scan modes (local/git-history use single-pass combined variants)
├── validator.py                # Live API validation (shared bearer helper + per-provider verdicts)
├── exporter.py                 # JSON/CSV/TXT/HTML/SARIF export + summary printer
├── tracker.py                  # Checkpoint/resume state, dedupe via hash index, occurrence tracking, processed sidecar
├── cli.py                      # Argparse builder, config merge, pre-commit hook
├── config.py                   # YAML config file loader
├── rate_limiter.py             # Token-bucket rate limiter (+ exponential backoff) to prevent concurrent-task quota exhaustion
└── utils.py                    # ISO-8601 parsing, UTC timestamp helper

tests/                          # Module-scoped test files
├── __init__.py                 # Test package init
├── test_patterns.py            # Pattern matching tests
├── test_provider_formats.py    # Per-provider format fixtures + cross-provider overlap
├── test_scoring.py             # Scoring, masking, fingerprinting tests
├── test_config.py              # Config loading, merging, and boolean coercion
├── test_cli.py                 # CLI parsing and pre-commit hook tests
├── test_exporter.py            # HTML export and format tests
├── test_fixes.py               # Regression tests for fixes and security patches
├── test_main.py                # Entry-point / CI exit-code tests
├── test_tracker.py             # Checkpoint/resume state, dedupe, occurrence tests
├── test_utils.py               # Date-parsing and timestamp helper tests
└── test_scanner.py             # Noise/allow/deny filtering, checkpoints, git history, single-pass + resume equivalence, content cache
```

### Audit Flow

```mermaid
flowchart TD
    subgraph Setup["1 · Setup"]
        S1["Install: pip install -e ."] --> S2["Token: GITHUB_TOKEN in .env"]
        S2 --> S3["Config: CLI flags win over auditor.yaml"]
    end
    subgraph Target["2 · Target"]
        S3 --> T{"Mode?"}
        T -- code --> T1["--repo owner/name"]
        T -- code --> T2["--recent-repos-days N (max 100 repos)"]
        T -- code --> T3["Global code index"]
        T -- commits --> T4["Commit-message search"]
        T -- local/git-history --> T5["--dir path · one pass, all patterns"]
    end
    subgraph Detect["3 · Detect (per provider)"]
        T1 & T2 & T3 & T4 & T5 --> D0{"Already processed? (--resume)"}
        D0 -- Yes --> D4
        D0 -- No --> D1["Regex extract candidates"]
        D1 --> D2{"deny match? → drop"}
        D2 --> D3{"noise word? → drop unless allow-matched"}
        D3 --> D4["Score 0-100: entropy 30 + context 25 + noise 20 + length 15 + diversity 10"]
        D4 --> D5{"Above threshold? (allow-matches skip gate)"}
    end
    subgraph Confirm["4 · Confirm and export"]
        D5 -- Yes --> C1["--validate? live API check: valid / dead / unknown"]
        D5 -- No --> C4["Discard"]
        C1 --> C2["Export json/csv/txt/html/sarif + audit.log"]
        C2 --> C3{"Exit: 0 clean, 2 fail-on hit, 1 error"}
    end
```

### Key Design Decisions

| Decision | Rationale |
| --- | --- |
| **Shared validation sessions** | `batch_validate_keys()` creates one `aiohttp.ClientSession` per provider batch, eliminating TCP connection spam |
| **Single-pass local modes** | `local` and `git-history` read their target once and fan out patterns per file/commit. Both per-provider entry points are thin wrappers over the combined methods, so there is one implementation per mode and no drift. Equivalence is asserted by running both paths over the same target and comparing finding sets |
| **Content cache keyed on blob SHA** | Keying on `(repo, path, blob_sha)` rather than `(repo, path)` is what makes caching safe: an edited file must never be reported from stale content. The byte budget, not just an entry cap, bounds growth |
| **Line numbers via a per-file newline index** | Counting `content[:match.start()].count("\n")` per match was O(n×m). Newline offsets are built once per file with `str.find` (C-speed, ~9ms on 8MB vs ~245ms for a Python-level scan) and located per match by binary search, then memoised so all provider passes over a file share one index. Measured 3.1–3.6× faster end to end; a parametrised test pins the reported line/column against the old arithmetic, since a wrong line silently mis-points every SARIF result |
| **Processed identifiers in a sidecar** | They are the bulk of the checkpoint and only ever grow, so a newline-delimited append-only file keeps each save proportional to the findings. An append that rewrote the whole file measured *slower* than the single-file format, so the append is a real `O_APPEND` write — and skips `fsync`, since a checkpoint is a resume aid, not a durability log |
| **Checkpoint writes serialised** | Multiple scan tasks can reach the interval threshold together; without a guard the slower write can land last carrying less state, silently dropping findings the checkpoint claims to have covered. `os.replace` keeps the file valid, so this was lost progress, not corruption |
| **`--dry-run` re-asserted per mode** | Rewriting a scan path can silently drop the guard that made `--dry-run` a no-op. Each combined entry point now checks it directly, and a test asserts zero file reads rather than trusting the flag's name |
| **Per-provider checkpoints everywhere** | All four modes record a processed identifier on the success path, not just on early-return paths. Without this, `--resume` re-fetched every code-search result while the checkpoint claimed to cover them |
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
pip install -e .[dev]
```

### Lint & Typecheck

```bash
ruff check .
ruff format --check .  # local / pre-commit only, not gated in CI
mypy auditor/
pre-commit install
```

### Running Tests

```bash
python -m pytest tests/ -v        # coverage on by default via addopts (--cov=auditor); --no-cov to opt out
python -m pytest tests/ -q        # compact output
```

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request across Python 3.11–3.13: `ruff check`, `ruff format --check`, `mypy auditor/`, and `pytest` with coverage (published to Codecov).

A second job self-scans with CredsClaw itself. Two steps, because they answer different questions:

```bash
# Gate — blocks the build. Scoped to the shipped package.
python -m auditor --mode local --dir auditor --providers all \
  --confidence-threshold 60.0 --fail-on-findings --output-file output/self_scan.json

# Informational — whole-tree exposure estimate, never blocks
python -m auditor --mode local --dir . --providers all \
  --confidence-threshold 60.0 --dry-run
```

Two deliberate choices worth knowing before you widen either scope:

- **The gate omits `--dry-run`.** Under `--dry-run` the scan short-circuits before matching, so the step would walk the file list and exit 0 no matter what it found — a gate that cannot fail.
- **The gate scans `auditor/`, not the repo root.** `tests/` contains synthetic keys built from fragments that are syntactically indistinguishable from live ones. A whole-tree gate fails on its own fixtures, which trains everyone to ignore a red build. The informational step still reports the full-tree count, and `--fail-on-findings` on it would be the way to opt in once those fixtures are fragmented.

### Codebase Stats (approximate, as of Oct 2026)

| Language | Files | Code | Comment |
| --- | --- | --- | --- |
| Python | 24 | ~4,348 | ~235 |
| TOML | 1 | 77 | 0 |
| Markdown | 1 | 0 | ~655 |
| **Total** | **26** | **~4,425** | **~890** |

### Project Layout Principles

- **Single Responsibility** — each module has one concern (scoring, validation, export…)
- **No Circular Imports** — layered flow centered on `scanner` (`cli/config → scanner → validator/exporter/tracker`), with shared `utils`/`patterns`/`scoring` underneath
- **Async First** — `asyncio.gather` + `Semaphore` for parallel provider scans
- **Test Coverage** — 213 tests, ~66% overall. `patterns.py` is at 100% and `tracker.py` at 93%; `validator.py` (~31%) and `exporter.py` (~41%) remain thin, since exercising live-validation paths needs mocked HTTP and the exporters have many output-shape branches. `scanner.py` sits at ~58% — the GitHub search paths still need mocked API responses.

---

## FAQ

**Q: Why didn't the scan find the key in my `.env` file?**

Make sure you're using local mode (`--mode local --dir .`). Code search mode only looks at GitHub. If it still doesn't find it, check that the `.env` file isn't excluded by the hidden-directory filter — hidden files (like `.env`) are included, only hidden directories are skipped.

**Q: Does the tool upload my keys anywhere?**

**No.** All scanning is local. In GitHub code-search mode, the tool fetches file contents from GitHub's API, processes them locally, and never sends discovered keys anywhere. Live validation sends the key directly to the provider's API (e.g., `api.openai.com`) for a single validation request.

**Q: Why is my scan re-downloading a file I know it already read?**

It should not be — file contents are memoised per `(repo, path, blob_sha)`. Two situations defeat it, both deliberate:

- **The file changed mid-scan.** The blob SHA is part of the cache key, so an edit during a long scan forces a re-fetch. This is intentional: without it, you would be reported secrets from content that no longer exists.
- **The cache overflowed.** The budget is 32 M chars / 4096 entries, evicted least-recently-used. A very large scan will evict files that a later provider pass then needs. Raise `CONTENT_CACHE_MAX_CHARS` in `scanner.py` if your scan legitimately needs a bigger working set.

The `File content cache: …` line at the end of a scan reports the hit rate, so you can tell which case you hit.

**Q: How do I avoid false positives from test keys?**

Increase `--confidence-threshold` (e.g., `--confidence-threshold 70`) or add deny patterns: `--deny-patterns test,mock,dummy`. Test keys with high entropy may still trigger — consider using placeholder values like `sk-test-...` which match the noise filter.

**Q: Can I scan a private repository?**

Yes. Your `GITHUB_TOKEN` needs `repo` scope for private repos. Ensure it has the appropriate permissions in GitHub Settings → Developer Settings → Personal Access Tokens.

**Q: What is the rate limit for GitHub API?**

GitHub allows 10–30 requests per minute for search, depending on your token's level. The tool handles rate limiting with exponential backoff (up to 5 retries, max 300s wait). For large scans, use `--max-pages` to limit scope.

**Q: How do I make CredsClaw fail a build or commit when secrets are found?**

Use `--fail-on-findings` to exit with code 2 when any finding meets the confidence threshold, or `--fail-on-severity HIGH` to only fail when a finding reaches a given severity tier. Exit code 0 means the scan was clean. Gates are skipped under `--dry-run` (always exit 0 barring errors); unexpected errors exit 1. This powers the generated pre-commit hook and CI gatekeeper checks (e.g., GitHub Actions).

**Q: What files does a scan leave behind?**

With the default `--checkpoint-file`, three:

- `output/progress.json` — findings, seen hashes, timestamp
- `output/progress.json.processed` — processed identifiers, one per line (appended, not rewritten)
- `output/audit.log` — the run log

The sidecar exists because processed identifiers are bulk data that only grows: keeping them out of the main checkpoint means each save rewrites only the findings. Checkpoints written by older versions kept everything in one file with an inline `processed` array; those still load, and the next save migrates them to the sidecar.

Two deliberate consequences:

- **Deleting only `progress.json` is not enough to start fresh.** The sidecar would make the scan skip everything it had "already" processed. `--resume`-less runs remove both files automatically; if you clear state by hand, delete the `.processed` file too.
- **A crash can leave a truncated final line.** It is discarded on load, so the worst case is re-scanning the last interval's items — the safe direction to fail.

**Q: Which providers were removed?**

Stripe, Twilio, SendGrid, and Supabase were removed in an earlier pass. HuggingFace, Cloudflare, Replicate, Groq, OpenRouter, Together AI, and Mistral AI were removed more recently. If you need any of them back, see the git history for their patterns and validators.

Each provider is defined in exactly three places, and adding one back means touching all three: the regex constant plus a `PROVIDER_CONFIGS` entry in `patterns.py`, a validator function plus `VALIDATION_MAP` entry in `validator.py`, and (for SSRF allowlisting) its host in `validator.ALLOWED_VALIDATION_HOSTS`. `tests/test_patterns.py::test_validatable_providers_match_validation_map` fails if the provider registries disagree, so a partial addition is caught immediately.

**Q: Why does scanning `local` mode read each file only once?**

Because `audit_local_tree()` walks the directory once, reads each file once, and then applies every selected provider's pattern to that in-memory content. The older per-provider design re-walked and re-read everything for each provider, so 7 providers meant 7× the I/O for identical findings. The same idea applies to `git-history`, where it means one `git show` per commit instead of one per commit *per provider*.

**Q: `--resume` says it worked but nothing was skipped. Why?**

`--resume` only skips work whose identifier is in the checkpoint, so every scan mode must record one per processed item. Code-search mode previously recorded identifiers only on its early-return paths (unreadable file, already-processed) and not after a successful scan, so a resumed code scan re-fetched every file. If you hit this, delete the checkpoint (`--checkpoint-file`) and re-run; the fix ships in all four modes now.

---

## License

MIT — see [LICENSE](LICENSE).
