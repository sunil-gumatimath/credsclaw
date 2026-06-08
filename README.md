# Exposed API Key Auditor

Async Python CLI to scan GitHub repositories (code search, commit messages) or local directories for exposed API keys and secrets. Features resumable checkpoints, optional live validation, confidence-based severity scoring, and encrypted output.

## Features

- **Scan targets**: GitHub `code` search, GitHub `commits` search, or local directory (`--mode code | commits | local`)
- **Provider support**:

| Provider | Key Patterns |
|---|---|
| OpenAI | Classic (`sk-{48 alnum}`), project (`sk-proj-...`), service account (`sk-svcacct-...`), admin (`sk-admin-...`) |
| Anthropic | `sk-ant-api01-...`, `sk-ant-api02-...`, `sk-ant-api03-...`, `sk-ant-oat01-...`, `sk-ant-admin-...` |
| Google AI | `AIza{35 chars}`, `AQ.{35+ chars}` |
| AWS | Access Key IDs: `AKIA`, `ASIA`, `ABIA`, `ACCA` (+16 chars) — secret key via env-var pattern |
| Stripe | Secret keys (`sk_live_`, `sk_test_`), restricted keys (`rk_live_`, `rk_test_`), publishable keys (`pk_live_`, `pk_test_`), webhook secrets (`whsec_`) |
| GitHub | `ghp_`, `gho_`, `ghs_`, `ghr_`, `ghu_`, `github_pat_` |
| Slack | Bot/user tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xapp-`), webhook URLs (`hooks.slack.com/services/...`) |
| Twilio | Account SID (`AC...`), API Key (`SK...`) |
| SendGrid | `SG.{22 chars}.{43 chars}` |
| HuggingFace | `hf_{34 alnum}` |
| Cloudflare | `cfk_`, `cfut_`, `cfat_` prefixed tokens |
| Supabase | `sbp_`, `sb_secret_`, `sb_publishable_` prefixed tokens |
| Azure | Service Bus connection strings (`Endpoint=sb://...`) |

- **Confidence-based severity scoring** — each finding gets a score 0–100 with severity CRITICAL / HIGH / MEDIUM / LOW
- **Tunable confidence threshold** — set minimum score with `--confidence-threshold` (default: 50.0)
- **Async + bounded concurrency** for fast scans
- **Checkpoint/resume** via `progress.json` — incremental scans with `--resume --since-checkpoint`
- **Optional live validation** — test discovered keys against provider APIs where supported
- **Context/noise filtering** — built-in noise detection (placeholder keys, examples, dummies) plus custom allow/deny regex filters
- **Multiple export formats** — JSON, CSV, or TXT
- **Optional Fernet encryption** for exported results

## Confidence Scoring

Each detected key is assigned a **confidence score (0–100)** based on multiple factors:

| Factor | Max Points | Description |
|---|---|---|
| Entropy | 30 | Shannon entropy of the key value (randomness) |
| Context patterns | 25 | Keywords like `api_key`, `secret`, `token` in surrounding text |
| Noise filter | 20 | Full penalty if context contains placeholder/example language |
| Length | 15 | Longer keys score higher (4 thresholds) |
| Character diversity | 10 | Ratio of unique to total characters |

Severity levels:

| Severity | Score Range |
|---|---|
| CRITICAL | >= 80 |
| HIGH | 60–79 |
| MEDIUM | 40–59 |
| LOW | < 40 |

The summary report includes a severity breakdown and average confidence across all findings.

## Key Safety

By default, raw keys are **never** stored. Stored fields are:

- `key_hash` — SHA-256 of the key (for deduplication)
- `key_masked` — partial view (`first8...last4`)

This applies to both checkpoint (`progress.json`) and export output. Pass `--store-raw-keys` only when you explicitly need the plaintext value (unsafe).

## Requirements

- Python 3.11+ (recommended)
- GitHub Personal Access Token in `GITHUB_TOKEN` env var (not required for `--mode local`)

```bash
python -m pip install -r requirements.txt
```

## Setup

1. Copy `.env.example` to `.env`.
2. Set `GITHUB_TOKEN=your_token`.
3. Optional:
   - `OUTPUT_ENCRYPTION_KEY` — for `--encrypt-output`
   - `GITHUB_AUDITOR_DISABLE_FILE_LOG=1` — disable `audit.log`

## Quick Start

```bash
# Basic run (defaults: mode=code, providers=openai,anthropic)
python auditor.py

# Dry run — search only, no findings export
python auditor.py --dry-run --providers openai,anthropic,google

# Target a single repository
python auditor.py --repo owner/repo --providers openai,anthropic,google

# Validate discovered keys where supported
python auditor.py --validate

# High-throughput scan
python auditor.py --max-concurrency 20 --checkpoint-interval 50

# Only report high-confidence findings
python auditor.py --confidence-threshold 70 --providers openai,aws,stripe

# Scan all available providers
python auditor.py --providers openai,anthropic,google,aws,stripe,github,slack,twilio,sendgrid,huggingface,cloudflare,supabase,azure
```

## Common Commands

```bash
# Code mode with filters
python auditor.py --mode code --extensions py,js,env --language python --min-stars 50

# Commit-message scan
python auditor.py --mode commits --repo owner/repo

# Incremental scan — only items newer than last checkpoint
python auditor.py --resume --since-checkpoint

# Encrypted JSON export
python auditor.py --encrypt-output --output-file results.enc

# Allow/deny filtering
python auditor.py --allow-patterns OPENAI_API_KEY,ANTHROPIC_API_KEY --deny-patterns example,dummy,mock

# Local directory scan
python auditor.py --mode local --dir /path/to/codebase --providers openai,github
```

## CLI Reference

### Core

| Flag | Description | Default |
|---|---|---|
| `--repo` | Target repository (`owner/repo`). Omit for global search. | `""` (global) |
| `--dir` | Local directory path to scan (required for `--mode local`). | -- |
| `--mode` | Search mode: `code`, `commits`, or `local`. | `code` |
| `--providers` | Comma-separated providers. | `openai,anthropic` |
| `--extensions` | File extensions to search (`py,js,env` — code mode only). | `""` |
| `--validate` | Validate found keys against provider APIs. | `false` |
| `--output-format` | Export format: `json`, `csv`, `txt`. | `json` |
| `--output-file` | Export path. | `audit_results.json` |
| `--resume` | Continue from previous checkpoint. | `false` |
| `--checkpoint-file` | Checkpoint path. | `progress.json` |
| `--max-pages` | Max GitHub result pages to fetch. | unlimited |
| `--min-stars` | Minimum repo stars filter. | none |
| `--language` | Programming language filter. | none |
| `--updated-after` | Repos updated after date (`YYYY-MM-DD`). | none |
| `--sort` | Sort mode: `indexed` or empty (best-match). | `indexed` |
| `--timeout` | Validation request timeout (seconds). | `10` |

### Performance / UX

| Flag | Description | Default |
|---|---|---|
| `--max-concurrency` | Concurrent item processors. | `10` |
| `--checkpoint-interval` | Save progress every N items. | `25` |
| `--dry-run` | Search only; skip content fetch and export. | `false` |
| `--since-checkpoint` | Only process items newer than checkpoint timestamp. | `false` |
| `--confidence-threshold` | Minimum confidence score (0–100) to report. | `50.0` |

### Security / Filtering

| Flag | Description |
|---|---|
| `--allow-patterns` | Comma-separated regex patterns; matching context is always accepted. |
| `--deny-patterns` | Comma-separated regex patterns; matching context is rejected. |
| `--store-raw-keys` | Include raw keys in checkpoint/export (unsafe). |
| `--encrypt-output` | Encrypt exported file with Fernet. |
| `--encryption-key` | Fernet key string (or use `OUTPUT_ENCRYPTION_KEY` env var). |

## Validation Support

When `--validate` is passed, discovered keys are tested against the respective provider API:

| Provider | Validated | Method |
|---|---|---|
| OpenAI | Yes | `GET /v1/models` |
| Anthropic | Yes | `GET /v1/models` |
| Stripe | Yes | `GET /v1/account` |
| GitHub | Yes | `GET /user` |
| Slack | Yes | `POST /api/auth.test` |
| SendGrid | Yes | `GET /v3/user/profile` |
| HuggingFace | Yes | `GET /api/whoami-v2` |
| Cloudflare | Yes | `GET /client/v4/user/tokens/verify` |
| Supabase | Yes | `GET /v1/projects` |
| Google AI | No | No reliable lightweight validation endpoint |
| AWS | No | Requires both Access Key ID and Secret Access Key |
| Twilio | No | Requires both Account SID/API Key and Auth Token/Secret |
| Azure | No | Requires SDK-based connection string validation |

## Output Files

| File | Contents |
|---|---|
| `progress.json` | Processed identifiers, findings, deduplication hashes, checkpoint timestamp |
| `audit.log` | Runtime logs (unless disabled via `GITHUB_AUDITOR_DISABLE_FILE_LOG`) |
| `audit_results.json` (default) | Export — JSON, CSV, TXT, or encrypted `.enc` |

## Docker

```bash
# Build
docker build -t api-key-auditor .

# Run with .env and local output directory
docker run --rm --env-file .env -v "${PWD}/docker-output:/work" api-key-auditor --dry-run --providers openai,anthropic,google

# Docker Compose
docker compose run --rm auditor --dry-run --providers openai,anthropic,google
```

Output files (`progress.json`, `audit.log`, `audit_results.json`) are written to `docker-output/`.

## Testing

```bash
python -m pytest -q
```

CI runs on Python 3.11 and 3.12 (GitHub Actions — see `.github/workflows/ci.yml`).

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: dotenv` / `No module named pytest` | `python -m pip install -r requirements.txt` |
| GitHub rate limits | Use a valid PAT with appropriate scope; reduce `--max-concurrency`; limit pages with `--max-pages` |
| Empty results | Broaden providers; remove strict filters (`--language`, `--min-stars`, `--updated-after`) |

## Responsible Use

This tool is intended for authorized security auditing and responsible disclosure only. Do not misuse discovered credentials. Report exposures to repository owners or providers for revocation.
