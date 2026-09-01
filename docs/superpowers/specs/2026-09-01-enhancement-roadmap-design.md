# CredsClaw Enhancement Roadmap Design

**Date:** 2026-09-01  
**Author:** Tedz  
**Status:** Draft  
**Version:** 1.0

---

## Executive Summary

This document specifies the design for 10 high-impact enhancements to CredsClaw, organized into three implementation waves. The enhancements transform CredsClaw from a basic secret scanner into an enterprise-grade security tool with custom provider support, intelligent scoring, automated remediation, and integration capabilities.

**Primary Goals:**
- **Enterprise readiness:** Custom patterns, privacy controls, adaptive scoring
- **Full lifecycle security:** Detect → Notify → Remediate
- **Professional tooling:** CI/CD, SARIF export, webhook integrations

**Target Delivery:** 3 waves over 6-9 days of focused implementation

---

## Wave 1: Foundation & Quick Wins

**Goal:** Establish baseline stability and address immediate gaps

### 1.1 Fix Test Dependencies

**Current State:**
- `requirements.txt` lists runtime dependencies only
- `pyproject.toml` has `dev = ["pytest>=8.0.0"]` but missing test utilities
- Tests fail with `ModuleNotFoundError: No module named 'aiohttp'`

**Design:**
Add comprehensive dev dependencies to `pyproject.toml`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=5.0.0",
    "aioresponses>=0.7.6",  # Mock aiohttp.ClientSession
    "ruff>=0.4.0",
    "mypy>=1.10.0",
]
```

**Testing:**
- Verify `pip install -e .[dev]` installs all dependencies
- Run `pytest tests/ -v` — all 71 tests should pass
- Add `pytest-asyncio` markers to async test functions

**Files Changed:**
- `pyproject.toml`

---

### 1.2 Re-Add Removed Providers

**Current State:**
- FAQ mentions Stripe, Twilio, SendGrid, Supabase were removed
- Users request these back (common payment/notification platforms)

**Design:**
Add 4 new provider patterns to `auditor/patterns.py`:

```python
STRIPE_KEY_PATTERN = r"\b(?:sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,})\b"
TWILIO_KEY_PATTERN = r"\bSK[0-9a-fA-F]{32}\b"
SENDGRID_KEY_PATTERN = r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"
SUPABASE_KEY_PATTERN = r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"  # JWT format
```

**Validation Endpoints:**
- Stripe: `POST https://api.stripe.com/v1/charges` with test amount (returns 401 if invalid)
- Twilio: `GET https://api.twilio.com/2010-04-01/Accounts.json` with Basic Auth
- SendGrid: `GET https://api.sendgrid.com/v3/user/profile` with Bearer token
- Supabase: No lightweight validation (JWTs require project-specific validation)

**PROVIDER_CONFIGS Update:**
```python
PROVIDER_CONFIGS = {
    # ... existing 14 ...
    "stripe": ("Stripe", "sk_live_ OR pk_live_", STRIPE_KEY_PATTERN),
    "twilio": ("Twilio", "SK", TWILIO_KEY_PATTERN),
    "sendgrid": ("SendGrid", "SG.", SENDGRID_KEY_PATTERN),
    "supabase": ("Supabase", "eyJ", SUPABASE_KEY_PATTERN),
}
```

**Testing:**
- Add pattern tests for each provider in `tests/test_patterns.py`
- Add validator tests in `tests/test_validator.py` (mock HTTP responses)

**Files Changed:**
- `auditor/patterns.py` (patterns + PROVIDER_CONFIGS)
- `auditor/validator.py` (validation functions + VALIDATION_MAP)
- `tests/test_patterns.py`
- `tests/test_validator.py` (new file)

---

### 1.3 SARIF Export Format

**Current State:**
- Exports: JSON, CSV, TXT, HTML
- No integration with GitHub Security tab or other security dashboards

**Design:**
Add SARIF (Static Analysis Results Interchange Format) export:

```python
def export_sarif_results(
    progress: ProgressTracker,
    output_file: str,
    encrypt_output: bool = False,
    encryption_key: str = "",
) -> None:
    """Export findings in SARIF 2.1.0 format."""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CredsClaw",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/tedz/credsclaw",
                        "rules": [
                            {
                                "id": "exposed-secret",
                                "name": "ExposedSecret",
                                "shortDescription": {"text": "Exposed API key or secret detected"},
                                "fullDescription": {
                                    "text": "A potential API key or secret was found in the codebase."
                                },
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "exposed-secret",
                        "level": _severity_to_sarif_level(key_data.get("severity", "LOW")),
                        "message": {
                            "text": f"{key_data['provider']} key found in {key_data.get('path', 'unknown')}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": key_data.get("url", ""),
                                    },
                                    "region": {
                                        "startLine": 1,
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "provider": key_data["provider"],
                            "confidence": key_data.get("confidence", 0),
                            "key_hash": key_data["key_hash"],
                            "valid": key_data.get("valid"),
                        },
                    }
                    for key_data in progress.found_keys
                ],
            }
        ],
    }

    raw_bytes = json.dumps(sarif, indent=2).encode("utf-8")
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if encrypt_output:
        if not encryption_key:
            raise ValueError("Encryption enabled but no encryption key provided")
        encrypted = maybe_encrypt_bytes(raw_bytes, encryption_key)
        output_path.write_bytes(encrypted)
    else:
        output_path.write_bytes(raw_bytes)


def _severity_to_sarif_level(severity: str) -> str:
    """Map CredsClaw severity to SARIF level."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity, "note")
```

**CLI Integration:**
Add `sarif` to `--output-format` choices:
```python
out.add_argument(
    "--output-format",
    type=str,
    choices=["json", "csv", "txt", "html", "sarif"],
    default="json",
)
```

**Usage:**
```bash
python -m auditor --mode local --dir . --output-format sarif --output-file results.sarif
# Upload to GitHub Security tab:
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -F sarif=@results.sarif \
  -F ref=refs/heads/main \
  -F commit_sha=$(git rev-parse HEAD)
```

**Testing:**
- Add SARIF export test in `tests/test_exporter.py`
- Validate output against SARIF 2.1.0 JSON schema

**Files Changed:**
- `auditor/exporter.py` (add `export_sarif_results`, `_severity_to_sarif_level`)
- `auditor/__main__.py` (handle `sarif` format in dispatch)
- `auditor/cli.py` (add `sarif` to choices)
- `tests/test_exporter.py`

---

### 1.4 GitHub Actions CI/CD

**Current State:**
- No automated testing or linting
- Tests require manual execution

**Design:**
Add GitHub Actions workflow:

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .[dev]
      
      - name: Lint with ruff
        run: ruff check .
      
      - name: Type check with mypy
        run: mypy auditor/
      
      - name: Test with pytest
        run: pytest --cov=auditor --cov-report=xml --cov-report=term-missing
      
      - name: Upload coverage to Codecov
        if: matrix.python-version == '3.11'
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.xml
          flags: unittests
          name: codecov-umbrella
```

**Ruff Configuration:**
```toml
# pyproject.toml
[tool.ruff]
line-length = 100
target-version = "py311"
select = ["E", "F", "I", "N", "W", "UP"]
ignore = ["E501"]  # Line too long (some patterns are long)

[tool.ruff.per-file-ignores]
"tests/*" = ["S101"]  # Asserts allowed in tests
```

**Mypy Configuration:**
```toml
# pyproject.toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
```

**Files Changed:**
- `.github/workflows/ci.yml` (new)
- `pyproject.toml` (add ruff + mypy config)

---

## Wave 2: Privacy & Intelligence

**Goal:** Add enterprise-grade features (custom patterns, privacy, adaptive scoring)

### 2.1 Privacy Hardening: Path and Repo Redaction

**Current State:**
- Audit logs expose full file paths (e.g., `C:\Users\Tedz\OneDrive\Desktop\VS Code\credsclaw\output\audit.log`)
- Output JSON includes real repository names and paths
- No way to anonymize findings for external sharing

**Design:**
Add two new CLI flags:

```python
sec.add_argument(
    "--redact-paths",
    action="store_true",
    help="Replace absolute paths with relative paths in output and logs",
)
sec.add_argument(
    "--redact-repo-names",
    action="store_true",
    help="Replace repository names with anonymized identifiers (repo-1, repo-2)",
)
```

**Implementation:**

```python
# auditor/utils.py
import os
import re
from pathlib import Path


class PathRedactor:
    """Redact sensitive paths and repository names."""

    def __init__(self, redact_paths: bool = False, redact_repos: bool = False):
        self.redact_paths = redact_paths
        self.redact_repos = redact_repos
        self._repo_map: Dict[str, str] = {}
        self._repo_counter = 0

    def redact_path(self, path: str) -> str:
        """Replace absolute paths with relative or anonymized paths."""
        if not self.redact_paths:
            return path

        # Replace home directory with ~
        home = str(Path.home())
        if path.startswith(home):
            path = path.replace(home, "~", 1)

        # Replace common user directory patterns
        path = re.sub(r"/home/[^/]+/", "/~/", path)
        path = re.sub(r"C:\\Users\\[^\\]+\\", "C:\\Users\\~\\", path)

        return path

    def redact_repo(self, repo: str) -> str:
        """Replace repository names with anonymized identifiers."""
        if not self.redact_repos:
            return repo

        if repo not in self._repo_map:
            self._repo_counter += 1
            self._repo_map[repo] = f"repo-{self._repo_counter}"

        return self._repo_map[repo]
```

**Integration Points:**
1. **Scanner:** Redact paths before storing in `key_data`
2. **Exporter:** Redact paths in JSON/CSV/TXT/HTML output
3. **Logger:** Filter log messages to redact paths

```python
# auditor/scanner.py
class APIAuditor:
    def __init__(self, ..., redactor: PathRedactor):
        self.redactor = redactor
    
    async def audit_local_directory(self, ...):
        # ...
        key_data = {
            "repo": self.redactor.redact_repo("local"),
            "path": self.redactor.redact_path(str(file_path.relative_to(dir_path))),
            # ...
        }
```

**Testing:**
- Unit tests for `PathRedactor` class
- Integration test: scan with `--redact-paths` and verify output contains `~` instead of full paths

**Files Changed:**
- `auditor/utils.py` (add `PathRedactor` class)
- `auditor/cli.py` (add flags)
- `auditor/scanner.py` (use redactor in all scan modes)
- `auditor/__main__.py` (initialize redactor)
- `auditor/exporter.py` (apply redaction to output)
- `tests/test_utils.py`

---

### 2.2 Adaptive Confidence Scoring

**Current State:**
- Static formula: entropy (30) + context (25) + noise (20) + length (15) + diversity (10)
- All files treated equally (`.env` vs `.md` vs test fixtures)
- No consideration of commit age (old keys more likely rotated)

**Design:**
Introduce file-type weighting and age-based decay:

```python
# auditor/scoring.py
FILE_TYPE_WEIGHTS = {
    # High-risk file types
    ".env": 1.5,
    ".env.local": 1.5,
    ".env.production": 1.5,
    "config.json": 1.3,
    "config.yaml": 1.3,
    "config.yml": 1.3,
    "settings.py": 1.2,
    "secrets.json": 1.5,
    # Medium-risk
    ".py": 1.0,
    ".js": 1.0,
    ".ts": 1.0,
    ".sh": 1.0,
    # Low-risk (documentation, tests)
    ".md": 0.7,
    ".rst": 0.7,
    ".txt": 0.8,
    "test_*.py": 0.5,
    "*_test.py": 0.5,
    "*.test.js": 0.5,
    "*.spec.js": 0.5,
}


def get_file_weight(filename: str) -> float:
    """Return confidence weight based on file type."""
    filename_lower = filename.lower()

    # Check exact matches first
    if filename_lower in FILE_TYPE_WEIGHTS:
        return FILE_TYPE_WEIGHTS[filename_lower]

    # Check extension
    ext = Path(filename).suffix.lower()
    if ext in FILE_TYPE_WEIGHTS:
        return FILE_TYPE_WEIGHTS[ext]

    # Check patterns
    if "test" in filename_lower or "spec" in filename_lower:
        return 0.5

    return 1.0  # Default weight


def calculate_age_factor(commit_date: str) -> float:
    """Reduce confidence for old commits (keys more likely rotated)."""
    if not commit_date:
        return 1.0

    try:
        commit_dt = parse_iso8601(commit_date)
        if not commit_dt:
            return 1.0

        age_days = (datetime.now(timezone.utc) - commit_dt).days

        if age_days > 365:
            return 0.6  # Very old — likely rotated
        elif age_days > 180:
            return 0.75
        elif age_days > 90:
            return 0.85
        elif age_days > 30:
            return 0.95
        else:
            return 1.0  # Recent — full confidence
    except Exception:
        return 1.0


def calculate_confidence_score(
    key: str,
    context: str,
    is_noise: bool,
    filename: str = "",
    commit_date: str = "",
) -> float:
    """Calculate confidence score with adaptive weighting."""
    # ... existing calculation ...

    # Apply file-type weight
    file_weight = get_file_weight(filename) if filename else 1.0

    # Apply age factor
    age_factor = calculate_age_factor(commit_date)

    score = entropy_score + context_score + noise_score + length_score + diversity_score

    # Apply adaptive factors
    score = score * file_weight * age_factor

    return min(max(score, 0.0), 100.0)
```

**Integration:**
Pass `filename` and `commit_date` to `calculate_confidence_score`:

```python
# auditor/scanner.py
def is_probable_secret(
    self, key: str, context: str, filename: str = "", commit_date: str = ""
) -> Tuple[bool, float]:
    # ...
    confidence = calculate_confidence_score(
        key, context, is_noise, filename=filename, commit_date=commit_date
    )
    return confidence >= self.args.confidence_threshold, confidence
```

**Testing:**
- Test `.env` file gets 1.5x boost
- Test commit from 2 years ago gets 0.6x reduction
- Test combined: `.env` file from 6 months ago = 1.5 * 0.75 = 1.125x

**Files Changed:**
- `auditor/scoring.py` (add weighting + age factor)
- `auditor/scanner.py` (pass filename + commit_date to scoring)
- `tests/test_scoring.py`

---

### 2.3 Custom Provider Support

**Current State:**
- Hardcoded 14 providers in `PROVIDER_CONFIGS`
- No way for users to add internal API patterns
- Organizations cannot scan proprietary services

**Design:**
Allow custom providers via YAML config:

```yaml
# auditor.yaml
providers: openai,github,aws,MyInternalAPI

custom_providers:
  - name: "MyInternalAPI"
    search_term: "internal_key_"
    pattern: "internal_key_[A-Za-z0-9]{32}"
    validation:
      url: "https://api.internal.com/validate"
      method: "POST"
      headers:
        Authorization: "Bearer {key}"
        Content-Type: "application/json"
      success_status: 200
      failure_status: [401, 403]
  
  - name: "LegacySystem"
    search_term: "legacy_token_"
    pattern: "legacy_token_[0-9a-f]{40}"
    # No validation — just pattern matching
```

**Implementation:**

```python
# auditor/config.py
from typing import Dict, List, Optional
import yaml


class CustomProvider:
    """User-defined provider from YAML config."""

    def __init__(self, config: dict):
        self.name: str = config["name"]
        self.search_term: str = config.get("search_term", "")
        self.pattern: str = config["pattern"]

        # Validation config (optional)
        validation = config.get("validation", {})
        self.validation_url: Optional[str] = validation.get("url")
        self.validation_method: str = validation.get("method", "GET")
        self.validation_headers: Dict[str, str] = validation.get("headers", {})
        self.success_status: int = validation.get("success_status", 200)
        self.failure_status: List[int] = validation.get("failure_status", [401, 403])

    def has_validation(self) -> bool:
        return bool(self.validation_url)


def load_custom_providers(config: dict) -> Dict[str, CustomProvider]:
    """Load custom providers from YAML config."""
    custom = config.get("custom_providers", [])
    return {p["name"]: CustomProvider(p) for p in custom}
```

```python
# auditor/validator.py
async def validate_custom_key(
    key: str,
    provider: CustomProvider,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    """Validate a key against a custom provider endpoint."""
    if not provider.has_validation():
        return None

    try:
        # Build headers with {key} substitution
        headers = {k: v.replace("{key}", key) for k, v in provider.validation_headers.items()}

        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            method = provider.validation_method.upper()
            if method == "GET":
                async with s.get(provider.validation_url, headers=headers) as resp:
                    pass
            elif method == "POST":
                async with s.post(provider.validation_url, headers=headers) as resp:
                    pass
            else:
                logger.warning("Unsupported validation method: %s", method)
                return None

            if resp.status == provider.success_status:
                return True
            if resp.status in provider.failure_status:
                return False
            return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except Exception:
        return None
```

**Integration in __main__.py:**
```python
# Load custom providers
custom_providers = load_custom_providers(config)

# Merge with built-in providers
for name, custom in custom_providers.items():
    PROVIDER_CONFIGS[name] = (custom.name, custom.search_term, custom.pattern)
    if custom.has_validation():
        VALIDATION_MAP[name] = lambda key, timeout, no_ssl_verify, session, p=custom: (
            validate_custom_key(key, p, timeout, no_ssl_verify, session)
        )
```

**Testing:**
- Test YAML parsing of custom providers
- Test custom pattern matching
- Mock custom validation endpoint

**Files Changed:**
- `auditor/config.py` (add `CustomProvider` class)
- `auditor/validator.py` (add `validate_custom_key`)
- `auditor/__main__.py` (load + merge custom providers)
- `auditor/cli.py` (document custom provider syntax)
- `tests/test_config.py`
- `tests/test_validator.py`

---

## Wave 3: Integrations & Automation

**Goal:** Full lifecycle security (detect → notify → remediate)

### 3.1 Webhook Notifications

**Current State:**
- Output: JSON/CSV/TXT/HTML/SARIF only
- No real-time alerts
- Manual review required

**Design:**
Add webhook notifications for Slack, Discord, and generic endpoints:

```python
# auditor/notifier.py
import aiohttp
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Send scan results to external webhooks."""

    def __init__(
        self,
        slack_webhook: str = "",
        discord_webhook: str = "",
        generic_webhook: str = "",
    ):
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.generic_webhook = generic_webhook

    async def notify(self, findings: List[Dict[str, Any]], scan_metadata: Dict[str, Any]) -> None:
        """Send notifications to all configured webhooks."""
        if self.slack_webhook:
            await self._notify_slack(findings, scan_metadata)
        if self.discord_webhook:
            await self._notify_discord(findings, scan_metadata)
        if self.generic_webhook:
            await self._notify_generic(findings, scan_metadata)

    async def _notify_slack(self, findings: List[Dict], metadata: Dict) -> None:
        """Send Slack webhook notification."""
        severity_counts = self._count_severities(findings)

        payload = {
            "text": f"🔒 CredsClaw Scan Complete",
            "attachments": [
                {
                    "color": "danger" if severity_counts["CRITICAL"] > 0 else "warning",
                    "title": f"Found {len(findings)} potential secrets",
                    "fields": [
                        {"title": "Critical", "value": severity_counts["CRITICAL"], "short": True},
                        {"title": "High", "value": severity_counts["HIGH"], "short": True},
                        {"title": "Medium", "value": severity_counts["MEDIUM"], "short": True},
                        {"title": "Low", "value": severity_counts["LOW"], "short": True},
                    ],
                    "footer": f"Scan mode: {metadata.get('mode', 'unknown')} | Providers: {metadata.get('providers', 'unknown')}",
                }
            ],
        }

        # Add top 5 findings as additional attachments
        for finding in findings[:5]:
            payload["attachments"].append(
                {
                    "color": "warning",
                    "title": f"{finding['provider']} key in {finding.get('repo', 'unknown')}",
                    "text": f"File: {finding.get('path', 'unknown')}\nConfidence: {finding.get('confidence', 0)}",
                }
            )

        await self._post_webhook(self.slack_webhook, payload)

    async def _notify_discord(self, findings: List[Dict], metadata: Dict) -> None:
        """Send Discord webhook notification."""
        severity_counts = self._count_severities(findings)

        payload = {
            "content": f"🔒 **CredsClaw Scan Complete**\nFound **{len(findings)}** potential secrets",
            "embeds": [
                {
                    "title": "Severity Breakdown",
                    "color": 0xFF0000 if severity_counts["CRITICAL"] > 0 else 0xFFA500,
                    "fields": [
                        {
                            "name": "Critical",
                            "value": str(severity_counts["CRITICAL"]),
                            "inline": True,
                        },
                        {"name": "High", "value": str(severity_counts["HIGH"]), "inline": True},
                        {"name": "Medium", "value": str(severity_counts["MEDIUM"]), "inline": True},
                        {"name": "Low", "value": str(severity_counts["LOW"]), "inline": True},
                    ],
                }
            ],
        }

        await self._post_webhook(self.discord_webhook, payload)

    async def _notify_generic(self, findings: List[Dict], metadata: Dict) -> None:
        """Send generic JSON webhook."""
        payload = {
            "scan_metadata": metadata,
            "findings": findings,
        }
        await self._post_webhook(self.generic_webhook, payload)

    async def _post_webhook(self, url: str, payload: Dict) -> None:
        """Post payload to webhook URL."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status not in (200, 204):
                        logger.warning("Webhook POST failed with status %s", resp.status)
        except Exception as exc:
            logger.error("Webhook notification failed: %s", exc)

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1
        return counts
```

**CLI Integration:**
```python
# auditor/cli.py
notif = parser.add_argument_group("Notifications")
notif.add_argument("--slack-webhook", type=str, help="Slack webhook URL for notifications")
notif.add_argument("--discord-webhook", type=str, help="Discord webhook URL for notifications")
notif.add_argument("--generic-webhook", type=str, help="Generic webhook URL (JSON POST)")
```

**Usage:**
```bash
python -m auditor --mode local --dir . --slack-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

**Testing:**
- Mock webhook endpoints with `aioresponses`
- Verify payload structure for Slack/Discord
- Test error handling (webhook failures don't crash scan)

**Files Changed:**
- `auditor/notifier.py` (new)
- `auditor/cli.py` (add webhook flags)
- `auditor/__main__.py` (initialize + call notifier)
- `tests/test_notifier.py` (new)

---

### 3.2 Automated Remediation PRs

**Current State:**
- Detection only — no remediation
- Manual process: user must manually remove secrets and add `.gitignore`

**Design:**
Add `--create-remediation-pr` flag that:
1. Replaces secrets with placeholders in affected files
2. Adds `.gitignore` rules for sensitive file types
3. Creates a GitHub PR with explanation

```python
# auditor/remediation.py
import asyncio
import base64
import logging
from pathlib import Path
from typing import List, Dict, Any
import aiohttp

logger = logging.getLogger(__name__)


class RemediationPR:
    """Create GitHub PRs to remediate exposed secrets."""

    def __init__(self, github_token: str):
        self.github_token = github_token
        self.base_url = "https://api.github.com"

    async def create_pr(
        self,
        repo: str,
        findings: List[Dict[str, Any]],
        branch_name: str = "fix/remove-exposed-secrets",
    ) -> str:
        """Create a remediation PR for the given repository."""
        owner, repo_name = repo.split("/")

        # 1. Get default branch
        default_branch = await self._get_default_branch(owner, repo_name)

        # 2. Create new branch
        await self._create_branch(owner, repo_name, branch_name, default_branch)

        # 3. Group findings by file
        findings_by_file = self._group_by_file(findings)

        # 4. For each file, replace secrets and commit
        for file_path, file_findings in findings_by_file.items():
            await self._remediate_file(owner, repo_name, branch_name, file_path, file_findings)

        # 5. Add .gitignore rules
        await self._add_gitignore_rules(owner, repo_name, branch_name, findings)

        # 6. Create PR
        pr_url = await self._create_pull_request(
            owner, repo_name, branch_name, default_branch, findings
        )

        return pr_url

    async def _get_default_branch(self, owner: str, repo: str) -> str:
        """Get the default branch name."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        data = await self._api_get(url)
        return data.get("default_branch", "main")

    async def _create_branch(self, owner: str, repo: str, branch: str, base: str) -> None:
        """Create a new branch from base."""
        # Get base branch SHA
        url = f"{self.base_url}/repos/{owner}/{repo}/git/ref/heads/{base}"
        base_data = await self._api_get(url)
        base_sha = base_data["object"]["sha"]

        # Create new branch
        url = f"{self.base_url}/repos/{owner}/{repo}/git/refs"
        await self._api_post(
            url,
            {
                "ref": f"refs/heads/{branch}",
                "sha": base_sha,
            },
        )

    async def _remediate_file(
        self,
        owner: str,
        repo: str,
        branch: str,
        file_path: str,
        findings: List[Dict],
    ) -> None:
        """Replace secrets in a file with placeholders."""
        # Get file content and SHA
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
        file_data = await self._api_get(url)

        content = base64.b64decode(file_data["content"]).decode("utf-8")
        sha = file_data["sha"]

        # Replace each secret with placeholder
        for finding in findings:
            key = finding.get("key")  # Raw key (if stored)
            if key:
                placeholder = f"YOUR_{finding['provider'].upper()}_KEY_HERE"
                content = content.replace(key, placeholder)

        # Commit updated file
        new_content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
        await self._api_put(
            url,
            {
                "message": f"security: remove exposed {findings[0]['provider']} key from {file_path}",
                "content": new_content_b64,
                "sha": sha,
                "branch": branch,
            },
        )

    async def _add_gitignore_rules(
        self,
        owner: str,
        repo: str,
        branch: str,
        findings: List[Dict],
    ) -> None:
        """Add .gitignore rules for sensitive file types."""
        rules_to_add = [
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "secrets.json",
            "config/secrets.yaml",
        ]

        # Check if .gitignore exists
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/.gitignore?ref={branch}"
        try:
            gitignore_data = await self._api_get(url)
            content = base64.b64decode(gitignore_data["content"]).decode("utf-8")
            sha = gitignore_data["sha"]
        except Exception:
            content = ""
            sha = None

        # Add missing rules
        existing_lines = set(content.splitlines())
        new_rules = [r for r in rules_to_add if r not in existing_lines]

        if new_rules:
            content += "\n# Added by CredsClaw\n" + "\n".join(new_rules) + "\n"
            new_content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

            url = f"{self.base_url}/repos/{owner}/{repo}/contents/.gitignore"
            payload = {
                "message": "security: add .gitignore rules for sensitive files",
                "content": new_content_b64,
                "branch": branch,
            }
            if sha:
                payload["sha"] = sha

            await self._api_put(url, payload)

    async def _create_pull_request(
        self,
        owner: str,
        repo: str,
        branch: str,
        base: str,
        findings: List[Dict],
    ) -> str:
        """Create a pull request with remediation details."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls"

        # Build PR body
        findings_table = "\n".join(
            [
                f"| {f['provider']} | {f.get('path', 'unknown')} | {f.get('severity', 'LOW')} | {f.get('confidence', 0)} |"
                for f in findings
            ]
        )

        body = f"""## 🚨 Exposed Secrets Detected

CredsClaw found **{len(findings)}** exposed secrets in this repository.

### What was changed:
- Replaced exposed secrets with placeholders (e.g., `YOUR_OPENAI_KEY_HERE`)
- Added `.gitignore` rules to prevent future leaks

### ⚠️ Important Next Steps:
1. **Review the changes** in this PR
2. **Rotate the exposed keys immediately** — they should be considered compromised
3. **Update your environment variables** with the new keys
4. **Merge this PR** once you've rotated the keys

### Affected Files:

| Provider | File | Severity | Confidence |
|----------|------|----------|------------|
{findings_table}

---

*This PR was automatically generated by [CredsClaw](https://github.com/tedz/credsclaw)*
"""

        payload = {
            "title": "🔒 Security: Remove exposed secrets and add .gitignore rules",
            "head": branch,
            "base": base,
            "body": body,
        }

        pr_data = await self._api_post(url, payload)
        return pr_data["html_url"]

    async def _api_get(self, url: str) -> Dict:
        """Make authenticated GET request."""
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def _api_post(self, url: str, data: Dict) -> Dict:
        """Make authenticated POST request."""
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=data) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def _api_put(self, url: str, data: Dict) -> Dict:
        """Make authenticated PUT request."""
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.put(url, headers=headers, json=data) as resp:
                resp.raise_for_status()
                return await resp.json()

    def _group_by_file(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by file path."""
        grouped: Dict[str, List[Dict]] = {}
        for f in findings:
            path = f.get("path", "")
            if path not in grouped:
                grouped[path] = []
            grouped[path].append(f)
        return grouped
```

**CLI Integration:**
```python
# auditor/cli.py
remed = parser.add_argument_group("Remediation")
remed.add_argument(
    "--create-remediation-pr",
    action="store_true",
    help="Create GitHub PRs to remove exposed secrets (requires --store-raw-keys)",
)
```

**Validation:**
```python
# auditor/__main__.py
if args.create_remediation_pr and not args.store_raw_keys:
    parser.error("--create-remediation-pr requires --store-raw-keys to replace actual keys")
```

**Usage:**
```bash
python -m auditor --repo owner/repo --providers all --store-raw-keys --create-remediation-pr
```

**Testing:**
- Mock GitHub API calls
- Test file content replacement
- Test .gitignore rule generation
- Test PR body formatting

**Files Changed:**
- `auditor/remediation.py` (new)
- `auditor/cli.py` (add flag)
- `auditor/__main__.py` (call remediation after scan)
- `tests/test_remediation.py` (new)

---

### 3.3 AST-Based JSON/YAML Scanning

**Current State:**
- Regex-only detection
- Misses semantic context (e.g., `{"api_key": "sk-..."}` vs `README: "use sk-..."`)

**Design:**
Add AST-based scanning for structured files:

```python
# auditor/ast_scanner.py
import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

SECRET_INDICATORS = [
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "secret_key",
    "secretkey",
    "token",
    "access_token",
    "auth_token",
    "password",
    "passwd",
    "pwd",
    "private_key",
    "privatekey",
    "credential",
    "credentials",
]


def scan_json_file(content: str, filename: str) -> List[Tuple[str, str, float, str]]:
    """Scan JSON file for secrets using semantic analysis."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    candidates = []
    _scan_json_object(data, "", candidates)
    return candidates


def _scan_json_object(
    obj: Any,
    path: str,
    candidates: List[Tuple[str, str, float, str]],
) -> None:
    """Recursively scan JSON object for secrets."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key

            # Check if key name indicates a secret
            key_lower = key.lower()
            is_secret_key = any(indicator in key_lower for indicator in SECRET_INDICATORS)

            if is_secret_key and isinstance(value, str):
                # High confidence if key name suggests secret
                candidates.append(
                    (
                        value,
                        f"JSON key: {current_path}",
                        85.0,  # High confidence due to semantic match
                        "HIGH",
                    )
                )

            # Recurse into nested objects
            _scan_json_object(value, current_path, candidates)

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_json_object(item, f"{path}[{i}]", candidates)


def scan_yaml_file(content: str, filename: str) -> List[Tuple[str, str, float, str]]:
    """Scan YAML file for secrets using semantic analysis."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    candidates = []
    _scan_json_object(data, "", candidates)  # YAML loads as dict/list, same as JSON
    return candidates


def scan_structured_file(content: str, filename: str) -> List[Tuple[str, str, float, str]]:
    """Route to appropriate scanner based on file extension."""
    ext = Path(filename).suffix.lower()

    if ext == ".json":
        return scan_json_file(content, filename)
    elif ext in (".yaml", ".yml"):
        return scan_yaml_file(content, filename)

    return []
```

**Integration:**
```python
# auditor/scanner.py
from auditor.ast_scanner import scan_structured_file

async def audit_local_directory(self, ...):
    # ...
    # First try AST-based scanning for structured files
    ast_candidates = scan_structured_file(content, str(file_path))
    
    # Then fall back to regex scanning
    regex_candidates = self.extract_candidates(content, pattern)
    
    # Merge results (AST takes precedence for high-confidence matches)
    local_candidates = ast_candidates + regex_candidates
```

**Testing:**
- Test JSON with `{"api_key": "sk-..."}` detected
- Test nested YAML with secrets
- Test that README with example key is NOT flagged (low confidence)

**Files Changed:**
- `auditor/ast_scanner.py` (new)
- `auditor/scanner.py` (integrate AST scanning)
- `tests/test_ast_scanner.py` (new)

---

## Testing Strategy

### Unit Tests
- **Wave 1:** Pattern tests, validator tests, SARIF export test
- **Wave 2:** PathRedactor tests, scoring weight tests, custom provider tests
- **Wave 3:** Notifier payload tests, remediation API mocking, AST scanner tests

### Integration Tests
- End-to-end scan with `--redact-paths` and verify output
- Custom provider YAML parsing + pattern matching
- Webhook notification with mocked endpoints

### Coverage Target
- Maintain >80% code coverage
- Add `--cov-fail-under=80` to pytest config

---

## Migration & Compatibility

### Backward Compatibility
- All new features are opt-in via CLI flags or YAML config
- Existing `auditor.yaml` files continue to work (custom_providers is optional)
- No breaking changes to output formats

### Deprecation
- None in this roadmap

### Data Migration
- Checkpoint files (`progress.json`) remain compatible
- Old checkpoint files can be loaded by new version

---

## Success Metrics

| Metric | Current | Target (Post-Wave 3) |
|--------|---------|----------------------|
| Providers | 14 | 18 + unlimited custom |
| Export formats | 4 | 5 (SARIF) |
| Test coverage | ~75% | >80% |
| CI/CD | None | Full (lint + test + coverage) |
| Integrations | 0 | 3 (Slack, Discord, generic) |
| Remediation | Manual | Automated PRs |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Custom provider YAML injection | High | Validate patterns with `re.compile()` before use |
| Remediation PR breaks code | High | Require `--store-raw-keys` flag, warn user before creating PR |
| Webhook failures crash scan | Medium | Catch all webhook exceptions, log warning, continue scan |
| Adaptive scoring false negatives | Medium | File weights are multiplicative (never zero), age factor minimum 0.6 |
| AST scanner performance | Low | Only scan `.json`/`.yaml` files, skip large files (>1MB) |

---

## Conclusion

This roadmap delivers 10 high-impact enhancements across 3 waves, transforming CredsClaw into an enterprise-grade security tool. Each wave builds on the previous, with clear dependencies and testing at every level.

**Next Steps:**
1. Review this spec
2. Approve or request changes
3. Proceed to implementation planning (writing-plans skill)
4. Execute Wave 1 → Wave 2 → Wave 3

---

**Document Version History:**
- v1.0 (2026-09-01): Initial draft
