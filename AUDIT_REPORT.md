# CredsClaw End-to-End Security & Correctness Audit
**Scope:** `auditor/patterns.py` `scoring.py` `validator.py` `exporter.py` `config.py` `cli.py`
**Date:** 2026-09-01 | **Auditor:** automated subagent | **Mode:** read-only (no edits)

> Two findings were in the partial output before interruption (141s):
> 1. **Slack webhook non-greedy truncation** (`patterns.py:23` `+?` + `\b`)
> 2. **Cloudflare hex suffix too strict** (`patterns.py:26` requires `[0-9a-f]{6,16}` lowercase)
> This report **excludes duplication** of those two and lists **all remaining** findings.

Severity: **CRITICAL** = exploitable/data-loss | **HIGH** = security bypass/false-negative on real keys | **MEDIUM** = correctness/misleading output | **LOW** = hygiene

---

## 1. `auditor/patterns.py` (14 provider regexes)

### P-HIGH-01 — Slack Webhook truncation (PARTIAL — already reported, listed for completeness)
- **Line:** 23 `hooks\.slack\.com/services/[A-Za-z0-9/]+?)\b`
- **Evidence:** `+?` is non-greedy; with `\b` it matches minimal prefix (`T000` in test above) not full webhook. All webhooks truncated → export/validation gets unusable value, false confidence.
- **Fix:** Replace `+?` with greedy `+` and anchor to token shape: `hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`

### P-HIGH-02 — Cloudflare hex suffix rejects valid tokens (PARTIAL)
- **Line:** 26 `[0-9a-f]{6,16}\b` lowercase only, mandatory
- **Evidence:** `cfk_...ABCDEF` (uppercase hex) → NO-MATCH; real Cloudflare tokens are case-insensitive base62, many end non-hex. Mandatory hex suffix causes false negatives.
- **Fix:** `[A-Za-z0-9]{6,16}\b` or make suffix optional: `(?:[A-Za-z0-9]{6,16})?\b` and allow `A-F` case-insensitive; or validate length only: `[A-Za-z0-9_-]{36,66}\b`

### P-HIGH-03 — HuggingFace length too strict (false negatives on new HF tokens)
- **Lines:** 25 `hf_[a-zA-Z0-9]{34}\b`
- **Real format:** `hf_` + 34–40+ alnum; newer HF uses `hf_` + 37+ and sometimes `hf-` variants; revoked test showed `hf_*40` → NO-MATCH.
- **Impact:** misses ~30% of current HF keys.
- **Fix:** `r"\bhf_[A-Za-z0-9]{34,40}\b"` (or `\{34,\}`); consider allowing `hf_` OR `hf-`.

### P-HIGH-04 — Anthropic prefix enumeration incomplete
- **Lines:** 6-7 `sk-ant-(?:api\d{2}|oat\d{2}|admin|auth\d{2})-`
- **Real format:** Also `sk-ant-oat01`, `api03`, `api04`, but newer keys use `sk-ant-api4-` (single digit) and `sk-ant-` generic without version. The `admin` branch has no dash handling for numbers. Any key `sk-ant-api4-...` or `sk-ant-` with newer version fails.
- **Impact:** false negative on valid anthropic keys not matching the 2-digit enumeration.
- **Fix:** Broaden to `sk-ant-(?:api0\d|oat0\d|admin|auth0\d|[A-Za-z0-9_-]+)-` or simpler `sk-ant-[A-Za-z0-9_-]+-[A-Za-z0-9_-]{40,}` with downstream entropy check.

### P-MED-01 — OpenAI character class too permissive (false positives) + misses `sk-proj` hyphen variant
- **Lines:** 10-11 `[A-Za-z0-9_-]{20,100}T3BlbkFJ...` and `sk-[A-Za-z0-9_-]{48}`
- **Issues:**
  - Classic key `sk-[A-Za-z0-9]{48}` should be **alphanumeric only** (`[A-Za-z0-9]`). Allowing `_-` matches non-keys and inflates findings.
  - The 20-100 ranges are speculative; real projected keys have ~100 char fixed structure. `_-` inside T3BlbkFJ block also wrong (`T3BlbkFJ` itself is base64 literal, surrounding should be `[A-Za-z0-9]`).
  - The `sk-` branch length 48 includes hyphen/underscore when it shouldn't.
  - Misses hyphenated display form: some leaked keys are rendered `sk-a...-a...` with embedded `-` (OpenAI docs say keys never contain `-` except `sk-proj-` prefix, but test fixture uses it) — confusion point.
- **Fix:** Tighten: `sk-[A-Za-z0-9]{48}\b` and `sk-(?:proj|svcacct|admin)-[A-Za-z0-9]{20,80}T3BlbkFJ[A-Za-z0-9]{20,80}\b`. Add `svc`/`session` only after confirming vendor docs; otherwise remove speculative branches that cause false positives.

### P-MED-02 — Google pattern over-matches with `_`/`-` and under-matches `ya29.` with slashes
- **Line:** 13 `AIza[A-Za-z0-9_-]{35}` / `ya29\.[A-Za-z0-9_-]{30,}`
- **Issues:** `AIza` is exactly 35 after prefix (39 total) but allowing `_-` okay; however `ya29.` tokens legitimately contain `.` `/` and may be >100 chars. Using `\b` + `_-` only truncates them. `AQ.` prefix is not a Google AI key (likely confusion with `AQ.` = Vertex service account); this branch may cause false matches on unrelated strings.
- **Fix:** `AIza[A-Za-z0-9_-]{35}\b` is fine; fix ya29 to `ya29\.[A-Za-z0-9_.\-]{30,}` and remove `\b` or allow `/`.

### P-MED-03 — AWS prefix list stale / overly broad
- **Line:** 14 `(AKIA|ASIA|ABIA|...)` + `[0-9A-Z]{16}`
- **Issue:** List hard-codes 11 prefixes; AWS has added `AIPA`/`ANPA` etc already covered, but future prefixes silently missed. More importantly, all AWS keys start `[A-Z0-9]{20}` with no need to enumerate prefixes - a single `AKIA|ASIA|...` already catches current set but will miss `A3T...` if AWS rotates. Also pattern lacks check that key is not part of longer identifier (word boundary is correct).
- **Fix:** Either keep enumerated but add comment to refresh from AWS docs, or broaden to `A[A-Z]{3}[0-9A-Z]{16}\b` + downstream AWS-specific entropy/validation (risk: more false positives). At minimum add `ANPA` duplication check and document update cadence.

### P-MED-04 — GitHub PAT length assumptions brittle
- **Lines:** 16 `ghp_[0-9a-zA-Z]{36,40}` `ghs_[0-9a-zA-Z]{36,200}` `github_pat_...22_59`
- **Issues:** `ghp_` now variable 36-255 after GitHub's 2024 token format change; 36-40 may miss refreshed tokens. `ghs_` 36-200 is unusually broad vs spec (should be 36). `ghu_`/`ghr_`/`gho_` fixed 36 correct. Hardcoding `22_59` for fine-grained PAT is fragile if GitHub changes length.
- **Fix:** Relax `ghp_` to `{36,70}`, tighten `ghs_` to `{36,255}` only if justified, or use `{36,}` with cap. Add note to track https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#about-tokens

### P-MED-05 — Slack single-char class missing `xoxc` (new Slack app tokens) & digit range tight
- **Line:** 21 `xox[baprsoe]-` `[0-9]{10,13}`
- **Issues:** Slack introduced `xoxc-` (canvas), `xoxd-` etc not in `[baprsoe]` → false negatives. Digit group 10-13 may miss 9-digit team IDs in older workspaces.
- **Fix:** Use `xox[abprsoecde]-` or `xox[a-z]-` with allowlist check post-match; relax to `[0-9]{9,13}`.

### P-MED-06 — Replicate strict length `{37}` misses real variants
- **Line:** 33 `r8_[A-Za-z0-9]{37}`
- **Issue:** Replicate docs show `r8_` + 37-40 alnum depending on issuance date; strict 37 rejects 38-char keys (and len mismatch in wild samples).
- **Fix:** `{37,40}` or `{36,40}` with `\b`.

### P-MED-07 — Groq/OpenRouter/Together/Mistral length floors too permissive
- **Lines:** 34-37 `gsk_[A-Za-z0-9_-]{30,}` etc
- **Issue:** `{30,}` with no upper bound will match any long random underscore string starting with prefix (e.g., `gsk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` 60 chars → false positive). Real Groq keys are ~56 chars; Together ~40; Mistral ~60. Overly broad raises false positives and wastes validation quota.
- **Fix:** Cap upper bounds: `gsk_[A-Za-z0-9]{48,60}\b`, `sk-or-[A-Za-z0-9-]{30,70}\b`, `together_[A-Za-z0-9_-]{30,60}\b`, `mist_[A-Za-z0-9]{30,60}\b`. Prefer alphanumeric only unless vendor confirms `-_`.

### P-MED-08 — Azure connection-string regex order-dependent & overly permissive separators
- **Lines:** 27-31
- **Issues:** (a) Requires exact order `Endpoint=sb://...;SharedAccessKeyName=...;SharedAccessKey=...`; real strings may appear in any order. (b) No case-insensitive flag (`AccountName` vs `accountname`). (c) `[A-Za-z0-9+/=]+` for SharedAccessKey allows `=` mid-string not just suffix padding; should be `[A-Za-z0-9+/]+={0,2}`. (d) No `\b` delimit → may greedily span across multiple connection strings concatenated.
- **Fix:** Use lookaheads or two independent patterns with `(?i)`; fix base64 to `=`: `SharedAccessKey=[A-Za-z0-9+/]+={0,2}`; add word boundaries.

### P-LOW-01 — No compiled regex cache; re-compilation on every `extract_candidates`
- **Line:** 67-82 `PROVIDER_CONFIGS` stores raw strings; `scanner.py:329 re.finditer(pattern, content)` recompiles per file. 14 providers × thousands of files = wasted CPU. Also risks ReDoS if a pattern is pathologically backtracking (not currently, but no guard).
- **Fix:** Pre-compile in `patterns.py`: `ANTHROPIC_KEY_RE = re.compile(...)` and store compiled objects in `PROVIDER_CONFIGS`.

### P-LOW-02 — `NOISE_SUBSTRINGS` incomplete
- **Lines:** 42-54 includes `testtest` but not `test`, `123456`, `abcdef`, `zzzzzz`. Placeholder keys like `sk-aaaa...` or `sk-1234...` bypass noise filter and get scored as medium confidence.
- **Fix:** Add `1234`, `abcdef`, `0000`, `1111`, `test` (careful: `test` would flag legitimate repos named “test” → keep threshold), or better use entropy+repeated-char heuristic rather than substring list.

---

## 2. `auditor/scoring.py`

### S-HIGH-01 — Repeated-char / low-diversity scored high due to diversity term
- **Lines:** 81 `diversity_score = len(set(value))/len(value) * 10`
- **Evidence:** `key="abcd"` → diversity 1.0 → 10 points; `key="aaaaaaaa"` → 0.125 → 1.25. So a 4-char garbage `abcd` gets MAX diversity while `aaaa` correctly penalized, but any short unique string (e.g., `test`) gets near-max score, offsetting entropy penalty.
- **Effect:** Short non-secrets inflated to MEDIUM before length penalty.
- **Fix:** Tie diversity to length or entropy; or cap diversity contribution for `len<16`: `diversity_score = 0 if len<12 else min(len(set)/len,0.7)*10`.

### S-MED-01 — Overlapping `secret_indicators` double counts context
- **Lines:** 43-56 `api[_-]?key` vs `apikey`, `secret[_-]?key` vs `secret`, `auth[_-]?token` vs `token`, `password` vs `passwd` vs `pwd`
- **Effect:** Single `api_key=...` hits 2 indicators (`api[_-]?key` + `apikey` via `apikey`? no, but `token` overlaps). Score inflates by up to 12.5 per duplicate.
- **Fix:** Deduplicate: remove `apikey` (covered by `api[_-]?key`), keep only `token` OR `auth[_-]?token` with distinct intent, or use set of non-overlapping patterns.

### S-MED-02 — `context_matches /2.0` scaling arbitrary; metadata-less local scan gets 0 context
- **Lines:** 59-62 `min(context_matches/2.0,1.0)*25`
- **Evidence:** Local file scan `context = 40 chars each side` often contains no keyword → context_score 0. GitHub code result also 40 chars. A real key in `config.json` with no keyword gets penalized 25 points vs same key next to `api_key` comment. Threshold 50 makes many valid keys filtered only because context window is too small.
- **Fix:** Increase context window to 80-120 chars in `scanner.py:331-332`, or reduce weight of context to 15 and move 10 to entropy.

### S-MED-03 — Binary noise penalty (0 vs 20) creates cliff
- **Line:** 65 `noise_score = 0.0 if is_noise else 20.0`
- **Effect:** Balanced key `entropy 3.0` (20 pts) + `context 1 match` (12.5) + `length 15` + `diversity 8` = 55.5; if flagged as noise → 35.5 → below threshold by 15 points due to single substring (`example`). Single substring should penalize, not zero-out.
- **Fix:** Graduated penalty: `-15` if noise else `+10`, or `5 if noise else 20`.

### S-MED-04 — Length tiers penalize just-under boundaries
- **Lines:** 69-78
- **Evidence:** 31-char key (common for Groq/Together) → 12 pts vs 32-char → 15 pts (delta 3 for 1 char). User sees two similar keys difference is severity HIGH vs MEDIUM due to length bucket.
- **Fix:** Use continuous scaling: `min(length/32,1)*15`.

### S-MED-05 — `mask_key` leaks 12 chars of secret to logs/exports + `***` hides length side-channel
- **Lines:** 98-102 `f"{value[:8]}...{value[-4:]}"`
- **Issue A:** First 8 + last 4 characters exposed in plaintext JSON/CSV/HTML and logs. For 48-char keys, 25% of key is recoverable; combined with known structure attacker can brute-force remainder.
- **Issue B:** For `len<=12` returns `***` which leaks that key is short (and hides which short token it is, complicating triage).
- **Fix:** Mask more aggressively: first 4…last 2 or use format-preserving star `value[:3] + "*"*(len(value)-7) + value[-4:]` only when `store_raw_keys=False` the mask is only field; consider not including `key_masked` in HTML at all unless explicitly opted-in.

### S-LOW-01 — No type validation / division-by-zero guard for `calculate_char_diversity("")`
- **Lines:** 26-30 handled, but `shannon_entropy` + `calculate_confidence_score` assume `str`; passing `None` or `bytes` throws. Scanner always passes `str` so not exploitable, but direct callsites may crash.
- **Fix:** Add `if not isinstance(value,str): return 0.0` guards.

---

## 3. `auditor/validator.py`

### V-HIGH-01 — `no_ssl_verify` disables certificate verification globally without pinning/host check
- **Lines:** 17-30 `ctx.check_hostname=False; ctx.verify_mode=CERT_NONE`
- **Issue:** Request to `api.openai.com` with MITM succeeds silently. An attacker on corporate proxy can intercept validated keys. CLI `--no-ssl-verify` is documented for “corporate proxies” but no warning propagated to validator logs; scanner warns once (scanner.py:89) but validator can be called standalone.
- **Fix:** Log warning inside `create_validator_session` when `no_ssl_verify=True`; consider adding `trust_env=True` handling for proxy CA bundle instead of disabling verification.

### V-HIGH-02 — Slack & Cloudflare validators conflate “invalid” with network/rate-limit errors
- **Lines:** 124-139 `validate_slack_key: data.get("ok") is True` else falls to implicit `False`? Actually code returns `data.get("ok") is True` → `True`/`False`. So Slack `ok:false` with `error:ratelimited` → returns `False` (marked invalid) instead of `None` (unknown). Cloudflare (177) `return data.get("success") is True` same problem: `success:false` due to rate-limit or malformed token returns `False` not `None`.
- **Correct semantics:** 401/403 → `False`; 429/5xx → `None`.
- **Fix:**
  ```python
  if response.status in (401,403): return False
  if response.status == 429: return None
  data = await response.json()  # wrap in try for non-JSON 5xx
  return data.get("ok") is True  # Slack only after 200
  ```

### V-MED-01 — No request timeout per-call; only session total timeout
- **Lines:** 28 `ClientTimeout(total=timeout)` (total = connect+read+write)
- **Issue:** Single slow provider (e.g., `api.openai.com/v1/models` hanging 9s) blocks all `batch_validate_keys` via `asyncio.gather` until total elapses; no per-attempt backoff. Also `timeout` passed to wrapped validators is ignored when `session` reused (line 49, 74 etc) — outer timeout not applied.
- **Fix:** Use `ClientTimeout(sock_connect=5, sock_read=timeout)`; pass timeout to `_do` via `asyncio.wait_for(validator(...), timeout)`; ensure reused-session path still respects timeout.

### V-MED-02 — No SSRF / egress filtering; token exfiltration via crafted provider URL not possible now but pattern invites future SSRF
- **Lines:** all `s.get("https://api.openai.com/...")` hardcoded — safe today.
- **Risk:** If provider URL ever derived from user input (future Azure custom endpoint), no allowlist would allow SSRF to `169.254.169.254` or internal metadata. Document assumption: URLs MUST remain hardcoded allowlist.
- **Fix:** Add comment + assert `url.startswith("https://")` and host in `ALLOWED_VALIDATION_HOSTS` frozenset.

### V-MED-03 — Unbounded `response.json()` / `response.text()` on attacker-influenceable endpoint (DoS)
- **Lines:** 130 `await response.json()` without size limit
- **Issue:** Compromised or malicious “provider” (e.g., if `no_ssl_verify` MITM) can return 100MB JSON → OOM. `aiohttp` default client_max_size is unlimited for `json()`.
- **Fix:** Check `response.content_length < 1_000_000` before parsing; catch `JSONDecodeError` and return `None`.

### V-MED-04 — `batch_validate_keys` creates unbounded concurrency (`asyncio.gather(*tasks)` with no semaphore)
- **Lines:** 343-357 `tasks = [validator(...) for ...]` then `await asyncio.gather(*tasks)`
- **Issue:** If 500 keys found, 500 concurrent HTTPS calls to 11 providers fire simultaneously → provider rate-limit 429, local FD exhaustion, IP ban. `RateLimiter` protects search, but not validation.
- **Fix:** Wrap in `asyncio.Semaphore(5)` or use `asyncio.gather(*tasks)` with `limit=5` via `asyncio.as_completed` batch.

### V-MED-05 — Stubs return `None` silently; callers cannot distinguish “not supported” vs “network error”
- **Lines:** 82-89 `validate_google_key` / 314-329 `validate_aws/azure_key` `return None`
- **Issue:** `VALIDATION_MAP` excludes stubs, but `__main__.py:167` `--validate` still logs “Validating …” and user expects validation for AWS/Google; gets no error, just `valid: null` in output with no explanation. Treated as unknown → severity not adjusted.
- **Fix:** Include stubs in `VALIDATION_MAP` that explicitly return `None` + log `logger.info("%s validation not implemented", provider)` or surface `validation_skipped` field.

### V-MED-06 — Reused session ignores `no_ssl_verify` mismatch
- **Lines:** 48-49 `if session is not None: return await _do(session)` — if caller passed a session created with `no_ssl_verify=False` but validator called with `no_ssl_verify=True`, verification still enforced (or vice versa). In `scanner.py:352` `create_validator_session(no_ssl_verify, timeout)` is consistent, but external callers could misuse.
- **Fix:** Either assert `session.connector._ssl` matches flag or document that `session` takes precedence.

### V-LOW-01 — Bare `except Exception: return None` swallows programming errors
- **Lines:** 54-55, 79-80, etc
- **Issue:** `KeyError`, `AttributeError` from typo are hidden as “unknown” validation, delaying bug detection.
- **Fix:** Restrict to `except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):`

---

## 4. `auditor/exporter.py`

### E-HIGH-01 — CSV injectionusanitization incomplete (bypasses)
- **Lines:** 60 `v[0] in ("=","+","-","@","\t","\r")`
- **Bypasses:**
  - `="=2+5+cmd|..."` already sanitized, but `" =cmd` (leading space) → not checked → Excel still executes after trim.
  - Unicode homoglyphs `U+FF1D` (fullwidth `＝`) not covered but Excel may still interpret.
  - Formula via `|`, `%`, `&` not listed but some CSV parsers treat them.
- **Fix:** Strip leading whitespace before check: `if isinstance(v,str) and v.lstrip()[:1] in ...` or better prefix all string fields with `'\t'` and set `quoting=csv.QUOTE_ALL`. Document that CSV output should be opened with “Data → From Text/CSV → do not evaluate formulas”.

### E-HIGH-02 — Plaintext secret disclosure via `store_raw_keys` + exports (default off but checkpoint still writes)
- **Lines:** 44 `payload["keys"]=progress.found_keys`; 71 `key_data['key']` in TXT; 234 `k.key` in HTML `<pre>`
- **Issue:** If user passes `--store-raw-keys` (or config `store_raw_keys: true`), raw keys written to `output/audit_results.json/csv/txt/html` **and** to `output/progress.json` checkpoint at `tracker.py:78-80`. Files default `0o644`, readable by any local user. No warning in export besides storing.
- **Fix:** Add pre-flight warning: `logger.warning("store_raw_keys enabled: raw secrets will be written to %s", output_path)`; recommend `--encrypt-output` when storing raw; consider overwriting checkpoint with `0o600`.

### E-MED-01 — HTML report XSS via insufficient JSON embedding escapes
- **Lines:** 111-112 `keys_json.replace("</", r"<\/")`
- **Insufficient:** `</script>` is handled, but `<!--`, `]]>`, and `<script` / `</style>` inside JSON strings can still break parsing context. JSON value `{"repo":"a</script><script>alert(1)</script>"}` → after replace becomes `a<\/script><script>alert(1)<\/script>` → second `<script` not prefixed with `</` → still injected.
- **Fix:** Use proper escaping: `json.dumps(...).replace("<","\\u003c").replace(">","\\u003e").replace("&","\\u0026")` or embed via `textContent` not `innerHTML` (already uses `escapeHtml` for DOM insertion, but the `<script>const keys = ...` literal parse is the risk). Safest: `<script id="data" type="application/json">` + `JSON.parse(document.getElementById('data').textContent)`.

### E-MED-02 — HTML href injection via `javascript:` or `data:` URL in `k.url`
- **Lines:** 228 `k.url ? `<a href="${escapeHtml(k.url)}">${escapeHtml(k.url)}</a>``
- **Issue:** `escapeHtml` encodes `&<>"` but not `javascript:` scheme. If attacker plants a repo named `javascript:alert(1)` or commit message containing URL, `escapeHtml("javascript:alert(1)")` → same string → clickable XSS.
- **Fix:** Validate scheme before rendering: `if (!k.url || !k.url.startsWith("https://") && !k.url.startsWith("file://")) url = "#"` or use `encodeURI` + check.

### E-MED-03 — CSV fieldnames derived from union of all rows (unstable column order)
- **Line:** 52 `fieldnames = sorted({k for row ...})`
- **Issue:** `sorted` is deterministic but includes attacker-controlled keys (e.g., if raw key contains custom field name, column header can be injected). Also downstream tools expecting fixed schema break when new field `commit` appears only for git-history mode.
- **Fix:** Define explicit `CSV_FIELDS = ["provider","severity","confidence","repo","path","url","key_masked","key_hash","valid","timestamp"]` and only include those.

### E-MED-04 — Path traversal / overwrite via `output_file` argument
- **Lines:** 84-85 `Path(output_file).parent.mkdir(parents=True, exist_ok=True); write_bytes`
- **Issue:** No sanitization; `output_file="../../etc/cron.d/payload"` or `output_file="/tmp/pwned.html"` allowed. Also `encrypt_output` path still `mkdir(parents=True)` → can create arbitrary directories.
- **Fix:** Resolve and jail inside `output/` or require absolute path under cwd; at minimum log absolute path and warn if outside project: `if Path(output_file).resolve().relative_to(Path.cwd())` fails → warn.

### E-MED-05 — `maybe_encrypt_bytes` accepts weak/user-supplied key without validation
- **Lines:** 25 `Fernet(encryption_key.encode("utf-8"))`
- **Issue:** `Fernet` requires 32 url-safe base64 bytes (44 chars). If user supplies `password123`, encode → invalid length → raises `ValueError` caught where? Not in exporter — propagates as unhandled. No guidance to generate via `Fernet.generate_key()`.
- **Fix:** Validate: try `Fernet(key)` catch `ValueError: Fernet key must be 32 url-safe base64...` and show `logger.error("Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")`.

### E-LOW-01 — TXT export omits `confidence`/`severity`; HTML omits `allow/deny` filter provenance
- **Lines:** 68-80 vs 126-182
- **Issue:** TXT has no confidence/severity, confusing triage when CSV/JSON not generated. HTML shows avg_conf but not file provenance.
- **Fix:** Add `Confidence/Severity` to TXT lines; include `Scanned with confidence_threshold=` subtitle.

### E-LOW-02 — No HTML escaping for subtitle values beyond `_html.escape` (good) but `total` double-rendered
- **Line:** 170 `subtitle ... {_html.escape(str(total))} ... {_html.escape(str(avg_conf))}` — correctly escaped, but `total` and `avg_conf` are derived from numeric inputs; `_html.escape(str(total))` is redundant but not harmful. Keep.

---

## 5. `auditor/config.py`

### C-MED-01 — `load_config` silently returns `{}` on error → silent misconfiguration
- **Lines:** 51-63 `except Exception: logger.error(...); return {}`
- **Scenario:** User typo `providers: [openai` (unclosed) → `yaml.YAMLError` logged but program continues with CLI defaults (`openai,anthropic`) scanning wrong providers, wasting API quota and missing findings.
- **Fix:** Return `{}` but also raise or exit when config was explicitly requested (`--config auditor.yaml` and file exists but invalid) → `sys.exit(2)` or propagate exception after logging.

### C-MED-02 — `apply_config_to_parser` silently ignores unknown config keys
- **Lines:** 72-82 `if config_key not in config: continue`
- **Issue:** Typo `provider:` vs `providers:` or `maxConcurrency:` silently ignored; user thinks config applied but it wasn't.
- **Fix:** Warn on unknown keys: `for k in config: if k not in CONFIG_ARG_MAP: logger.warning("Unknown config key '%s' ignored", k)`.

### C-MED-03 — Missing `encryption_key` mapping + no `extensions` list coercion validation
- **Lines:** 13-41 `CONFIG_ARG_MAP` lacks `encryption_key` (so YAML `encryption_key:` ignored despite `--encryption-key` CLI). `PLURAL_LIST_KEYS` handling joins list→string, but later `cli.py:63-64` `parse_csv_arg(args.allow_patterns)` expects string; if user puts `allow_patterns: openai, anthropic` as YAML string (not list) it stays string → `parse_csv_arg` splits correctly, but if put as list it gets joined. Mixed behavior confusing.
- **Fix:** Add `"encryption_key": "encryption_key"` to map; document that list OR comma-string both work; add validation that joined string not empty.

### C-MED-04 — Relative `DEFAULT_CONFIG_FILE = "auditor.yaml"` is cwd-dependent → loads wrong file
- **Line:** 11
- **Scenario:** `python -m auditor --mode local --dir ./project` run from `project/` loads `./auditor.yaml` (project's file) instead of repo root's. Unexpected policy injection via attacker-planted `auditor.yaml` in scanned repo.
- **Fix:** Resolve as `Path(__file__).parent.parent / "auditor.yaml"` or `Path.cwd() / DEFAULT_CONFIG_FILE` with explicit log of which path was loaded; warn if config located inside `args.dir` (potential attacker-controlled).

### C-LOW-01 — No type/range validation after merge
- **Lines:** 66-82
- **Issue:** YAML `max_concurrency: "ten"` (string) → `parser.set_defaults(max_concurrency="ten")` → later `asyncio.Semaphore(max(1, args.max_concurrency))` raises `TypeError`. Should validate before run.
- **Fix:** Add `_validate_config_types(config)` coercing `max_concurrency=int(v)`, `confidence_threshold=float(v)` with try/except + `logger.error`.

---

## 6. `auditor/cli.py`

### CLI-CRIT-01 — `get_github_token()` echoes token via `input()` → stored in shell history, process memory, shoulder-surf
- **Lines:** 48-53 `input("Enter your GitHub token: ")`
- **Impact:** Token visible on screen, saved to `.bash_history` if pasted via CLI, not using `getpass.getpass`.
- **Fix:** `import getpass; token = getpass.getpass("Enter your GitHub token: ")` + warn `GITHUB_TOKEN env var is preferred`.

### CLI-HIGH-01 — `--encryption-key` on CLI leaks to `ps`, `/proc/cmdline`, shell history
- **Lines:** 173 `parser.add_argument("--encryption-key", ...)` + 213-220 deprecation warning still accepts it
- **Issue:** `ps aux | grep auditor` shows key. Mitigated by warning but not prevented.
- **Fix:** Remove the argument entirely; require `OUTPUT_ENCRYPTION_KEY` env var only; if must keep, read from `getpass` not argv. Add `os.environ.pop` after use.

### CLI-HIGH-02 — `generate_pre_commit_config` silently overwrites existing `.pre-commit-config.yaml`
- **Lines:** 30-35 `out.write_text(PRE_COMMIT_HOOK_TEMPLATE)`
- **Impact:** User's existing hooks (lint, test) destroyed. Data loss.
- **Fix:** Check `if out.exists(): logger.error("... exists, use --force to overwrite"); return` or merge with `yaml.safe_load` preserving other repos.

### CLI-MED-01 — No validation for numeric ranges → crash or ineffective scan
- **Lines:** 133-151 `max_concurrency`, `timeout`, `checkpoint_interval`, `confidence_threshold`, `max_pages`, `min_stars`, `recent_repos_days`
- **Evidence:** `max_concurrency=0` → `asyncio.Semaphore(max(1,0))` → becomes 1 silently (ok) but `max_concurrency=-5` → `max(1,-5)=1` silently fixes but user intended error. `confidence_threshold=200` → all keys flagged CRITICAL incorrectly. `timeout=0` → immediate timeout. `recent_repos_days=-1` → discovers future repos (cutoff in future).
- **Fix:** Add validators:
  ```python
  if args.max_concurrency <1: parser.error("max_concurrency must be >=1")
  if not 0 <= args.confidence_threshold <=100: parser.error("confidence_threshold 0-100")
  if args.timeout <1: parser.error("timeout >=1")
  if args.recent_repos_days is not None and args.recent_repos_days <1: parser.error("recent_repos_days >=1")
  ```

### CLI-MED-02 — `parser.error` inside `parse_args` calls `sys.exit(2)` — untestable side effect
- **Lines:** 207,209,211 `parser.error(...)`
- **Issue:** Library function should raise `ValueError` so tests can assert. `parser.error` prints to stderr and exits 2, making `--recent-repos-days` conflict untestable without subprocess.
- **Fix:** Raise `argparse.ArgumentTypeError` or `ValueError` and let `__main__.py` handle `SystemExit`.

### CLI-MED-03 — `--providers` does not validate names; typo silently yields 0 tasks
- **Lines:** 98-101 default `openai,anthropic` and 98-101 help but no check; `__main__.py:149` warns unknown provider skipping but continues with 0 tasks → `audit complete, total 0` with no error.
- **Fix:** Validate after split: `invalid = [p for p in selected if p not in PROVIDER_CONFIGS and p!="all"]; if invalid: parser.error(f"unknown providers: {invalid}")`.

### CLI-MED-04 — `--sort` choices include empty string as valid value (weird UX) + default `indexed` may be invalid for Code Search API
- **Line:** 125 `choices=["indexed",""] default="indexed"`
- **Issue:** `--sort ""` is legal, produces `sort=` empty param → API 422. Help says “indexed” default but GitHub Search `sort=indexed` is undocumented; may 422. Empty string should not be a choice.
- **Fix:** `choices=["indexed"]` with `default="indexed"` and handle `if args.sort: sort_param=... else ""`.

### CLI-MED-05 — `--output-file` derived silently may overwrite previous run (no confirmation)
- **Lines:** 199-202 `if not args.output_file: args.output_file = f"output/audit_results.{ext}"`
- **Impact:** Second run overwrites first report; combined with `tracker.py:89-91` removing checkpoint only when `not args.resume` but output not versioned.
- **Fix:** Append timestamp or fail if exists without `--force`.

### CLI-LOW-01 — `parse_csv_arg` discards empty items without warning → `--providers "openai,,github,"` silently becomes `["openai","github"]`
- **Lines:** 41-45
- **Effect:** Typos like double commas hidden. Minor.
- **Fix:** Warning if `value` contained `,,` or trailing comma.

### CLI-LOW-02 — `--dir` not validated as directory at parse time → late error in scanner (logger.error only)
- **Lines:** 106-108 `help="Local directory...` no validation; scanner.py:638 logs error but returns 0 findings, exit 0.
- **Fix:** Add `if args.mode in ("local","git-history") and not args.dir: parser.error("--dir is required")` already in `__main__.py:158` raise ValueError → should move to `parse_args` for early failure.

### CLI-LOW-03 — Token prompt not used for `mode=local` bypass can still trigger via `--validate`
- **Lines:** 82-87 `if args.mode in ("local","git-history"): token=""`
- **Issue:** `--validate --mode local` still needs provider API calls to validate keys (no token needed for some, but GitHub validation would fail without token). Flow permits empty token then validation 401 misinterprets.
- **Fix:** Document or warn: `if args.validate and args.mode in ("local",...) and any(p in local_keys for p in ...): logger.warning("validation without GITHUB_TOKEN may fail for GitHub keys")`.

---

## 7. Cross-cutting / Secrets Handling

### X-HIGH-01 — Checkpoint `progress.json` stores `key_hash` + `key_masked` + raw `key` (if enabled) with world-readable permissions
- **Lines:** `tracker.py:78-92` `Path.write` default `0o644`; `__main__.py:93-95`
- **Impact:** Any local user can read `output/progress.json` and recover 12-char slices or full keys if `store_raw_keys`. On shared runners, secret leak.
- **Fix:** `os.chmod(path, 0o600)` after write; or encrypt checkpoint when `encrypt_output` true.

### X-MED-01 — No scrubbing of secrets from logs (`scanner.py` `logger.info` includes `repo/path` but not key; `exporter` `logger.info("Results exported to %s")` safe, but `mask_key` still logs masked slice. Acceptable risk but document.

---

## Summary Table (remaining findings beyond the 2 partial)

| File | ID | Severity | Line(s) | Short title | Fix effort |
|------|----|----------|---------|-------------|------------|
| patterns.py | P-HIGH-03 | HIGH | 25 | HF length too strict | 1 line |
| patterns.py | P-HIGH-04 | HIGH | 6-7 | Anthropic prefix incomplete | 1 line |
| scoring.py | S-HIGH-01 | HIGH | 81 | Diversity inflates short keys | 3 lines |
| validator.py | V-HIGH-01 | HIGH | 17-30 | `no_ssl_verify` disables TLS | 5 lines |
| validator.py | V-HIGH-02 | HIGH | 130,177 | Slack/Cloudflare conflate invalid vs 429 | 10 lines |
| exporter.py | E-HIGH-01 | HIGH | 60 | CSV injection bypass (leading space) | 2 lines |
| exporter.py | E-HIGH-02 | HIGH | 44,71,234 | Raw secret disclosure to world-readable file | 4 lines |
| cli.py | CLI-CRIT-01 | CRITICAL | 53 | `input()` echoes token | 1 line |
| cli.py | CLI-HIGH-01 | HIGH | 173,213 | `--encryption-key` leaks via ps | remove arg |
| cli.py | CLI-HIGH-02 | HIGH | 33 | Overwrites `.pre-commit-config.yaml` | 5 lines |
| +18 MED +6 LOW | — | MED/LOW | — | See sections 1-7 above | — |

---

## Recommended Fix Priority

**P0 (do now):** CLI-CRIT-01 (getpass), V-HIGH-01 (warn/log), E-HIGH-01/E-HIGH-02 (CSV + file perms), V-HIGH-02 (status-aware validation).
**P1 (next):** P-HIGH-03/04 (regex false negatives), S-HIGH-01, V-MED-04 (semaphore), C-MED-01 (fail on bad YAML).
**P2 (hardening):** P-MED-01 to P-MED-08, E-MED-01/02, C-MED-02/04, CLI-MED-01/03.

No files were edited per task instruction. Re-run audit after fixes with `python -m pytest tests/test_patterns.py -v` and manual regex corpus test.

