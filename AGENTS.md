# AGENTS.md — check_please

## Topology (Macro)

Single Python package `credential_auditor` (v1.1.1, Python 3.10+, 3 deps: httpx, rich, python-dotenv). Monolith with 6 interfaces over one core audit pipeline + encrypted vault.

- **Core library**: `credential_auditor/__main__.py` → `orchestrator.py` → `providers/*` → `models.py`
- **Interfaces**: CLI (`__main__.py`), TUI (`tui.py` + `tui.tcss` — requires `textual`), Web SPA (`simple_web.py` — localhost:8457, self-contained HTML/CSS/JS in one file), Desktop (`desktop_app.py` via pywebview), Agent broker (`agent_api.py` — localhost:8458, HTTP + MCP stdio + env-inject/export/write-env), Easy/Simple wizards (`easy_mode.py`, `simple_cli.py`)
- **Entry script**: `start.sh` handles venv creation, dep install, mode dispatch. Supports `--tui`, `--web`, `--easy`, `--simple`, `--guide`, `--agent-api`, `--agent-env CMD`, `--agent-export`, `--agent-write-env PATH`, `--agent-mcp`, `--desktop`, `--dry-run`
- **Deployment**: `Dockerfile` (python:3.12-slim, ENTRYPOINT check-please), `k8s.yaml` (Deployment + ClusterIP Service on 8458), `desktop/` (Linux .desktop + SVG icon)
- **Data dir**: `~/.local/share/check-please/.accounts/` and `.vaults/` — legacy `.account.json`/`.vault.json` auto-migrated. All vault/account files chmod 600.

## Module Decomposition (Meso)

| Module | Role |
|---|---|
| `models.py` | Frozen dataclasses: `KeyResult`, `RateLimitInfo`, `KeyFingerprint`, `AuditSummary`. Canonical 11-field ordering in `to_dict()` (INV-5). 7 statuses: `valid`, `invalid_format`, `auth_failed`, `suspended_account`, `quota_exhausted`, `insufficient_scope`, `network_error` |
| `providers/__init__.py` | ABC `Provider` with `__init_subclass__` auto-registration into `_registry`. Zero-touch addition — new file = new provider. `discover_providers()` via `pkgutil.iter_modules`. `detect_provider_by_key()` auto-detects by key_format specificity (longest literal prefix wins) |
| `providers/*_p.py` | 16 providers: openai, anthropic, google, github, groq, huggingface, mistral, openrouter, cerebras, deepseek, nvidia, together, stripe (2 key types), slack, sendgrid, twilio. Each defines `name`, `env_patterns`, `key_format`, async `validate()` |
| `orchestrator.py` | Async engine: cache lookup → throttled `check_key` (semaphore=10) → failed-provider bail (3 consecutive failures → skip) → auto-detect fallback → sort results. Module-level `ValidationCache` (TTL 3600s, max 10K). Audit log to `audit.log` |
| `cache.py` | TTL cache keyed by `sha256(provider:key)[:16]`, never stores raw keys |
| `security.py` | `RedactionLevel` (partial/full/hash), `suppress_credential_logging()`, `is_symlink_or_hardlink_attack()`, `check_output_permissions()` |
| `output.py` | Rich table + JSON writer. Respects redaction level, symlink guard |
| `audit_log.py` | Append-only structured log, 10MB rotation, symlink refusal |
| `self_test.py` | 7 invariant tests: INV-1 empty providers, INV-2 invalid_format <5ms no net, INV-3 network isolation, INV-4 no raw key in output, INV-5 canonical field order, INV-6 zero-touch addition, plus all-7-statuses-reachable |
| `organize_env.py` | Messy .env normalizer: categorizes, deduplicates, recovers commented keys, handles numbered alts (#2, #3), quotes/escapes values, chmod 600 |
| `agent_api.py` | Agent broker. HTTP: `GET /providers`, `GET /credentials`, `POST /credentials/{VAR}`, `GET /health`, `GET /usage`, `GET /usage/{VAR}`, `POST /usage`. Permissions via `.check_please_agent_permissions.json` with per-cred `max_uses`, `expires`, `rpm_limit`, bearer `token_ttl`, Slack/webhook alerts. Modes: `--serve`, `--env CMD`, `--export`, `--write-env PATH`, `--mcp` |
| `simple_web.py` | Full SPA: lock screen, dashboard, audit, vault (PBKDF2 200K + HMAC-SHA256 + SHAKE-256 keystream XOR + HMAC integrity, v1 compat), multi-account, biometric WebAuthn, CSV import/export, encrypted `.cpbackup`, shell env scan |

## Dependency Graph

```
__main__.py ─┬─> orchestrator.audit() ─┬─> providers.Provider.check_key()
             │                         │        ├─> check_format() (no network)
             │                         │        └─> validate() (live API)
             │                         ├─> cache.ValidationCache
             │                         ├─> audit_log.AuditLog
             │                         └─> security.suppress_credential_logging()
             └─> output.render_table/write_json
                  └─> security.check_output_permissions

agent_api.py → standalone, stdlib-only + dotenv (no httpx needed)
simple_web.py → standalone, stdlib-only (crypto via hashlib/pbkdf2/shake/hmac)
tui.py → textual + orchestrator + organize_env
```

Critical paths: `organize_env` → `orchestrator.audit()` → `output.write_json` → prune dead keys (in `start.sh`). Provider discovery must be called before `Provider.get_registry()`.

## Dev Commands (Exact)

```bash
./start.sh                          # first run → guide, subsequent → easy wizard
./start.sh --web                    # browser UI on :8457
./start.sh --tui                    # Textual TUI (installs textual)
./start.sh --dry-run                # preview without API calls
python -m credential_auditor --env .env --timeout 30
python -m credential_auditor --env .env --provider openai --provider github
python -m credential_auditor --env .env --output audit_report.json --force-insecure-output
python -m credential_auditor --env .env --json -q
python -m credential_auditor --dry-run --env .env
python -m credential_auditor --list-providers
python -m credential_auditor --self-test
pip install -e ".[dev]" && pytest tests/ -q   # CI command
```

Single test: `pytest tests/test_models.py -q`, `pytest tests/test_providers.py -k openai -q`

## Adding a Provider (SOP)

1. Create `credential_auditor/providers/<name>_p.py`
2. Subclass `Provider`, set `name`, `env_patterns` (list of compiled regex), `key_format`, implement `async validate(key, client) -> (status, account_info, scopes, rate_limit, usage_stats, error_detail)`
3. Done — auto-discovered via `__init_subclass__`. No registration needed. Verify with `--list-providers`.

Status discrimination pattern (see `openai_p.py:14`, `github_p.py:2`): 200→valid, 401→auth_failed, 403 check body/header for suspended vs scope vs quota, 429→quota_exhausted, else network_error.

## Conventions & Gotchas

- Frozen dataclasses in `models.py` — immutable, hash=False for list/dict fields
- Never log or output raw keys — only `KeyFingerprint` (prefix/suffix/length or hash). Check INV-4 pattern
- All response JSON guarded by 5MB cap in `_safe_json()` (`providers/__init__.py:104`)
- `httpx.AsyncClient` with `max_redirects=0` passed from orchestrator — providers must not create their own client
- Orchestrator concurrency limit 10, failed-provider bail threshold 3. Env injection now restricted to `_COMPANION_VARS = ("TWILIO_ACCOUNT_SID",)` for security (was previously all non-secret vars)
- `agent_api.py` uses `ThreadingHTTPServer` (was HTTPServer) — now concurrent, so `_CredScope` is thread-safe with `check_and_record()` atomic. Uses `threading.Lock` non-reentrant — `_rpm_unlocked()` must be used inside lock, not `get_rpm()`. Tracker has proactive eviction and empty-deque cleanup to prevent memory leak. Webhook SSRF guard: only https, blocks localhost/private IPs.
- `simple_web.py` uses `ThreadingHTTPServer` with `daemon_threads=True`. Session globals `_current_user`, `_session_token`, `_session_passkey` — cleared on logout, validated on `/api/` routes. Vault `_save_vault()` now refuses to overwrite encrypted vault without session key (prevents downgrade to plaintext). `_valid_username` now forbids `.`, `..`, leading dot, `..` substring, and non-alphanumeric names. `_valid_env_key` regex prevents injection in `/api/env/scan-import`. CSV export now sanitizes formula injection (`=+-@|%` prefixed with `'` and `QUOTE_ALL`).
- Vault encryption: PBKDF2 200K → split into enc_key/mac_key via HMAC domain separation. v2 uses SHAKE-256 keystream + HMAC tag. v1 compat retained for migration (`simple_web.py:177`)
- `organize_env.py` `organize()` returns dict stats for TUI; `organize_env()` writes file directly
- File permissions: all vault/account/organized outputs → chmod 600. `security.check_output_permissions()` now also checks parent symlink chain (TOCTOU mitigation)
- Rate limit extraction: `_extract_rate_limit()` handles both epoch and seconds-until-reset headers
- Provider detection: `_literal_prefix_len` now skips negative lookahead `(?!...)`. `detect_provider_by_key()` sorts by literal prefix, then charset specificity (hex more specific than alphanum), then pattern length. OpenAI regex now excludes `sk-ant-` and `sk-or-v1-` via negative lookahead. Twilio SID validation now case-insensitive `AC[a-fA-F0-9]{32}`
- Cache: `clear()` now resets stats. Added `purge_expired()` and proactive eviction on write path.
- `_parse_duration` now accepts plain seconds (`"3600"`) and case-insensitive units (`"30M"`). Previously returned 0 for plain numbers.
- `desktop_app.py` now uses direct `ThreadingHTTPServer` bind with retry to avoid TOCTOU race (was check-then-bind).
- Test files import via `ROOT` path insertion — `sys.path.insert(0, str(ROOT))` pattern in tests

## Testing & Quality

- `tests/`: `test_agent_modes.py`, `test_crypto_vault.py`, `test_models.py`, `test_providers.py`, `test_security_organize.py`, `test_usage_tracker.py` — now 94 tests (was 93)
- CI: `.github/workflows/ci.yml` — ubuntu-latest, Python 3.12, `pip install -e ".[dev]" && pytest tests/ -q`
- Dev deps: `pytest>=8.0`, `mypy>=1.10` (optional)
- Self-test: `python -m credential_auditor --self-test` runs 7 invariant checks with mock transport, no network
- No mypy config committed — run manually if needed
- `HOSTILE_AUDIT_REPORT.md` is historical — don't re-audit unless asked

## RALPH Build Protocol — Permanent Rules

> These rules were established at project init and apply permanently. Any AI agent reading AGENTS.md must treat these rules as hard constraints, not suggestions.

### EXECUTION RULES (apply to every phase and every task)

**Planning:**
- Use step-by-step reasoning to produce the implementation plan.
  Show your reasoning before code — but the plan is not proof of completion.

**Gates (non-negotiable before marking any task [x]):**
- Every task must pass its gate command before being marked complete.
- Gate command output must appear verbatim in the Proof line (trimmed to relevant lines + timestamp).
- If the gate fails: task stays [ ], error is logged under ❌ FAIL:, and you fix
  before continuing. You do not move to the next task on a failing gate.

**Failures:**
- Do NOT delete original implementation attempts that failed.
- Keep the original code/approach, append ❌ FAIL: with the exact error,
  then append ✅ FIX: with what replaced it and why it worked.

**Proof format (required on every task):**
```
Proof: `<exact command>` → `<trimmed output with exit code>` @ <timestamp>
```

### TRACKER MUTATION RULES — PERMANENT, NON-NEGOTIABLE

1. **Permitted changes on completion only:**
   - `[ ]` → `[x]`
   - Replace `_pending_` with actual proof (command + output + timestamp)
   - Append a row to the Completion Log table

2. **Forbidden at all times:**
   - Rewriting, removing, or reordering any task
   - Adding or removing sections
   - Editing any uncompleted task
   - Replacing proof text without retaining the original attempt record

3. **On failure:** Leave `[ ]`. Append below the Proof line:
   ```
   ❌ FAIL: [error message, timestamp]
   ✅ FIX: [what replaced it and why]
   Proof: [final passing result]
   ```

### Hostile Audit Gates (run after each phase)

- [ ] Does `pytest tests/ -q` return exit 0 with 0 errors?
- [ ] Does `python -m credential_auditor --self-test` return exit 0?
- [ ] Do all new routes/endpoints return expected responses? (show curl or test output)
- [ ] Does the feature work in the running application? (show log)
- [ ] Are there any console errors at runtime?
- [ ] Did you introduce any suppressed errors or disabled checks? If yes: document each with justification.
