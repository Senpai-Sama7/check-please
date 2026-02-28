# check_please

Credential audit pipeline — organizes a messy `.env` file and validates API keys against live provider endpoints.

## Quick Start

```bash
./start.sh        # CLI pipeline
./start.sh --tui  # Terminal UI
./check_please    # One-click TUI launcher
```

The script handles venv setup, dependency installation, and runs the full pipeline.

## TUI

A Textual-based terminal UI with four screens:

| Key | Screen | Description |
|-----|--------|-------------|
| `d` | Dashboard | Stat cards, full audit results table, action buttons |
| `a` | Audit | Run the full pipeline with live progress and log |
| `p` | Report | Drill into results by provider, by status, or raw JSON |
| `?` | Help | Show keybindings |
| `q` | Quit | Exit |

The Dashboard "Organize" button pushes a sub-screen that runs `.env` organization. Press `Escape` to return from any sub-screen.

## What It Does

| Step | Action |
|------|--------|
| 1 | Finds Python 3.10+ |
| 2 | Creates/verifies virtual environment |
| 3 | Installs dependencies (httpx, rich, python-dotenv) |
| 4 | Verifies `.env` exists |
| 5 | Checks `.env` file permissions |
| 6 | Organizes `.env` → `.env.organized` (categorized, deduped, cleaned) |
| 7 | Runs auditor self-test (7 invariants) |
| 8 | Audits credentials against live APIs |
| 9 | Prunes dead keys from `.env.organized` |

## Providers (16)

| Provider | Endpoint | Key Pattern |
|----------|----------|-------------|
| Anthropic | `/v1/models` | `sk-ant-*` |
| Cerebras | `/v1/models` | `csk-*` |
| DeepSeek | `/models` | `sk-*` (hex) |
| GitHub | `/user` | `ghp_*`, `gho_*`, `github_pat_*` |
| Google/Gemini | `/v1beta/models` | `AIza*` |
| Groq | `/openai/v1/models` | `gsk_*` |
| HuggingFace | `/api/whoami-v2` | `hf_*` |
| Mistral | `/v1/models` | alphanumeric |
| NVIDIA | `/v1/models` | `nvapi-*` |
| OpenAI | `/v1/models` | `sk-*` |
| OpenRouter | `/api/v1/auth/key` | `sk-or-v1-*` |
| SendGrid | `/v3/user/profile` | `SG.*.*` |
| Slack | `/auth.test` | `xox[bpas]-*` |
| Stripe | `/v1/account` | `sk_live_*`, `rk_live_*` |
| Together | `/v1/models` | hex (64 chars) |
| Twilio | `/Accounts/{SID}.json` | hex (32 chars) |

## Output Files

- `.env.organized` — clean, categorized env file (regenerated each run)
- `audit_report.json` — JSON audit results with summary and per-key status
- `audit.log` — structured JSON-line log of all audit events (timestamped)
- `.env` — original file (never modified)

## Features

| Feature | Description |
|---------|-------------|
| Validation cache | TTL-based (1hr) cache prevents redundant API calls across runs |
| Audit log | Structured JSON-line log (`audit.log`) of every validation, auto-detect, and bail event |
| Multi-level redaction | `PARTIAL` (prefix...suffix), `FULL` ([REDACTED]), `HASH` ([sha256:...]) |
| Auto-detect by key pattern | If env var name doesn't match a provider, tries matching the key value against all provider patterns |
| Failed-provider bail | Skips a provider after 3 consecutive auth failures |
| Audit summary | Aggregate stats (valid/failed/errors, cache hits, auto-detected, providers skipped, avg latency) |

## Adding a Provider

Create `credential_auditor/providers/<name>_p.py`:

```python
class MyProvider(Provider):
    name: ClassVar[str] = "myprovider"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^MY_API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^mk-[a-z0-9]{32}$")

    async def validate(self, key, client):
        resp = await client.get("https://api.example.com/me", headers={"Authorization": f"Bearer {key}"})
        if resp.status_code == 200:
            return "valid", "account info", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid key"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
```

Auto-discovered on next run. No registration needed.

## Audit Statuses

| Status | Meaning |
|--------|---------|
| `valid` | Key works, account accessible |
| `invalid_format` | Key doesn't match expected pattern (no network call) |
| `auth_failed` | 401/403 — key rejected |
| `suspended_account` | Account-level suspension |
| `quota_exhausted` | Rate limit or quota at zero |
| `insufficient_scope` | Missing permissions |
| `network_error` | Timeout/DNS/connection failure |

## Security

- No raw keys in any output — only fingerprints (`sk-p...89UA (164)`)
- `.env` permissions checked (warns if world-readable)
- Dead keys auto-pruned from organized file
- httpx debug logging disabled to prevent key leakage
- Cache keys are SHA-256 hashes of `provider:key` — no raw keys stored in memory
