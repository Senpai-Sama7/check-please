# check_please

Credential audit pipeline — organizes a messy `.env` file and validates API keys against live provider endpoints.

## Install

```bash
pip install .           # core (httpx, rich, python-dotenv)
pip install ".[tui]"    # + Textual TUI
```

After install, `check-please` is available as a command:

```bash
check-please --env .env              # full audit
check-please --json --env .env       # JSON to stdout
check-please --dry-run --env .env    # preview without API calls
```

## Quick Start (no install)

```bash
./start.sh              # Guided mode (first run: tutorial, then: easy mode)
./start.sh --easy       # Step-by-step wizard
./start.sh --simple     # Numbered menu — no commands to remember
./start.sh --web        # Browser-based visual interface
./start.sh --tui        # Rich terminal UI (requires textual)
./start.sh --guide      # First-time tutorial
./start.sh --agent-api  # Credential broker for AI agents
./start.sh --dry-run    # Preview what would be audited
./start.sh --help       # Full usage docs
```

`start.sh` handles venv setup, dependency installation, and launches your chosen interface.

## CLI

```bash
# Full audit with table + summary
python -m credential_auditor --env .env

# JSON to stdout (pipe to jq, scripts, etc.)
python -m credential_auditor --json --env .env

# Preview without API calls
python -m credential_auditor --dry-run --env .env

# Quiet mode — exit code only (0=all valid, 1=issues, 2=config error)
python -m credential_auditor --quiet --env .env

# Filter by provider
python -m credential_auditor --env .env --provider openai --provider github

# Save report to file
python -m credential_auditor --env .env --output report.json

# List all providers with key patterns
python -m credential_auditor --list-providers

# Self-test (7 invariants)
python -m credential_auditor --self-test

# Version
python -m credential_auditor --version
```

## TUI

A Textual-based terminal UI with five screens:

| Key | Screen | Description |
|-----|--------|-------------|
| `d` | Dashboard | 8 stat cards, full audit results table, action buttons |
| `a` | Audit | Run the full pipeline with color-coded live progress |
| `p` | Report | Summary stats, drill by provider, by status, raw JSON |
| `?` | Help | Keybindings and CLI equivalents |
| `q` | Quit | Exit |

### Dashboard Stat Cards

| Card | Description |
|------|-------------|
| TOTAL KEYS | Number of credentials audited |
| PROVIDERS | Available provider count (16) |
| VALID | Keys that passed validation |
| DEAD | Keys that failed auth |
| AUTO-DETECT | Keys matched by key pattern (not env var name) |
| CACHE HIT% | Validation cache hit rate |
| AVG LATENCY | Average API call latency |
| LAST AUDIT | Timestamp of last audit run |

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
| NVIDIA | `/v2/nvcf/functions` | `nvapi-*` |
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
| Dry run | Preview matched credentials without making API calls |
| JSON stdout | Pipe audit results to jq, scripts, or other tools |
| Quiet mode | Exit code only — for CI/CD pipelines |

## Agent API

A localhost credential broker that lets AI agents (MCP tools, LangChain, AutoGPT, etc.) securely request API keys with your permission.

```bash
./start.sh --agent-api
```

On startup, the broker:
1. Loads your `.env`
2. Generates a one-time bearer token (displayed in terminal)
3. Listens on `http://127.0.0.1:8458`
4. Logs every access to `agent_access.log`

### Permissions

Create `.check_please_agent_permissions.json` to control which credentials agents can access:

```json
{
  "allowed": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
}
```

Agents can only retrieve credentials listed in `allowed`. Everything else is denied.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/providers` | List providers and their env var names (no values) |
| GET | `/credentials` | List allowed credential names (no values) |
| POST | `/credentials/{VAR}` | Get credential value (if permitted) |
| GET | `/health` | Server status |

All requests require `Authorization: Bearer <token>` header.

### Example

```bash
# List what's available
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/credentials

# Get a specific key (must be in allowed list)
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/credentials/OPENAI_API_KEY
```

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
