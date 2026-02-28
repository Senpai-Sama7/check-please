# check_please

Secure credential broker for AI coding agents + full audit pipeline for your `.env` file.

Give your AI agents (Codex, Claude Code, Gemini CLI, Copilot, Open Interpreter) access to API keys — scoped, logged, and revocable — without pasting secrets into chat.

## Connect Your AI Agent (30 seconds)

### Step 1: Set permissions

Create `.check_please_agent_permissions.json` in your project root:

```json
{
  "allowed": [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN"
  ],
  "token_ttl": "1h"
}
```

### Step 2: Connect

Pick the method that matches your agent:

**Codex (OpenAI):**
```bash
./start.sh --agent-env codex
```

**Claude Code (MCP):**

Add to `~/.claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "credentials": {
      "command": "python",
      "args": ["/absolute/path/to/check_please/agent_api.py", "--mcp"]
    }
  }
}
```
Then restart Claude Code. The `get_credential` tool becomes available.

**Gemini CLI:**
```bash
eval $(./start.sh --agent-export)
gemini
```

**GitHub Copilot CLI:**
```bash
eval $(./start.sh --agent-export)
ghcs
```

**Open Interpreter:**
```bash
./start.sh --agent-env interpreter
```

**Any agent (generic):**
```bash
# Option A: inject env vars into a command
./start.sh --agent-env <your-agent-command>

# Option B: export to current shell session
eval $(./start.sh --agent-export)

# Option C: write a .env file the agent can read
./start.sh --agent-write-env /tmp/agent.env

# Option D: HTTP API with bearer token
./start.sh --agent-api
# Then: curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/credentials/OPENAI_API_KEY
```

<!-- AGENT INSTRUCTIONS: If you are an AI agent reading this README to connect:
1. Ask the user to run: ./start.sh --agent-env <your-name>
   OR ask them to add the MCP config above to your config file.
2. If using HTTP API mode, the bearer token is printed to the user's terminal on startup.
3. HTTP endpoint: POST http://127.0.0.1:8458/credentials/{VAR_NAME} with Authorization: Bearer <token>
4. To list available credentials: GET http://127.0.0.1:8458/credentials
5. All access is logged. Respect the permissions file — denied requests return 403. -->

### Scoped Permissions

Control exactly how much access each credential gets:

```json
{
  "allowed": [
    "OPENAI_API_KEY",
    {"name": "ANTHROPIC_API_KEY", "max_uses": 50, "expires": "2h"},
    {"name": "GITHUB_TOKEN", "max_uses": 10, "expires": "30m"}
  ],
  "token_ttl": "1h"
}
```

- Plain strings = unlimited access
- `max_uses` = deny after N requests
- `expires` = deny after time limit (`30s`, `5m`, `2h`, `1d`)
- `token_ttl` = bearer token auto-expires

### HTTP API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/providers` | List providers and env var names (no values) |
| GET | `/credentials` | List allowed credential names (no values) |
| POST | `/credentials/{VAR}` | Get credential value (if permitted) |
| GET | `/health` | Server status |

All requests require `Authorization: Bearer <token>` header. Token is displayed on startup.

---

## Install

```bash
pip install .           # core (httpx, rich, python-dotenv)
pip install ".[tui]"    # + Textual TUI
```

Or just run `./start.sh` — it handles venv, deps, and launches automatically.

## Quick Start

```bash
./start.sh              # Guided mode
./start.sh --easy       # Step-by-step wizard
./start.sh --simple     # Numbered menu
./start.sh --web        # Browser UI
./start.sh --tui        # Terminal UI
./start.sh --desktop    # Install as native desktop app
./start.sh --dry-run    # Preview without API calls
./start.sh --help       # Full usage
```

## CLI

```bash
check-please --env .env              # full audit
check-please --json --env .env       # JSON to stdout
check-please --dry-run --env .env    # preview
check-please --quiet --env .env      # exit code only (CI/CD)
check-please --env .env --provider openai --provider github  # filter
check-please --env .env --output report.json  # save report
check-please --list-providers        # show all 16 providers
check-please --self-test             # 7 invariants
```

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

## Interfaces

| Interface | Command | Description |
|-----------|---------|-------------|
| CLI | `check-please --env .env` | Full audit with table output |
| TUI | `./start.sh --tui` | Rich terminal UI (5 screens, keybindings) |
| Web | `./start.sh --web` | Browser-based dashboard |
| Desktop | `./start.sh --desktop` | Native window app (GTK+WebKit) |
| Agent API | `./start.sh --agent-api` | HTTP broker for AI agents |
| MCP | `./start.sh --agent-mcp` | MCP server for Claude Code, Copilot |

## Security

- No raw keys in any output — only fingerprints (`sk-p...89UA (164)`)
- `.env` permissions checked (warns if world-readable)
- Cache keys are SHA-256 hashes — no raw keys in memory
- Agent broker: one-time bearer token, localhost-only
- Agent broker: per-credential scoping (max_uses, TTL expiry)
- Agent broker: all access logged to `agent_access.log`
- httpx debug logging disabled to prevent key leakage

## Adding a Provider

Create `credential_auditor/providers/<name>_p.py`:

```python
class MyProvider(Provider):
    name: ClassVar[str] = "myprovider"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^MY_API_KEY$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^mk-[a-z0-9]{32}$")

    async def validate(self, key, client):
        resp = await client.get("https://api.example.com/me",
                                headers={"Authorization": f"Bearer {key}"})
        if resp.status_code == 200:
            return "valid", "account info", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid key"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
```

Auto-discovered on next run. No registration needed.
