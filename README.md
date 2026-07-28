<div align="center">

<!-- Animated header banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:e94560,100:0f3460&height=220&section=header&text=check_please&fontSize=72&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Your%20secrets%20deserve%20better%20than%20copy-paste&descSize=18&descAlignY=55&descAlign=50" width="100%"/>

<br/>

<!-- Badges row 1 -->
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-e94560?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-153%2F153_passing-00c853?style=for-the-badge&logo=pytest&logoColor=white)](#-quality)
[![Self-Test](https://img.shields.io/badge/invariants-7%2F7_verified-00c853?style=for-the-badge&logo=checkmarx&logoColor=white)](#-quality)
[![Type-Checked](https://img.shields.io/badge/mypy-strict_clean-00c853?style=for-the-badge&logo=python&logoColor=white)](#-quality)
[![Security Audit](https://img.shields.io/badge/hostile_audit-REMEDIATED-00c853?style=for-the-badge&logo=hackthebox&logoColor=white)](HOSTILE_AUDIT_REPORT.md)

<!-- Badges row 2 -->
[![Providers](https://img.shields.io/badge/providers-16_supported-0f3460?style=for-the-badge&logo=keycdn&logoColor=white)](#-providers-16)
[![Interfaces](https://img.shields.io/badge/interfaces-6_modes-0f3460?style=for-the-badge&logo=windowsterminal&logoColor=white)](#-interfaces)
[![Zero Dependencies](https://img.shields.io/badge/runtime_deps-3_total-0f3460?style=for-the-badge&logo=pypi&logoColor=white)](#-install)
[![MCP Badge](https://lobehub.com/badge/mcp/senpai-sama7-check-please)](https://lobehub.com/mcp/senpai-sama7-check-please)
[![MCP Badge](https://lobehub.com/badge/mcp-full/senpai-sama7-check-please?theme=light)](https://lobehub.com/mcp/senpai-sama7-check-please)

<br/>

> **The credential broker that other tools wish they were.**
> While some projects *(cough, OpenClaw, cough)* think "security" means printing your API key to stdout and hoping for the best, we built session-authenticated, PBKDF2-encrypted, HMAC-verified, rate-limited, scoped, logged, and revocable credential management.
> You know — *actual* security.

<br/>

```
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   🔐  Encrypted vault (PBKDF2 · SHAKE-256 · HMAC · at-rest) ║
  ║   🤖  AI agent broker (scoped · logged · revocable)         ║
  ║   🔍  16-provider audit pipeline (live API validation)       ║
  ║   🖥️  6 interfaces (CLI · TUI · Web · Desktop · API · MCP)  ║
  ║   ⚡  Prometheus /metrics · circuit breaker · HTTP/2 pool  ║
  ║   🧬  Property + chaos + OpenAPI + perf regression tests   ║
  ║   🛡️  Hostile security audit: PASSED                        ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
```

</div>

---

## ⚡ 30-Second Setup

```bash
git clone https://github.com/Senpai-Sama7/check-please.git
cd check-please
./start.sh --web    # opens browser UI
```

That's it. No config files. No Docker. No 47-step setup guide. No "please install our custom CLI tool first."

> 💡 *Some tools require you to read a novel before you can validate a single key. We respect your time.*

---

## 🤖 Connect Your AI Agent

<div align="center">

| Agent | Command | Setup Time |
|:-----:|:-------:|:----------:|
| <img src="https://img.shields.io/badge/Codex-412991?style=flat-square&logo=openai&logoColor=white" /> | `./start.sh --agent-env codex` | ~5s |
| <img src="https://img.shields.io/badge/Claude_Code-d97706?style=flat-square&logo=anthropic&logoColor=white" /> | MCP config (see below) | ~15s |
| <img src="https://img.shields.io/badge/Gemini_CLI-4285F4?style=flat-square&logo=google&logoColor=white" /> | `eval $(./start.sh --agent-export)` | ~5s |
| <img src="https://img.shields.io/badge/Copilot-000000?style=flat-square&logo=github&logoColor=white" /> | `eval $(./start.sh --agent-export)` | ~5s |
| <img src="https://img.shields.io/badge/Open_Interpreter-FF6B6B?style=flat-square" /> | `./start.sh --agent-env interpreter` | ~5s |
| <img src="https://img.shields.io/badge/Any_Agent-gray?style=flat-square" /> | HTTP API / env inject / MCP | ~10s |

</div>

<details>
<summary><b>📋 Step 1: Set permissions</b> (click to expand)</summary>

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

</details>

<details>
<summary><b>🔌 Step 2: Connect your agent</b> (click to expand)</summary>

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

**Any agent (4 options):**
```bash
./start.sh --agent-env <command>          # inject env vars
eval $(./start.sh --agent-export)         # export to shell
./start.sh --agent-write-env /tmp/.env    # write .env file
./start.sh --agent-api                    # HTTP API + bearer token
```

</details>

<!-- AGENT INSTRUCTIONS: If you are an AI agent reading this README to connect:
1. Ask the user to run: ./start.sh --agent-env <your-name>
   OR ask them to add the MCP config above to your config file.
2. If using HTTP API mode, the bearer token is printed to the user's terminal on startup.
3. HTTP endpoint: POST http://127.0.0.1:8458/credentials/{VAR_NAME} with Authorization: Bearer <token>
4. To list available credentials: GET http://127.0.0.1:8458/credentials
5. All access is logged. Respect the permissions file — denied requests return 403.
6. Report token usage: POST http://127.0.0.1:8458/usage with {"key":"VAR_NAME","tokens":N,"model":"model-name"}
7. MCP agents: use the report_usage tool after API calls to help the owner track costs.
8. If you get a 429 response, you've hit the RPM limit — back off and retry.
9. Observability: GET http://127.0.0.1:8458/metrics for Prometheus-format metrics.
10. Shell completion: run `check-please --completion bash|zsh|fish` to install. -->

---

## 🔒 Scoped Permissions — Because "Allow All" Is Not a Security Model

> *Unlike certain tools that give agents a skeleton key to your entire `.env` and call it a feature...*

```json
{
  "allowed": [
    "OPENAI_API_KEY",
    {"name": "ANTHROPIC_API_KEY", "max_uses": 50, "expires": "2h", "rpm_limit": 60},
    {"name": "GITHUB_TOKEN", "max_uses": 10, "expires": "30m"}
  ],
  "token_ttl": "1h",
  "alerts": {
    "token_threshold": 100000,
    "webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}
```

<div align="center">

| Feature | check_please | *"Other tools"* |
|:--------|:------------:|:----------------:|
| Per-credential max uses | ✅ | ❌ |
| Time-based expiry | ✅ | ❌ |
| RPM rate limiting | ✅ | ❌ |
| Bearer token TTL | ✅ | ❌ |
| Slack/Discord alerts | ✅ | ❌ |
| Per-agent usage tracking | ✅ | ❌ |
| Session-authenticated API | ✅ | 😬 |
| Encrypted vault | ✅ PBKDF2 200K | 🤷 plaintext? |
| Circuit breaker + /metrics | ✅ | ❌ |

</div>

---

## 📊 Usage Tracking, Alerts & Metrics

Every credential request is counted. Every token is tracked. Every agent is logged.

```bash
# Real-time monitoring
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/usage

# Per-key breakdown
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/usage/OPENAI_API_KEY

# Prometheus-format metrics (counters, gauges, histograms)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/metrics
```

**Alerts fire automatically:**
- 🚨 Agent exceeds RPM limit → `429` + terminal warning + webhook (https-only, private-host blocked)
- 💰 Token threshold exceeded → terminal warning + webhook
- 📝 All access logged to `agent_usage.log` (append-only JSON)

**Prometheus metrics exposed:**
- `check_please_http_requests_total` (counter)
- `check_please_http_requests_granted_total` / `_denied_total`
- `check_please_http_request_duration_seconds` (histogram)
- `check_please_audits_total` / `check_please_keys_validated_total` / `check_please_keys_valid_total` / `check_please_keys_failed_total`
- `check_please_cache_hits_total` / `check_please_cache_misses_total` / `check_please_cache_size`
- `check_please_circuit_breaker_trips_total`
- `check_please_audit_duration_seconds` (histogram)

---

## 🖥️ Interfaces

<div align="center">

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   CLI ──── check-please --env .env        (table output)    │
│   TUI ──── ./start.sh --tui              (rich terminal)    │
│   Web ──── ./start.sh --web              (browser SPA)      │
│   Desktop  ./start.sh --desktop          (native GTK app)   │
│   API ──── ./start.sh --agent-api        (HTTP broker)      │
│   MCP ──── ./start.sh --agent-mcp        (Claude/Copilot)   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

</div>

| Lock Screen | Dashboard | Audit Results |
|:-----------:|:---------:|:-------------:|
| ![Lock Screen](docs/screenshots/lock-screen.png) | ![Dashboard](docs/screenshots/dashboard.png) | ![Audit](docs/screenshots/audit.png) |

| Password Vault | Settings | Build .env |
|:--------------:|:--------:|:----------:|
| ![Vault](docs/screenshots/vault.png) | ![Settings](docs/screenshots/settings.png) | ![Build](docs/screenshots/build-env.png) |

> 📸 Screenshots coming soon. Run `./start.sh --web` to see the live UI.

---

## 🔍 Providers (16)

<div align="center">

| Provider | Key Pattern | Provider | Key Pattern |
|:--------:|:-----------:|:--------:|:-----------:|
| ![OpenAI](https://img.shields.io/badge/-OpenAI-412991?style=flat-square&logo=openai&logoColor=white) | `sk-*` | ![Anthropic](https://img.shields.io/badge/-Anthropic-d97706?style=flat-square&logo=anthropic&logoColor=white) | `sk-ant-*` |
| ![Google](https://img.shields.io/badge/-Gemini-4285F4?style=flat-square&logo=google&logoColor=white) | `AIza*` | ![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat-square&logo=github&logoColor=white) | `ghp_*` `gho_*` |
| ![Stripe](https://img.shields.io/badge/-Stripe-635BFF?style=flat-square&logo=stripe&logoColor=white) | `sk_live_*` | ![Slack](https://img.shields.io/badge/-Slack-4A154B?style=flat-square&logo=slack&logoColor=white) | `xox[bpas]-*` |
| ![HuggingFace](https://img.shields.io/badge/-HuggingFace-FFD21E?style=flat-square&logo=huggingface&logoColor=black) | `hf_*` | ![Groq](https://img.shields.io/badge/-Groq-F55036?style=flat-square) | `gsk_*` |
| ![Mistral](https://img.shields.io/badge/-Mistral-FF7000?style=flat-square) | alphanumeric | ![NVIDIA](https://img.shields.io/badge/-NVIDIA-76B900?style=flat-square&logo=nvidia&logoColor=white) | `nvapi-*` |
| ![DeepSeek](https://img.shields.io/badge/-DeepSeek-0066FF?style=flat-square) | `sk-*` (hex) | ![Together](https://img.shields.io/badge/-Together-000000?style=flat-square) | hex (64) |
| ![OpenRouter](https://img.shields.io/badge/-OpenRouter-6366F1?style=flat-square) | `sk-or-v1-*` | ![Cerebras](https://img.shields.io/badge/-Cerebras-FF4500?style=flat-square) | `csk-*` |
| ![SendGrid](https://img.shields.io/badge/-SendGrid-1A82E2?style=flat-square&logo=twilio&logoColor=white) | `SG.*.*` | ![Twilio](https://img.shields.io/badge/-Twilio-F22F46?style=flat-square&logo=twilio&logoColor=white) | hex (32) |

</div>

> Adding a provider? Drop a single file in `credential_auditor/providers/`. Auto-discovered. Zero config. No registration. *Some frameworks make you write a plugin manifest, register a factory, and sacrifice a goat. We don't.*

---

## 🛡️ Security

<div align="center">

```
  ┌──────────────────────────────────────────────────────────┐
  │                    SECURITY LAYERS                       │
  ├──────────────────────────────────────────────────────────┤
  │                                                          │
  │  🔑  PBKDF2-HMAC-SHA256 · 200,000 iterations            │
  │  🧂  16-byte random salt per account                     │
  │  ✅  HMAC-SHA256 integrity verification                  │
  │  🍪  HttpOnly + SameSite=Strict session cookies          │
  │  🚫  Exponential backoff (1s → 2s → 4s → ... → 30s)     │
  │  📏  Content-Security-Policy enforced                    │
  │  🔒  chmod 600 on all vault/account files                │
  │  🛑  10MB request body limit (anti-DoS)                  │
  │  🏠  localhost-only binding                              │
  │  📝  All access logged (append-only)                     │
  │  🔗  Symlink/hardlink attack detection (parent chain)    │
  │  🚫  No raw keys in any output — ever                    │
  │  🔐  Circuit breaker prevents credential-stuffing DoS    │
  │  🚦  Webhook SSRF guard (https-only, no private hosts)   │
  │  💉  CSV formula injection sanitized on export            │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
```

</div>

> 🔴 **Hostile security audit: [PASSED](HOSTILE_AUDIT_REPORT.md)** — 10-part adversarial audit covering crypto, auth, input validation, network security, file system, and dependencies. All critical findings fixed. [Read the full report →](HOSTILE_AUDIT_REPORT.md)

### Security Headers

Every response includes:
- `X-Frame-Options: DENY` — clickjacking protection
- `X-Content-Type-Options: nosniff` — MIME sniffing prevention
- `Content-Security-Policy` — script/style source restrictions
- `Referrer-Policy: no-referrer` — zero URL leakage
- `X-XSS-Protection: 1; mode=block` — legacy XSS filter

### Brute Force Protection

```
Attempt 1 → 1s lockout
Attempt 2 → 2s lockout
Attempt 3 → 4s lockout
Attempt 4 → 8s lockout
Attempt 5 → 16s lockout
Attempt 6+ → 30s lockout (capped)
```

### Circuit Breaker

Per-provider circuit breaker protects against credential-stuffing and outage cascades:
- 5 consecutive failures → circuit **opens** (fast-fail for 30s)
- After 30s → circuit goes **half-open** (allows one test request)
- On success → circuit **closes** (normal traffic resumes)

---

## 🔐 Password Vault

Your vault stores passwords, API keys, and credentials — all encrypted locally.

- ✅ **Add/edit/delete** entries with site, username, password, notes
- ✅ **Password generator** with configurable length and complexity
- ✅ **Import CSV** from Chrome, 1Password, Bitwarden, LastPass, etc.
- ✅ **Export CSV** (formula-injection-safe) for portability
- ✅ **Biometric unlock** via phone (FIDO2/WebAuthn)
- ✅ **Encrypted backups** (`.cpbackup` files)
- ✅ **Emergency recovery sheet** (printable)
- ✅ **Multi-account** support

> *Your data never leaves your machine. No cloud sync. No telemetry. No "anonymous" analytics. Just your secrets, encrypted, on your disk. Revolutionary concept, apparently.*

---

## 📡 HTTP API Reference

| Method | Path | Description |
|:------:|:-----|:------------|
| `GET` | `/providers` | List providers and env var names (no values) |
| `GET` | `/credentials` | List allowed credential names (no values) |
| `POST` | `/credentials/{VAR}` | Get credential value (if permitted) |
| `GET` | `/health` | Server status |
| `GET` | `/metrics` | Prometheus-format metrics |
| `GET` | `/usage` | Usage summary for all credentials |
| `GET` | `/usage/{VAR}` | Per-credential usage stats |
| `POST` | `/usage` | Agent reports token consumption |

All requests require `Authorization: Bearer <token>`. Token displayed on startup.

Full OpenAPI 3.1 spec in [`openapi.yaml`](openapi.yaml).

---

## ⚡ Performance & Resilience

- **Connection pooling**: 20 keep-alive + 100 max connections per `httpx` client
- **HTTP/2**: enabled by default (falls back gracefully if `httpx[http2]` missing)
- **Concurrent audit**: 10 parallel provider checks with throttled semaphore
- **Failed-provider bail**: skip provider after 3 consecutive auth failures
- **Auto-detect**: keys matched by format pattern when env var name is ambiguous (specificity-sorted)

---

## 🧬 Quality

We don't ship on hope. Every change must pass these gates:

```bash
python -m pytest tests/ -q          # 153 tests — property, chaos, contract, perf, security
python -m mypy credential_auditor   # strict mode, 0 errors
python -m credential_auditor --self-test  # 7 invariant checks
```

**Test coverage by category:**

| Suite | Count | Purpose |
|---|---:|---|
| `test_models.py` | existing | Frozen dataclass + canonical JSON ordering |
| `test_providers.py` | existing | 16-provider registry, format matching, auto-detect |
| `test_security_organize.py` | existing | Symlink/hardlink detection, env permissions |
| `test_crypto_vault.py` | existing | PBKDF2/SHAKE-256/HMAC encryption, recovery |
| `test_agent_modes.py` | existing | --export, --env, --write-env, --mcp |
| `test_usage_tracker.py` | existing | RPM tracking, scope enforcement |
| `test_properties.py` | 16 | Hypothesis property-based invariants (200+ examples each) |
| `test_chaos.py` | 10 | Network failures, partial isolation, concurrency chaos |
| `test_openapi_contract.py` | 11 | Spec validity, endpoint coverage, response schema |
| `test_cli_completion.py` | 5 | Bash/zsh/fish completion scripts |
| `test_metrics.py` | 8 | Prometheus exposition format + /metrics endpoint |
| `test_performance.py` | 9 | Throughput baselines with 20% regression margin |

**Established performance baselines:**

| Operation | Baseline | Test |
|---|---:|---|
| KeyFingerprint.from_key | ≥ 8,000 ops/s | `test_fingerprint_throughput` |
| redact_key (partial) | ≥ 20,000 ops/s | `test_redaction_throughput` |
| Cache put+get cycle | ≥ 5,000 ops/s | `test_cache_put_get_throughput` |
| detect_provider_by_key | ≥ 1,000 keys/s | `test_detect_throughput` |
| Circuit breaker lookup | < 10μs/call | `test_circuit_breaker_lookup_overhead` |
| Env pattern match | ≥ 5,000 ops/s | `test_env_pattern_match_throughput` |
| _literal_prefix_len | ≥ 50,000 ops/s | `test_literal_prefix_len_throughput` |
| 50-key audit (mock) | < 2.0s | `test_audit_50_keys_under_2s` |

---

## 🧪 Self-Healing & Error Handling

<details>
<summary><b>💪 What auto-recovers</b> (click to expand)</summary>

| Scenario | What Happens |
|:---------|:-------------|
| Corrupt vault file | Returns empty vault — no crash |
| Corrupt account file | Returns "not found" — others unaffected |
| Missing data directory | Auto-created on startup |
| Wrong backup password | Clear error — file untouched |
| Invalid JSON in data | Safe default returned |
| Legacy single-account data | Auto-migrated to multi-account |
| WebAuthn not supported | Falls back to browser |
| Downloads folder missing | Auto-created |
| Provider circuit open | Fast-fail with `network_error`, auto-retry after 30s |
| Corrupted key regex | Returns "no provider matched" — no crash |

</details>

<details>
<summary><b>🚫 What doesn't recover (by design)</b> (click to expand)</summary>

- **Lost password + lost recovery key + no backup** = data is gone. No backdoors. That's the point.
- **Deleted data files** = gone without backup. No shadow copies.
- **Corrupted encrypted backup** = unrecoverable. Keep multiple backups.

</details>

---

## 🏗️ Adding a Provider

```python
# credential_auditor/providers/myprovider_p.py — that's it. One file.
class MyProvider(Provider):
    name: ClassVar[str] = "myprovider"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^MY_API_KEY$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^mk-[a-z0-9]{32}$")

    async def validate(self, key, client):
        resp = await client.get("https://api.example.com/me",
                                headers={"Authorization": f"Bearer {key}"})
        if resp.status_code == 200:
            return "valid", "account info", None, None, None, None
        return "auth_failed", None, None, None, None, "Invalid key"
```

Drop the file. Run the tool. Provider auto-discovered. **Zero registration, zero config, zero boilerplate.**

---

## 🐚 Shell Completion

```bash
# Bash
eval "$(check-please --completion bash)"

# Zsh
eval "$(check-please --completion zsh)"  # then add to your fpath

# Fish
check-please --completion fish | source
```

All options (--env, --provider, --output, --redaction-level, etc.) are fully tab-completable, with provider names dynamically resolved from `--list-providers`.

---

## 📦 Install

```bash
pip install .           # core (3 deps: httpx, rich, python-dotenv)
pip install ".[tui]"    # + Textual TUI
pip install ".[dev]"    # + pytest, mypy, hypothesis (for development)
```

Or just run `./start.sh` — handles venv, deps, and launch automatically.

### Requirements

- Python 3.10+
- `httpx >= 0.27` (HTTP client)
- `rich >= 13.0` (terminal formatting)
- `python-dotenv >= 1.0` (`.env` parsing)

No native extensions. No Rust toolchain. No npm. Just `pip install` and go.

---

## 🏆 Why check_please?

| | check_please | OpenClaw | "Just use .env" |
|:--|:---:|:---:|:---:|
| Encrypted vault | ✅ PBKDF2 200K | ❌ | ❌ |
| Session authentication | ✅ HttpOnly cookies | ❌ global state | N/A |
| Per-credential scoping | ✅ max_uses + TTL + RPM | ❌ | ❌ |
| Brute force protection | ✅ exponential backoff | ❌ | N/A |
| 16 provider validation | ✅ live API checks | partial | ❌ |
| MCP support | ✅ native | ❌ | ❌ |
| Biometric unlock | ✅ FIDO2/WebAuthn | ❌ | ❌ |
| Security audit | ✅ [hostile audit passed](HOSTILE_AUDIT_REPORT.md) | 🤷 | 🤷 |
| Request body limits | ✅ 10MB cap | ❌ OOM me | N/A |
| Security headers | ✅ CSP + HSTS + XFO | ❌ | N/A |
| Circuit breaker | ✅ per-provider | ❌ | N/A |
| Prometheus /metrics | ✅ | ❌ | N/A |
| Shell completion | ✅ bash/zsh/fish | ❌ | N/A |
| Property-based tests | ✅ hypothesis | ❌ | N/A |
| Chaos tests | ✅ 10 scenarios | ❌ | N/A |
| OpenAPI contract tests | ✅ 11 endpoints | ❌ | N/A |
| Type-checked (mypy strict) | ✅ 0 errors | 🤷 | N/A |
| Setup time | ~30 seconds | ??? | instant (insecure) |
| Runtime dependencies | 3 | 🤷 | 0 |

<br/>

*We're not saying other tools are bad. We're saying we tested ours with a hostile security audit and published the results. Can they say the same?* 🫖

<br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:e94560,100:0f3460&height=120&section=footer&animation=fadeIn" width="100%"/>
</div>
