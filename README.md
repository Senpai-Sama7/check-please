<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=200&section=header&text=CHECK%20PLEASE&fontSize=64&fontColor=fff&animation=fadeIn&fontAlignY=32&desc=The%20Credential%20Broker%20That%20Takes%20Security%20Seriously&descSize=16&descAlignY=55&descAlign=50" width="100%"/>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&duration=3000&pause=1000&color=818CF8&center=true&vCenter=true&repeat=true&width=700&lines=PBKDF2+200K+%C2%B7+HMAC-SHA256+%C2%B7+SHAKE-256;16+Providers+%C2%B7+6+Interfaces+%C2%B7+153+Tests;Circuit+Breaker+%C2%B7+Prometheus+%C2%B7+HTTP%2F2+Pool;mypy+--strict+Clean+%C2%B7+Zero+Trust+by+Default">
  <img alt="Feature ticker" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&duration=3000&pause=1000&color=1a1a2e&center=true&vCenter=true&repeat=true&width=700&lines=PBKDF2+200K+%C2%B7+HMAC-SHA256+%C2%B7+SHAKE-256;16+Providers+%C2%B7+6+Interfaces+%C2%B7+153+Tests;Circuit+Breaker+%C2%B7+Prometheus+%C2%B7+HTTP%2F2+Pool;mypy+--strict+Clean+%C2%B7+Zero+Trust+by+Default">
</picture>

<br/><br/>

[![Python](https://img.shields.io/badge/Python_3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License_MIT-e94560?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests_153%2F153-00c853?style=for-the-badge&logo=pytest&logoColor=white)](#-quality-assurance)
[![Invariants](https://img.shields.io/badge/Invariants_7%2F7-00c853?style=for-the-badge&logo=checkmarx&logoColor=white)](#-quality-assurance)
[![mypy](https://img.shields.io/badge/mypy_--strict_Clean-2ea44f?style=for-the-badge&logo=python&logoColor=white)](#-quality-assurance)
[![Audit](https://img.shields.io/badge/Hostile_Audit_PASSED-00c853?style=for-the-badge&logo=hackthebox&logoColor=white)](HOSTILE_AUDIT_REPORT.md)

[![Providers](https://img.shields.io/badge/Providers_16-0f3460?style=for-the-badge&logo=keycdn&logoColor=white)](#-supported-providers)
[![Interfaces](https://img.shields.io/badge/Interfaces_6-0f3460?style=for-the-badge&logo=windowsterminal&logoColor=white)](#-six-interfaces)
[![Runtime Deps](https://img.shields.io/badge/Runtime_Deps_3-0f3460?style=for-the-badge&logo=pypi&logoColor=white)](#-installation)
[![MCP](https://lobehub.com/badge/mcp/senpai-sama7-check-please)](https://lobehub.com/mcp/senpai-sama7-check-please)

</div>

---

<div align="center">

### `Your .env is a liability. This is the control plane.`

**check_please** is a zero-trust credential broker, encrypted vault, and 16-provider
validation pipeline — engineered to the standard your most paranoid security review demands.

</div>

<br/>

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│   .env ──► [ORGANIZE] ──► [SELF-TEST] ──► [AUDIT] ──► [REPORT] ──► [PRUNE]│
│                                                                            │
│                encrypt ◄── VAULT ──► HMAC verify                           │
│                                                                            │
│   AGENTS ──► scoped broker ──► max_uses · TTL · RPM · usage ledger         │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

<br/>

## ◆ Why check_please Exists

Most tools in this space commit a cardinal sin: they treat your credentials as *convenient
input* instead of *hostile material*. They print keys to stdout, skip permission models,
and call it "developer experience."

We took the opposite approach. Every design decision in check_please starts from the
assumption that **your .env file is the most dangerous artifact on your machine** —
and builds a control plane worthy of that reality.

<table>
<tr>
<td width="33%" align="center">

**🔐 Vault-Grade Crypto**

PBKDF2-HMAC-SHA256 · 200K iterations · SHAKE-256 keystream · HMAC integrity tags · recovery key wrapping

</td>
<td width="33%" align="center">

**🤖 Agent Control Plane**

Per-credential scopes · max_uses · TTL · RPM limits · append-only usage ledger · revocation without rotation

</td>
<td width="33%" align="center">

**⚡ Production-Grade Resilience**

Circuit breakers · HTTP/2 pooling · failed-provider bail · concurrency throttle · Prometheus observability

</td>
</tr>
</table>

---

## ◆ 60-Second Quickstart

```bash
git clone https://github.com/Senpai-Sama7/check-please.git && cd check-please
./start.sh --web
```

> Opens a locked, encrypted SPA in your browser. No config. No cloud. No telemetry.
> First run creates your account; recovery key shown once — write it down.

<details>
<summary><b>⌨️ Prefer the terminal?</b></summary>

```bash
./start.sh --dry-run          # preview without network calls
python -m credential_auditor --env .env --json
python -m credential_auditor --self-test
```

</details>

<details>
<summary><b>🐚 Install shell completion (one-liner)</b></summary>

```bash
# bash
eval "$(check-please --completion bash)"
# zsh
eval "$(check-please --completion zsh)"
# fish
check-please --completion fish | source
```

</details>

---

## ◆ Six Interfaces, One Engine

<div align="center">

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   CLI          check-please --env .env          Power users         │
│   TUI          ./start.sh --tui                 Terminal natives    │
│   WEB          ./start.sh --web                 Everyone            │
│   DESKTOP      ./start.sh --desktop             GUI operators       │
│   API          ./start.sh --agent-api           AI agents           │
│   MCP          ./start.sh --agent-mcp           Claude/Copilot      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

</div>

Every interface sits on the same core: a frozen-dataclass audit pipeline with
canonical 11-field JSON ordering, immutable results, and zero raw-key output paths.

---

## ◆ Supported Providers

<div align="center">

| AI / LLM | | Platform | |
|:--:|:--:|:--:|:--:|
| OpenAI `sk-*` | Anthropic `sk-ant-*` | GitHub `ghp_*` | Stripe `sk_live_*` |
| Google `AIza*` | Groq `gsk_*` | Slack `xox[bpas]-*` | SendGrid `SG.*.*` |
| Mistral | DeepSeek `sk-*` | Twilio hex(32) | OpenRouter `sk-or-v1-*` |
| HuggingFace `hf_*` | NVIDIA `nvapi-*` | Together hex(64) | Cerebras `csk-*` |

</div>

> **Zero-touch extensibility** — adding a provider is one file in `credential_auditor/providers/`.
> Auto-discovered via `__init_subclass__`. No registration. No manifest. No ceremony.

---

## ◆ Agent Broker: Scoped Access, Not Skeleton Keys

Give your AI agents **exactly** the access they need — and nothing more.

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

<table>
<tr>
<td align="center"><b>Capability</b></td>
<td align="center"><b>check_please</b></td>
<td align="center"><b>Typical tools</b></td>
</tr>
<tr><td>Per-credential max uses</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Time-based expiry</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>RPM rate limiting</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Bearer token TTL</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Slack/Discord alerts</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Per-agent usage ledger</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Session-authenticated API</td><td align="center">✅</td><td align="center">😬</td></tr>
<tr><td>Prometheus /metrics</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>MCP stdio server</td><td align="center">✅</td><td align="center">❌</td></tr>
<tr><td>Encrypted vault</td><td align="center">✅ PBKDF2 200K</td><td align="center">🤷 plaintext</td></tr>
</table>

### Wire Your Agent

```bash
# Inject into any subprocess
./start.sh --agent-env codex

# Export to current shell
eval $(./start.sh --agent-export)

# Write to file (chmod 600)
./start.sh --agent-write-env /tmp/.env

# HTTP broker on :8458
./start.sh --agent-api
```

<details>
<summary><b>Claude Code (MCP) — copy-paste config</b></summary>

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

</details>

---

## ◆ Security Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DEFENSE IN DEPTH                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  L1  Crypto      PBKDF2 200K · salt per account · HMAC domain split  │
│  L2  Vault       SHAKE-256 keystream XOR · HMAC-SHA256 tag · v2      │
│  L3  Auth        Exponential backoff 1s→30s · HttpOnly+SameSite=Strict│
│  L4  Filesystem  chmod 600 · symlink+hardlink chain detection        │
│  L5  Network     localhost-only · 10MB body cap · max_redirects=0    │
│  L6  Input       regex whitelists · path traversal guards · CSV-safe │
│  L7  Output      no raw keys ever · redaction levels · 5MB JSON cap  │
│  L8  Resilience  circuit breaker · failed-provider bail · throttle   │
│  L9  SSRF guard  webhook https-only · private-host blocklist         │
│  L10 Logging     append-only · correlation IDs · no credential logs  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Circuit Breaker Behavior

```text
  CLOSED ──── 5 consecutive failures ────► OPEN
    ▲                                        │
    │                              30s timeout
    │                                        ▼
  success on test request ◄───── HALF-OPEN (1 probe allowed)
```

Protects your audit from cascading provider outages — and your account from
credential-stuffing lockouts.

### Prometheus Observability

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8458/metrics
```

Exposes request counters, duration histograms, cache hit/miss rates, circuit-breaker
trips, and per-audit duration — ready for Grafana, Datadog, or vanilla Prometheus.

---

## ◆ Quality Assurance

We don't ship on hope. Three gates, all green, every commit:

```bash
python -m pytest tests/ -q          # 153 tests across 12 suites
python -m mypy credential_auditor   # --strict clean on 27 source files
python -m credential_auditor --self-test  # 7 runtime invariants
```

### Test Suite Breakdown

| Suite | Tests | Purpose |
|---|--:|---|
| `test_models.py` | — | Frozen dataclasses · canonical JSON ordering |
| `test_providers.py` | — | 16-provider registry · format matching · auto-detect |
| `test_security_organize.py` | — | Symlink/hardlink detection · env permissions |
| `test_crypto_vault.py` | — | PBKDF2/SHAKE-256/HMAC · recovery flows |
| `test_agent_modes.py` | — | --export · --env · --write-env · --mcp |
| `test_usage_tracker.py` | — | RPM tracking · scope enforcement |
| `test_properties.py` | **16** | Hypothesis invariants (200+ examples each) |
| `test_chaos.py` | **10** | Network failures · partial isolation · concurrency |
| `test_openapi_contract.py` | **11** | Spec validity · endpoint coverage · schema match |
| `test_cli_completion.py` | **5** | bash/zsh/fish script generation |
| `test_metrics.py` | **8** | Prometheus exposition · /metrics endpoint |
| `test_performance.py` | **9** | Throughput baselines with 20% regression margin |

### Performance Baselines (enforced in CI)

| Operation | Throughput Floor | Actual |
|---|--:|--:|
| KeyFingerprint.from_key | ≥ 8,000 ops/s | measured |
| redact_key (partial) | ≥ 20,000 ops/s | measured |
| Cache put+get cycle | ≥ 5,000 ops/s | measured |
| detect_provider_by_key | ≥ 1,000 keys/s | measured |
| Circuit breaker lookup | < 10μs/call | measured |
| Env pattern match | ≥ 5,000 ops/s | measured |
| _literal_prefix_len | ≥ 50,000 ops/s | measured |
| 50-key audit (mock) | < 2.0s | measured |

---

## ◆ HTTP API Reference

| Method | Path | Purpose |
|:--:|:--|:--|
| `GET` | `/health` | Liveness probe |
| `GET` | `/providers` | Provider → env var mapping (no values) |
| `GET` | `/credentials` | Allowed credential names (no values) |
| `POST` | `/credentials/{VAR}` | Retrieve credential value (scoped) |
| `GET` | `/metrics` | Prometheus exposition |
| `GET` | `/usage` | Aggregate usage summary |
| `GET` | `/usage/{VAR}` | Per-credential usage stats |
| `POST` | `/usage` | Agent token-consumption reports |

All endpoints: `Authorization: Bearer <token>` · security headers · no-store caching.
Full spec: [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1).

---

## ◆ Vault Deep Dive

The encrypted vault is a standalone PBKDF2-secured store for passwords, API keys,
and recovery material — independent of the audit pipeline.

- **At-rest encryption** — v2 SHAKE-256 keystream + HMAC-SHA256 integrity tag
- **Recovery key** — 128-bit, shown once at account creation
- **Key wrapping** — vault key wrapped by passkey AND recovery key (recovery preserves vault)
- **CSV import/export** — Chrome, 1Password, Bitwarden, LastPass compatible (formula-injection-safe)
- **Biometric unlock** — FIDO2/WebAuthn (registration-ready; assertion verification in progress)
- **Encrypted backups** — `.cpbackup` files with passphrase-based restore
- **Multi-account** — isolated vaults per user under `~/.local/share/check-please/.vaults/`

<details>
<summary><b>Crypto construction (v2)</b></summary>

```
PBKDF2-HMAC-SHA256(passkey, salt, 200_000) → master_key
master_key ─┬─► HMAC("check_please:enc")  → enc_key
            └─► HMAC("check_please:mac")  → mac_key

ciphertext  = plaintext XOR SHAKE-256(enc_key || nonce)
tag         = HMAC-SHA256(mac_key, nonce || ciphertext)
```

v1 (PBKDF2-as-stream) is retained for seamless migration of legacy vaults.

</details>

---

## ◆ Error Recovery Matrix

| Failure Mode | Behavior |
|---|---|
| Corrupt vault file | Empty vault returned — no crash |
| Corrupt account file | "Not found" — other accounts unaffected |
| Missing data directory | Auto-created on startup |
| Wrong backup password | Clear error — file untouched |
| Invalid JSON in data | Safe default returned |
| Legacy single-account | Auto-migrated to multi-account |
| Provider circuit open | `network_error` + auto-retry in 30s |
| Malformed regex pattern | "No provider matched" — no exception |

> **Irrecoverable by design**: lost passkey + lost recovery key + no backup = data is gone.
> No backdoors. That's the point.

---

## ◆ Adding a Provider

```python
# credential_auditor/providers/acme_p.py — one file, that's it
class AcmeProvider(Provider):
    name: ClassVar[str] = "acme"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^ACME_API_KEY$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^acme-[a-z0-9]{32}$")

    async def validate(self, key, client):
        resp = await client.get("https://api.acme.com/me",
                                headers={"Authorization": f"Bearer {key}"})
        if resp.status_code == 200:
            return "valid", "account info", None, None, None, None
        return "auth_failed", None, None, None, None, "Invalid key"
```

Drop the file. Run the tool. Provider auto-discovered.
**Zero registration. Zero config. Zero boilerplate.**

---

## ◆ Installation

```bash
pip install .           # runtime: httpx, rich, python-dotenv
pip install ".[tui]"    # + Textual TUI
pip install ".[dev]"    # + pytest, mypy, hypothesis (development)
```

Or `./start.sh` — creates venv, installs deps, launches the wizard. Handles everything.

**Requirements**: Python 3.10+ · no native extensions · no Rust toolchain · no npm.

---

<div align="center">

## ◆ The Honest Comparison

| Capability | check_please | OpenClaw | "Just use .env" |
|---|:--:|:--:|:--:|
| Encrypted vault | ✅ PBKDF2 200K | ❌ | ❌ |
| Session auth | ✅ HttpOnly | ❌ global | N/A |
| Per-credential scoping | ✅ | ❌ | ❌ |
| Circuit breaker | ✅ | ❌ | N/A |
| Prometheus metrics | ✅ | ❌ | N/A |
| Shell completion | ✅ | ❌ | N/A |
| Property-based tests | ✅ | ❌ | N/A |
| Chaos tests | ✅ 10 scenarios | ❌ | N/A |
| OpenAPI contract tests | ✅ | ❌ | N/A |
| mypy --strict clean | ✅ 0 errors | 🤷 | N/A |
| Hostile audit | ✅ PASSED | 🤷 | 🤷 |
| 16-provider validation | ✅ live API | partial | ❌ |
| Setup time | ~30s | ??? | instant (insecure) |

<br/>

*We're not saying other tools are bad. We're saying we published the audit, the
metrics, and the test suite. Can they say the same?*

<br/>

**[Hostile Audit Report](HOSTILE_AUDIT_REPORT.md)** ·
**[OpenAPI Spec](openapi.yaml)** ·
**[Agent Guide](AGENTS.md)**

<br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=120&section=footer&animation=fadeIn" width="100%"/>

**check_please** — because your secrets deserve better than copy-paste.

</div>
