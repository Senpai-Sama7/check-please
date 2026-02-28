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

---

## User Manual

This section is for everyone — no technical knowledge required.

### Getting Started

1. Run `./start.sh --web` (opens in your browser) or `./start.sh --desktop` (opens as a desktop app)
2. The app opens at `http://localhost:8457`
3. You'll see the account creation screen on first launch

### Creating Your Account

1. Pick a username and password (minimum 4 characters)
2. Confirm your password and click "Create Account"
3. A recovery key appears (looks like `ABCD-EFGH-IJKL-MNOP`) — **save this immediately**
4. Click "Copy" to copy it to your clipboard, then paste it somewhere safe
5. Click "I've Saved It — Continue" to enter the app

> ⚠️ Your recovery key is shown once and never again. If you lose your password AND your recovery key, your vault data cannot be recovered. This is by design — nobody (not even us) can access your data without your credentials.

### Signing In

- Enter your username and password, then click "Unlock"
- If you have biometrics set up, click "Unlock with Biometrics" to use your phone instead
- If you have multiple accounts, type your username or pick from the suggestions

### The Dashboard

After signing in, you'll see five pages in the left sidebar:

| Page | What It Does |
|------|-------------|
| 📊 Dashboard | Overview with quick actions |
| 🔍 Audit | Scan and validate your API keys |
| 🔐 Password Vault | Store and manage passwords |
| 📋 Providers | See all 16 supported API providers |
| ⚙️ Settings | Account, biometrics, backups, security |

### Password Vault

Your vault stores passwords, API keys, and login credentials — all encrypted on your device.

**Add a password:**
1. Go to Password Vault → click "Add Entry"
2. Fill in the site name, username, and password
3. Click "Save"

**Generate a strong password:**
1. In the Add Entry form, click "Generate"
2. A random strong password is created and filled in automatically
3. Adjust length or settings if needed, then save

**Import from another password manager:**
1. Export your passwords as CSV from Chrome, 1Password, Bitwarden, etc.
2. Go to Password Vault → click "Import CSV"
3. Select your file — entries are imported into your vault

**Export your vault:**
- Click "Export CSV" to download all entries as a spreadsheet-compatible file

### Auditing Your .env File

The audit tool checks if your API keys are valid, expired, or misconfigured.

1. Go to the Audit page
2. Upload your `.env` file (or it auto-detects one in your project)
3. Click "Run Audit" — each key is tested against its provider's API
4. Results show ✅ Valid, ❌ Failed, or ⚠️ Warning for each key

**Sort and filter results:**
- Use the toolbar to sort by status or provider
- Filter to show only valid, failed, or warning results
- Check individual results or "Select All"

**Remove bad keys:**
- Check the keys you want to remove → click "Remove Selected"
- They're removed from your `.env` file

### Building a .env File

Create a clean, organized `.env` file from your credentials:

1. Go to Audit → click "Build .env"
2. Check which providers/keys to include
3. Click "Preview" to see what the file will look like
4. Click "Download" to save it to your Downloads folder (with real values)
5. Or click "Save" to write it directly as your project's `.env`

The downloaded file is organized with section headers by provider for easy reading.

### Biometric Unlock (Phone)

Use your phone's fingerprint or face recognition to unlock — no password needed.

**Set up:**
1. Go to Settings → click "Set Up Biometrics"
2. Your browser shows a QR code or Bluetooth prompt
3. Scan with your phone and authenticate (fingerprint/face)
4. Done — biometric is now linked to your account

**Use it:**
- On the sign-in screen, click "Unlock with Biometrics"
- Authenticate on your phone when prompted
- You're in — no password required

**Works on the forgot password screen too** — if you forgot your password but have biometrics, just tap the biometric button to skip the recovery process entirely.

> Note: Biometric auth uses your phone via QR code or Bluetooth. Works with any FIDO2-compatible phone (most modern Android and iPhone devices).

### If You Forget Your Password

**Option 1 — Biometrics (easiest):**
Click "Unlock with Biometrics" on the sign-in or forgot password screen.

**Option 2 — Recovery key:**
1. Click "Forgot password?" on the sign-in screen
2. Enter your recovery key (the `XXXX-XXXX-XXXX-XXXX` from account creation)
3. Choose a new password
4. Click "Reset Password" — your vault stays intact

**Option 3 — Encrypted backup:**
1. If you previously exported a backup (`.cpbackup` file), go to Settings
2. Click "Import Encrypted Backup"
3. Select your backup file and enter the backup password
4. Your account and vault are fully restored

**Option 4 — Emergency sheet:**
If you printed an emergency recovery sheet, it has your recovery key and step-by-step instructions.

**Last resort — Erase Everything:**
On the forgot password screen, click "Erase Everything & Start Over." This permanently deletes your account and vault. Only use this if all other options are exhausted.

### Encrypted Backups

Backups protect you against data loss — device wipes, accidental deletion, hardware failure.

**Create a backup:**
1. Go to Settings → "Export Encrypted Backup"
2. Enter a backup password (can be different from your account password)
3. A `.cpbackup` file is saved to your Downloads folder

**Restore from backup:**
1. Go to Settings → "Import Encrypted Backup"
2. Select your `.cpbackup` file
3. Enter the backup password you used when creating it
4. Your account and all vault entries are restored

> 💡 Store backups somewhere safe — USB drive, cloud storage, or email them to yourself. The file is fully encrypted and useless without the backup password.

### Emergency Recovery Sheet

A printable document with your recovery instructions — your paper safety net.

1. Go to Settings → "Print Emergency Sheet"
2. A print dialog opens with a formatted recovery document
3. Print it and store it somewhere physically secure (safe, lockbox, etc.)

The sheet includes space to write your recovery key and step-by-step instructions for getting back into your account.

### Logging Out

Click the 🚪 Log Out button at the bottom of the sidebar. You'll be taken back to the sign-in screen.

---

## Security & Error Handling

### Encryption

- All account data and vault entries are encrypted with PBKDF2-HMAC-SHA256 (200,000 iterations)
- Each account has a unique random salt (16 bytes)
- Ciphertext integrity is verified with HMAC-SHA256 before decryption — tampered data is rejected immediately
- Vault files are set to owner-read-only permissions (`chmod 600`)

### Brute Force Protection

- Failed password attempts trigger exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped)
- The lockout timer resets after a successful login
- The UI shows "Too many attempts. Try again in Xs." when rate-limited

### Security Headers

Every response includes:
- `X-Frame-Options: DENY` — prevents the app from being embedded in iframes (clickjacking)
- `X-Content-Type-Options: nosniff` — prevents browsers from guessing content types
- `Referrer-Policy: no-referrer` — no URL information leaks to other sites
- `X-XSS-Protection: 1; mode=block` — legacy cross-site scripting filter

### Error Handling

| Scenario | What Happens |
|----------|-------------|
| Corrupt vault file | Returns empty vault — no crash, no data loss to other accounts |
| Corrupt account file | Returns "account not found" — other accounts unaffected |
| Missing data directory | Auto-created on startup (`~/.local/share/check-please/`) |
| Missing accounts/vaults folders | Auto-created when first needed |
| Wrong backup password | Clear error message — backup file is not modified or corrupted |
| Invalid JSON in any data file | Caught silently, returns safe default (empty list or None) |
| Server port already in use | Kill the old process with `fuser -k 8457/tcp` and relaunch |
| Legacy single-account data | Auto-migrated to multi-account format on first login |
| WebAuthn not supported | Falls back to opening your browser where it is supported |
| Downloads folder missing | Auto-created before writing backup or .env files |

### Self-Healing Mechanisms

- **Directory auto-creation**: All required directories (`DATA_DIR`, `.accounts/`, `.vaults/`) are created automatically if missing — the app never fails because a folder doesn't exist
- **Legacy migration**: Old single-account data (`.account.json`, `.vault.json`) is automatically migrated to the multi-account format (`.accounts/username.json`, `.vaults/username.json`) on first access — no manual steps needed
- **Graceful corruption handling**: If any JSON data file becomes corrupt, the app returns a safe empty state instead of crashing. Your other accounts and data are unaffected
- **Permission enforcement**: Vault and account files are automatically set to `600` (owner-read-only) every time they're saved, even if permissions were changed externally
- **Shared data directory**: Desktop app and browser both read from `~/.local/share/check-please/`, so your data is always consistent regardless of how you launch the app

### What's NOT Self-Healing (By Design)

- **Lost password + lost recovery key + no backup** = data is gone. This is intentional — if there were a backdoor, it wouldn't be secure
- **Deleted data files** = cannot be recovered without a backup. The app doesn't keep shadow copies
- **Corrupted encrypted backup** = cannot be restored. Keep multiple backups if your data is critical

### Recovery Priority (If You're Locked Out)

| Priority | Method | What You Need |
|----------|--------|--------------|
| 1 | Password | Your account password |
| 2 | Biometrics | Your registered phone nearby |
| 3 | Recovery key | The XXXX-XXXX-XXXX-XXXX from account creation |
| 4 | Encrypted backup | A `.cpbackup` file + the backup password |
| 5 | Emergency sheet | The printed paper with your recovery key |

---

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
