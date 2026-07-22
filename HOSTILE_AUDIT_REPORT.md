# check_please — Hostile Security Audit Report

**Date:** 2026-02-28 (original) · **Remediated:** 2026-07-22
**Auditor:** Kiro (automated hostile audit) + Cursor forensic pass
**Scope:** Full codebase — `agent_api.py`, `simple_web.py`, `credential_auditor/`, tests, config

---

## Executive Summary

**Overall Rating: LOW–MODERATE RISK** — Prior critical session/auth gaps are closed.
Vault data is now encrypted at rest (v2 AEAD-style construction). Remaining residual risk is
inherent to a localhost stdlib HTTP server (single global session, WebAuthn is convenience-only).

**Self-test:** 7/7 PASS
**Pytest:** see CI / local run
**No hardcoded secrets in project code.**
**No .env files tracked in git.**

---

## Remediation Status (2026-07-22)

| ID | Finding | Status | Notes |
|----|---------|--------|-------|
| C-1 | No session tokens | ✅ Fixed | HttpOnly `session=` cookie + `compare_digest` |
| C-2 | Vault endpoints unauthenticated | ✅ Fixed | All `/api/*` (except public set) require session |
| C-3 | Nuke without password | ✅ Fixed | Requires passkey verification |
| H-1 | PBKDF2-as-stream cipher | ✅ Fixed | v2: PBKDF2 → HMAC key split → SHAKE-256 XOR → HMAC tag; v1 decrypt retained |
| H-2 | 64-bit recovery key / unsalted hash | ✅ Fixed | 128-bit keys + PBKDF2-HMAC salt (200k) |
| H-3 | Agent API missing security headers | ✅ Fixed | nosniff / DENY / no-referrer / no-store |
| H-4 | No body size limits | ✅ Fixed | 10 MB cap + invalid Content-Length handling |
| M-1 | `agent_usage.log` not gitignored | ✅ Fixed | Also `.check_please_agent_token` |
| M-2 | No CSP | ✅ Fixed | CSP header on web UI |
| M-4 | 4-char password min | ✅ Fixed | Server + client enforce ≥ 8 (`_MIN_PASSKEY_LEN`) |
| L-3 | Bearer token in scrollback | ✅ Mitigated | `--quiet` writes token to chmod-600 file |

### Additional fixes from forensic pass

- **Deadlock:** `_UsageTracker.summary()` re-entered a non-reentrant `Lock` via `get_rpm()` — hung `GET /usage` and MCP usage reporting. Fixed with `_rpm_unlocked()`.
- **Vault at rest:** Passwords were stored as plaintext JSON. Now encrypted under the session passkey; legacy plaintext vaults migrate on unlock.
- **Logout:** Client-only logout left the server session valid. Added `POST /api/account/logout` + cookie clear.
- **`/stop`:** Was public — now requires a valid session.
- **Constant-time compares:** Recovery hash + bearer token use `hmac.compare_digest`.
- **Provider bail:** Mid-run skip of remaining keys after N consecutive auth failures (was post-hoc only).
- **Fingerprint hash redaction:** Hashes the full key, not prefix+suffix.

---

## Findings (original detail retained below for history)

### 🔴 CRITICAL (3) — remediated

#### C-1: Web UI has NO session tokens — global `_current_user` variable
**Status:** Fixed with session cookie. Residual: single global session (one concurrent browser).

#### C-2: Vault endpoints have zero authentication
**Status:** Fixed via `_check_session()` gate.

#### C-3: Account nuke endpoint has no password confirmation
**Status:** Fixed — requires passkey.

### 🟠 HIGH (4) — remediated

#### H-1: Stream cipher uses PBKDF2 with 1 iteration for keystream
**Status:** Replaced by v2 construction (SHAKE-256 keystream + domain-separated HMAC). v1 decrypt kept for migration.

#### H-2: Recovery key has only 32/64 bits of entropy
**Status:** 128-bit keys (`token_hex(4)` × 4) + salted PBKDF2 hash.

#### H-3: Agent API has zero security headers
**Status:** Fixed.

#### H-4: No request body size limits
**Status:** Fixed (10 MB).

### 🟡 MEDIUM / 🟢 LOW — see table above

---

## What's Working Well

| Area | Status | Notes |
|------|--------|-------|
| No hardcoded secrets | ✅ PASS | Zero real keys in codebase |
| .env not tracked in git | ✅ PASS | `.gitignore` covers `.env*` secrets |
| Key redaction (INV-4) | ✅ PASS | Only fingerprints in output |
| PBKDF2 key derivation | ✅ PASS | 200,000 iterations, SHA-256, 16-byte salt |
| HMAC integrity verification | ✅ PASS | `hmac.compare_digest()` |
| Vault encryption at rest | ✅ PASS | v2 envelope under session passkey |
| Agent API bearer token | ✅ PASS | `secrets.token_urlsafe(32)` |
| Localhost binding | ✅ PASS | Web + agent API |
| Credential scoping | ✅ PASS | max_uses / expires / rpm_limit |
| RPM rate limiting | ✅ PASS | Sliding window (no deadlock) |
| Brute force protection | ✅ PASS | Exponential backoff |
| File permissions | ✅ PASS | chmod 600 |
| Self-test suite | ✅ PASS | 7/7 invariants |

---

## Residual / Accepted Risk

1. **Single global session** — one concurrent authenticated browser; fine for localhost personal use.
2. **WebAuthn path is convenience-only** — credential ID check without attestation; does not unlock vault crypto without the passkey.
3. **Passkey held in process memory** while session is active — required to decrypt the vault; cleared on logout/nuke.
4. **Dependencies use range pins** (`>=x,<y`) — supply-chain residual (M-5); lockfile optional for production packaging.
