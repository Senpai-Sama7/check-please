"""Premium web interface — full SPA with credential audit + password vault."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac as _hmac
import io
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs

DIR = Path(__file__).resolve().parent
PORT = 8457
# Shared data dir — same location regardless of how app is launched
DATA_DIR = Path.home() / ".local" / "share" / "check-please"
DATA_DIR.mkdir(parents=True, exist_ok=True)
ACCOUNTS_DIR = DATA_DIR / ".accounts"
VAULTS_DIR = DATA_DIR / ".vaults"
_LEGACY_ACCOUNT = DATA_DIR / ".account.json"
_LEGACY_VAULT = DATA_DIR / ".vault.json"

_current_user: str = ""  # set on login
_session_token: str = ""  # set on login, validated on all /api/ requests
_session_passkey: str = ""  # vault encryption key held only while session is active
_failed_attempts: dict = {}  # {username: (count, last_fail_time)}
_MIN_PASSKEY_LEN = 8
_MAX_BODY_BYTES = 10_485_760  # 10 MB
_RECOVERY_GROUPS = 4
_RECOVERY_BYTES_PER_GROUP = 4  # 4×32 bits = 128-bit recovery keys
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _valid_env_key(key: str) -> bool:
    """Validate env var name to prevent injection (no newlines, no '=', reasonable length)."""
    if not key or len(key) > 128:
        return False
    if not _ENV_KEY_RE.fullmatch(key):
        return False
    # Forbid control chars and whitespace
    if any(ord(c) < 32 or c in "\n\r=" for c in key):
        return False
    return True


def _valid_username(username: str) -> bool:
    """Reject empty / path-traversing / oversized usernames."""
    if not username or not _USERNAME_RE.fullmatch(username):
        return False
    # Forbid reserved names and patterns that could be confusing
    if username in (".", ".."):
        return False
    if username.startswith("."):
        return False
    if ".." in username:
        return False
    # Must contain at least one alphanumeric to avoid names like "---" or "___"
    if not any(c.isalnum() for c in username):
        return False
    return True


def _safe_under(base: Path, candidate: Path) -> bool:
    """Return True if candidate resolves inside base (no traversal)."""
    try:
        base_r = base.resolve()
        cand_r = candidate.resolve()
        return cand_r == base_r or base_r in cand_r.parents
    except OSError:
        return False


def _acct_path(username: str) -> Path:
    ACCOUNTS_DIR.mkdir(exist_ok=True)
    path = ACCOUNTS_DIR / f"{username}.json"
    if not _safe_under(ACCOUNTS_DIR, path):
        raise ValueError("invalid username path")
    return path


def _vault_path(username: str | None = None) -> Path:
    VAULTS_DIR.mkdir(exist_ok=True)
    name = username or _current_user or "_default"
    path = VAULTS_DIR / f"{name}.json"
    if not _safe_under(VAULTS_DIR, path):
        raise ValueError("invalid vault path")
    return path

def _list_users() -> list[str]:
    ACCOUNTS_DIR.mkdir(exist_ok=True)
    return sorted(p.stem for p in ACCOUNTS_DIR.glob("*.json"))

def _migrate_legacy() -> None:
    """Migrate old single-file account/vault to multi-account dirs."""
    if _LEGACY_ACCOUNT.is_file():
        try:
            acct = json.loads(_LEGACY_ACCOUNT.read_text())
            name = acct.get("name", "user") or "user"
            dest = _acct_path(name)
            if not dest.is_file():
                dest.write_text(json.dumps(acct, indent=2))
                os.chmod(dest, 0o600)
            if _LEGACY_VAULT.is_file():
                vdest = _vault_path(name)
                if not vdest.is_file():
                    vdest.write_text(_LEGACY_VAULT.read_text())
                    os.chmod(vdest, 0o600)
                _LEGACY_VAULT.unlink()
            _LEGACY_ACCOUNT.unlink()
        except Exception:
            pass

# ── Vault helpers ──────────────────────────────────────────────────────────

VAULT_FILE = _LEGACY_VAULT  # kept for test compat

def _load_vault() -> list[dict]:
    """Load vault entries. Supports legacy plaintext list and v2 encrypted envelope."""
    vf = _vault_path()
    if not vf.is_file():
        return []
    try:
        raw = json.loads(vf.read_text())
    except Exception:
        return []
    if isinstance(raw, list):
        return raw  # legacy plaintext
    if isinstance(raw, dict) and "encrypted" in raw:
        if not _session_passkey:
            return []
        pt = _decrypt(raw["encrypted"], _session_passkey)
        if not pt:
            return []
        try:
            data = json.loads(pt)
            return data if isinstance(data, list) else []
        except Exception:
            return []
    return []

def _save_vault(entries: list[dict]) -> None:
    """Persist vault. Encrypts at rest when a session passkey is available."""
    vf = _vault_path()
    if _session_passkey:
        blob = _encrypt(json.dumps(entries, separators=(",", ":")), _session_passkey)
        vf.write_text(json.dumps({"v": 2, "encrypted": blob}, indent=2))
    else:
        # Security: never downgrade an encrypted vault to plaintext.
        # If file already exists and is encrypted, refuse to overwrite.
        if vf.is_file():
            try:
                existing = json.loads(vf.read_text())
                if isinstance(existing, dict) and "encrypted" in existing:
                    raise RuntimeError("Refusing to overwrite encrypted vault without session key")
            except RuntimeError:
                raise
            except Exception:
                pass
        # Fallback for migration/tests without an active session — still chmod 600
        vf.write_text(json.dumps(entries, indent=2))
    os.chmod(vf, 0o600)

def _vault_id() -> str:
    return secrets.token_hex(8)

def _pw_strength(pw: str) -> dict:
    length = len(pw)
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    score = sum([length >= 8, length >= 12, length >= 16, has_upper, has_lower, has_digit, has_special])
    labels = ["Very Weak", "Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]
    return {"score": score, "max": 7, "label": labels[min(score, 7)], "length": length}

# ── Account helpers (passkey-encrypted) ────────────────────────────────────

def _derive_key(passkey: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 200_000)

def _encrypt(data: str, passkey: str) -> dict:
    """Authenticated encryption (v2).

    Construction (stdlib-only, no third-party crypto deps):
      1. PBKDF2-HMAC-SHA256 (200k) → master key
      2. HMAC split into enc_key / mac_key (domain separation)
      3. SHAKE-256(enc_key || nonce) keystream XOR plaintext
      4. HMAC-SHA256(mac_key, nonce || ciphertext) integrity tag

    v1 (legacy PBKDF2-as-stream) remains decryptable for migration.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = _derive_key(passkey, salt)
    enc_key = _hmac.new(key, b"check_please:enc", "sha256").digest()
    mac_key = _hmac.new(key, b"check_please:mac", "sha256").digest()
    pt = data.encode()
    stream = hashlib.shake_256(enc_key + nonce).digest(len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, stream))
    mac = _hmac.new(mac_key, nonce + ct, "sha256").hexdigest()
    return {"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "mac": mac, "v": 2}

def _decrypt(blob: dict, passkey: str) -> str | None:
    try:
        salt = bytes.fromhex(blob["salt"])
        ct = bytes.fromhex(blob["ct"])
        key = _derive_key(passkey, salt)
        version = int(blob.get("v", 1))
        if version >= 2:
            nonce = bytes.fromhex(blob["nonce"])
            enc_key = _hmac.new(key, b"check_please:enc", "sha256").digest()
            mac_key = _hmac.new(key, b"check_please:mac", "sha256").digest()
            expected = _hmac.new(mac_key, nonce + ct, "sha256").hexdigest()
            if not _hmac.compare_digest(expected, blob.get("mac", "")):
                return None
            stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
            return bytes(a ^ b for a, b in zip(ct, stream)).decode()
        # v1 legacy: PBKDF2 keystream (kept for account/backup migration)
        if not _hmac.compare_digest(_hmac.new(key, ct, "sha256").hexdigest(), blob.get("mac", "")):
            return None
        stream = hashlib.pbkdf2_hmac("sha256", key, salt + b"stream", 1, dklen=len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream)).decode()
    except Exception:
        return None

def _make_recovery_key() -> str:
    """128-bit recovery key formatted as XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX."""
    return "-".join(
        secrets.token_hex(_RECOVERY_BYTES_PER_GROUP).upper()
        for _ in range(_RECOVERY_GROUPS)
    )


def _new_vault_key() -> str:
    """Random vault encryption key (independent of the user passkey)."""
    return secrets.token_urlsafe(32)


def _unwrap_vault_key(acct: dict, secret: str, field: str = "vault_key_wrap") -> str | None:
    blob = acct.get(field)
    if not isinstance(blob, dict):
        return None
    return _decrypt(blob, secret)


def _clear_session() -> None:
    global _current_user, _session_token, _session_passkey
    _current_user = ""
    _session_token = ""
    _session_passkey = ""

def _load_account(username: str | None = None) -> dict | None:
    name = username or _current_user
    if not name:
        return None
    p = _acct_path(name)
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None

def _save_account(data: dict, username: str | None = None) -> None:
    name = username or _current_user or data.get("name", "user")
    p = _acct_path(name)
    p.write_text(json.dumps(data, indent=2))
    os.chmod(p, 0o600)

def _check_rate_limit(username: str) -> float:
    """Return seconds to wait, or 0 if allowed."""
    info = _failed_attempts.get(username)
    if not info:
        return 0
    count, last = info
    delay = min(2 ** (count - 1), 30)  # 1s, 2s, 4s, 8s, 16s, 30s cap
    elapsed = time.time() - last
    return max(0, delay - elapsed)

def _record_fail(username: str):
    count = _failed_attempts.get(username, (0, 0))[0]
    _failed_attempts[username] = (count + 1, time.time())

def _clear_fails(username: str):
    _failed_attempts.pop(username, None)

def _verify_passkey(passkey: str, username: str | None = None) -> bool:
    acct = _load_account(username)
    if not acct:
        return False
    result = _decrypt(acct.get("check", {}), passkey)
    return result == "check_please_ok"

def _account_exists() -> bool:
    return len(_list_users()) > 0


# ── HTML: Full SPA ─────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Check Please</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Syncopate:wght@400;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --void:#050507;--glass:rgba(255,255,255,.03);--glass2:rgba(255,255,255,.06);--glass-border:rgba(255,255,255,.08);--glass-border2:rgba(255,255,255,.15);
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --accent:#4f46e5;--glow:#818cf8;--accent-bg:rgba(79,70,229,.12);--accent-border:rgba(79,70,229,.3);
  --green:#34d399;--green-bg:rgba(52,211,153,.1);--green-border:rgba(52,211,153,.2);
  --red:#f87171;--red-bg:rgba(248,113,113,.1);--red-border:rgba(248,113,113,.2);
  --amber:#fbbf24;--amber-bg:rgba(251,191,36,.1);--amber-border:rgba(251,191,36,.2);
  --font:'Outfit',system-ui,sans-serif;--font-display:'Syncopate',sans-serif;--font-mono:'SF Mono',SFMono-Regular,ui-monospace,monospace;
  --ease:cubic-bezier(.16,1,.3,1);
}
html{font-family:var(--font);background:var(--void);color:var(--text);-webkit-font-smoothing:antialiased;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent}
body{min-height:100vh;overflow-x:hidden;
  background-image:radial-gradient(circle at 15% 50%,rgba(79,70,229,.08),transparent 25%),radial-gradient(circle at 85% 30%,rgba(129,140,248,.08),transparent 25%);
  background-attachment:fixed;display:flex}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--void)}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:10px}

/* Spatial grid */
.spatial-grid{position:fixed;inset:0;background-image:linear-gradient(to right,rgba(255,255,255,.02) 1px,transparent 1px),linear-gradient(to bottom,rgba(255,255,255,.02) 1px,transparent 1px);background-size:50px 50px;mask-image:radial-gradient(ellipse at center,black 40%,transparent 80%);-webkit-mask-image:radial-gradient(ellipse at center,black 40%,transparent 80%);z-index:0;pointer-events:none}

/* Ambient glow */
#ambient-glow{position:fixed;width:600px;height:600px;background:radial-gradient(circle,rgba(129,140,248,.06) 0%,transparent 70%);border-radius:50%;transform:translate(-50%,-50%);pointer-events:none;z-index:0;transition:opacity .3s}

/* Sidebar */
.sidebar{width:260px;background:rgba(5,5,7,.8);backdrop-filter:blur(20px);border-right:1px solid var(--glass-border);display:flex;flex-direction:column;flex-shrink:0;position:relative;z-index:20}
.sidebar .brand{display:flex;align-items:center;gap:12px;padding:28px 22px 24px;font-family:var(--font-display);font-weight:700;font-size:.75rem;letter-spacing:.15em;text-transform:uppercase}
.sidebar .brand svg{width:32px;height:32px;flex-shrink:0}
.sidebar .brand span{background:linear-gradient(to right,#fff,var(--glow));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar nav{flex:1;padding:8px 12px;display:flex;flex-direction:column;gap:2px}
.sidebar nav a{display:flex;align-items:center;gap:12px;padding:11px 16px;border-radius:12px;color:var(--text2);text-decoration:none;font-size:.8125rem;font-weight:500;transition:all .3s var(--ease);cursor:pointer;border:1px solid transparent}
.sidebar nav a:hover{color:var(--text);background:var(--glass2)}
.sidebar nav a.active{color:var(--glow);background:var(--accent-bg);border-color:var(--accent-border)}
.sidebar nav a .icon{width:20px;text-align:center;font-size:1rem}
.sidebar nav a .badge{margin-left:auto;background:var(--accent);color:#fff;font-size:.6rem;font-weight:700;padding:2px 7px;border-radius:10px}
.sidebar .sep{height:1px;background:var(--glass-border);margin:8px 16px}
.sidebar .bottom{padding:16px;border-top:1px solid var(--glass-border)}
.sidebar .bottom .ver{color:var(--text3);font-size:.65rem;text-align:center;letter-spacing:.08em;text-transform:uppercase}

/* Main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative;z-index:10}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:20px 36px;border-bottom:1px solid var(--glass-border);background:rgba(5,5,7,.6);backdrop-filter:blur(20px);flex-shrink:0}
.topbar h1{font-family:var(--font-display);font-size:.85rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
.topbar .actions{display:flex;gap:8px}
.content{flex:1;overflow-y:auto;padding:32px 36px 60px}

/* Pages */
.page{display:none;animation:fadeUp .5s var(--ease)}.page.active{display:block}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

/* Panel (glassmorphism card) */
.panel{background:var(--glass);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid var(--glass-border);border-radius:24px;padding:28px;position:relative;overflow:hidden;transition:transform .4s var(--ease),border-color .4s}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);opacity:0;transition:opacity .4s}
.panel:hover{transform:translateY(-2px);border-color:var(--glass-border2)}
.panel:hover::before{opacity:1}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.panel-header h2{font-size:1rem;font-weight:700;letter-spacing:-.01em}
.panel-header .sub{color:var(--text2);font-size:.75rem;margin-top:3px}

/* Grid */
.grid{display:grid;gap:16px}
.cols-2{grid-template-columns:1fr 1fr}.cols-3{grid-template-columns:1fr 1fr 1fr}.cols-4{grid-template-columns:repeat(4,1fr)}
@media(max-width:900px){.cols-2,.cols-3,.cols-4{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.cols-2,.cols-3,.cols-4{grid-template-columns:1fr}}

/* Stat */
.stat{background:var(--glass);backdrop-filter:blur(24px);border:1px solid var(--glass-border);border-radius:16px;padding:22px;text-align:center;transition:all .4s var(--ease)}
.stat:hover{border-color:var(--glass-border2);transform:translateY(-2px)}
.stat .val{font-family:var(--font-display);font-size:1.75rem;font-weight:700;letter-spacing:.05em}
.stat .lbl{font-size:.65rem;font-weight:500;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-top:6px}
.stat.green .val{color:var(--green)}.stat.red .val{color:var(--red)}.stat.accent .val{color:var(--glow)}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:12px;border:1px solid var(--glass-border);background:var(--glass2);color:var(--text);font-size:.8125rem;font-weight:600;cursor:pointer;transition:all .3s var(--ease);font-family:var(--font);white-space:nowrap}
.btn:hover{background:rgba(255,255,255,.08);border-color:var(--glass-border2);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.primary{background:var(--glow);border-color:var(--glow);color:var(--void);box-shadow:0 0 20px rgba(129,140,248,.3)}
.btn.primary:hover{background:#fff;border-color:#fff;box-shadow:0 0 30px rgba(255,255,255,.4)}
.btn.danger{background:var(--red-bg);border-color:var(--red-border);color:var(--red)}
.btn.success{background:var(--green-bg);border-color:var(--green-border);color:var(--green)}
.btn.sm{padding:7px 14px;font-size:.75rem;border-radius:8px}
.btn:disabled{opacity:.3;cursor:not-allowed;pointer-events:none}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* Inputs */
input[type=text],input[type=password],input[type=url],input[type=email],input[type=search],select,textarea{
  width:100%;padding:12px 16px;background:transparent;border:none;border-bottom:1px solid var(--glass-border);
  color:var(--text);font-size:.875rem;font-family:var(--font);transition:all .3s;outline:none;border-radius:0}
input:focus,select:focus,textarea:focus{border-bottom-color:var(--glow)}
textarea{resize:vertical;min-height:80px;font-family:var(--font-mono);font-size:.8rem}
.input-group{display:flex;flex-direction:column;gap:6px}
.input-group label{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text3)}

/* Table */
.table-wrap{overflow-x:auto;border:1px solid var(--glass-border);border-radius:16px;background:var(--glass)}
table{width:100%;border-collapse:collapse;font-size:.8125rem}
th{background:rgba(5,5,7,.5);font-weight:600;text-transform:uppercase;font-size:.65rem;letter-spacing:.08em;color:var(--text3);padding:14px 18px;text-align:left;border-bottom:1px solid var(--glass-border)}
td{padding:14px 18px;border-bottom:1px solid var(--glass-border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(129,140,248,.04)}

/* Badges */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge.green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.badge.red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.badge.amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
.badge.accent{background:var(--accent-bg);color:var(--glow);border:1px solid var(--accent-border)}

/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(8px);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:rgba(15,15,20,.95);backdrop-filter:blur(24px);border:1px solid var(--glass-border);border-radius:24px;padding:32px;width:90%;max-width:520px;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.5);animation:modalIn .3s var(--ease)}
@keyframes modalIn{from{opacity:0;transform:scale(.95) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal h2{font-size:1.1rem;font-weight:700;margin-bottom:20px}
.modal .form-grid{display:flex;flex-direction:column;gap:16px}
.modal .form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:24px;padding-top:20px;border-top:1px solid var(--glass-border)}

/* Password strength */
.pw-meter{height:3px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden;margin-top:8px}
.pw-meter .fill{height:100%;border-radius:2px;transition:width .3s,background .3s}
.pw-label{font-size:.65rem;font-weight:600;margin-top:4px;letter-spacing:.04em}

/* Key result cards */
.kc{display:flex;align-items:center;gap:14px;padding:16px 20px;background:var(--glass);border:1px solid var(--glass-border);border-radius:16px;border-left:3px solid var(--glass-border);transition:all .3s var(--ease);margin-bottom:8px}
.kc:hover{border-color:var(--glass-border2);transform:translateY(-1px)}
.kc.v-valid{border-left-color:var(--green)}.kc.v-auth_failed,.kc.v-suspended_account{border-left-color:var(--red)}
.kc.v-network_error,.kc.v-quota_exhausted,.kc.v-insufficient_scope,.kc.v-invalid_format{border-left-color:var(--amber)}
.kc .ki{font-size:1.1rem;flex-shrink:0;width:24px;text-align:center}
.kc .km{flex:1;min-width:0}.kc .kp{font-weight:600;font-size:.875rem}.kc .ke{color:var(--text2);font-size:.7rem;margin-top:2px;font-family:var(--font-mono)}
.kc .ks{font-size:.65rem;font-weight:600;padding:3px 10px;border-radius:20px;flex-shrink:0;text-transform:uppercase;letter-spacing:.04em}
.ks.t-valid{background:var(--green-bg);color:var(--green)}.ks.t-auth_failed,.ks.t-suspended_account{background:var(--red-bg);color:var(--red)}
.ks.t-network_error,.ks.t-quota_exhausted,.ks.t-insufficient_scope,.ks.t-invalid_format{background:var(--amber-bg);color:var(--amber)}

/* Loader */
.loader{display:none;padding:40px;text-align:center}
.loader.on{display:block}
.spinner{width:32px;height:32px;border:2px solid rgba(255,255,255,.1);border-top-color:var(--glow);border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 14px}
@keyframes spin{to{transform:rotate(360deg)}}
.loader .msg{color:var(--text2);font-size:.8rem}

/* Toast */
.toast-container{position:fixed;top:24px;right:24px;z-index:200;display:flex;flex-direction:column;gap:8px}
.toast{padding:14px 22px;border-radius:16px;font-size:.8125rem;font-weight:500;box-shadow:0 8px 30px rgba(0,0,0,.4);animation:toastIn .4s var(--ease);max-width:360px;backdrop-filter:blur(20px)}
.toast.success{background:rgba(6,95,70,.9);color:var(--green);border:1px solid var(--green-border)}
.toast.error{background:rgba(127,29,29,.9);color:var(--red);border:1px solid var(--red-border)}
.toast.info{background:rgba(30,58,95,.9);color:var(--glow);border:1px solid var(--accent-border)}
@keyframes toastIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}

/* Drop zone */
.drop-zone{border:2px dashed var(--glass-border);border-radius:16px;padding:40px;text-align:center;transition:all .3s var(--ease);cursor:pointer}
.drop-zone:hover,.drop-zone.dragover{border-color:var(--glow);background:var(--accent-bg)}
.drop-zone .dz-icon{font-size:2rem;margin-bottom:12px;opacity:.6}
.drop-zone h3{font-size:.9rem;font-weight:600;margin-bottom:4px}
.drop-zone p{font-size:.75rem;color:var(--text3)}

/* Lock screen */
.lock-screen{position:fixed;inset:0;background:var(--void);z-index:300;display:flex;align-items:center;justify-content:center;
  background-image:radial-gradient(circle at 50% 40%,rgba(79,70,229,.1),transparent 50%)}
.lock-screen.hidden{display:none}
.lock-box{text-align:center;width:380px;padding:40px}
.lock-box svg{width:56px;height:56px;margin-bottom:24px}
.lock-box h1{font-family:var(--font-display);font-size:1rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;margin-bottom:8px}
.lock-box h1 span{background:linear-gradient(to right,#fff,var(--glow));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.lock-box p{color:var(--text2);font-size:.8125rem;margin-bottom:28px;line-height:1.6}
.lock-box .input-group{text-align:left;margin-bottom:14px}
.lock-box .lock-err{color:var(--red);font-size:.75rem;margin-bottom:12px;min-height:1.2em}

/* Onboarding */
.onboard-overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);backdrop-filter:blur(8px);z-index:250;display:flex;align-items:center;justify-content:center}
.onboard-overlay.hidden{display:none}
.onboard-card{background:rgba(15,15,20,.95);backdrop-filter:blur(24px);border:1px solid var(--glass-border);border-radius:24px;padding:40px;width:90%;max-width:520px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5);animation:modalIn .3s var(--ease)}
.onboard-card h2{font-size:1.2rem;font-weight:700;margin-bottom:8px}
.onboard-card p{color:var(--text2);font-size:.875rem;line-height:1.6;margin-bottom:28px;max-width:400px;margin-left:auto;margin-right:auto}
.onboard-card .step-icon{font-size:2.5rem;margin-bottom:16px}
.onboard-dots{display:flex;gap:6px;justify-content:center;margin-bottom:24px}
.onboard-dots .dot{width:6px;height:6px;border-radius:50%;background:rgba(255,255,255,.15);transition:all .3s var(--ease)}
.onboard-dots .dot.active{background:var(--glow);width:24px;border-radius:3px}
.onboard-actions{display:flex;gap:10px;justify-content:center}

/* Search */
.search-bar{position:relative}
.search-bar input{padding-left:36px}
.search-bar .si{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:.85rem;pointer-events:none}

/* Empty */
.empty{text-align:center;padding:48px 20px;color:var(--text2)}
.empty .icon{font-size:2.5rem;margin-bottom:12px;opacity:.4}
.empty h3{font-size:.9rem;font-weight:600;color:var(--text);margin-bottom:6px}
.empty p{font-size:.8rem;max-width:320px;margin:0 auto;line-height:1.5}

/* Pre */
.pre{background:rgba(0,0,0,.3);border:1px solid var(--glass-border);border-radius:12px;padding:18px;font-family:var(--font-mono);font-size:.75rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;line-height:1.7;color:var(--text2)}

@media(max-width:768px){.sidebar{display:none}.content{padding:20px 16px}}
</style>
</head>
<body>
<div id="ambient-glow"></div>
<div class="spatial-grid"></div>

<!-- Lock Screen -->
<div class="lock-screen" id="lock-screen">
  <div class="lock-box">
    <svg viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="url(#lg)"/><path d="M18 28l7 7 13-13" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#818cf8"/></linearGradient></defs></svg>
    <h1><span>Check Please</span></h1>
    <div id="lock-setup">
      <p>Create a password to protect your vault. Everything is encrypted locally on this device.</p>
      <div class="input-group"><label>Username</label><input type="text" id="setup-name" placeholder="Choose a username"></div>
      <div class="input-group"><label>Create Password</label><input type="password" id="setup-pass" placeholder="Choose a strong password"></div>
      <div class="input-group"><label>Confirm Password</label><input type="password" id="setup-pass2" placeholder="Confirm password"></div>
      <div class="lock-err" id="setup-err"></div>
      <button class="btn primary" onclick="createAccount()" style="width:100%">Create Account</button>
      <div style="margin-top:16px;text-align:center"><a href="#" onclick="showLogin();return false" id="lock-switch-login" style="color:var(--text3);font-size:.8125rem;text-decoration:none;transition:color .2s" onmouseover="this.style.color='var(--glow)'" onmouseout="this.style.color='var(--text3)'">Already have an account? <span style="color:var(--glow)">Sign in</span></a></div>
    </div>
    <div id="lock-login" style="display:none">
      <p id="lock-greeting">Sign in to your vault.</p>
      <div id="account-picker" style="margin-bottom:14px">
        <div class="input-group"><label>Username</label><input type="text" id="login-user-input" placeholder="Enter username" autocomplete="username"></div>
      </div>
      <div class="input-group"><label>Password</label><input type="password" id="login-pass" placeholder="Enter password" onkeydown="if(event.key==='Enter')unlock()"></div>
      <div class="lock-err" id="login-err"></div>
      <button class="btn primary" onclick="unlock()" style="width:100%;margin-bottom:8px">Unlock</button>
      <button class="btn" onclick="biometricAuth()" id="bio-login-btn" style="width:100%;display:none">🔒 Unlock with Biometrics</button>
      <div style="margin-top:16px;display:flex;justify-content:space-between;align-items:center"><a href="#" onclick="showForgot();return false" style="color:var(--text3);font-size:.75rem;text-decoration:none;transition:color .2s" onmouseover="this.style.color='var(--glow)'" onmouseout="this.style.color='var(--text3)'">Forgot password?</a><a href="#" onclick="showSetup();return false" style="color:var(--text3);font-size:.8125rem;text-decoration:none;transition:color .2s" onmouseover="this.style.color='var(--glow)'" onmouseout="this.style.color='var(--text3)'">Create new account <span style="color:var(--glow)">→</span></a></div>
    </div>
    <!-- Forgot password -->
    <div id="lock-forgot" style="display:none">
      <p style="margin-bottom:16px">Enter your recovery key to reset your password. This is the key shown when you created your account.</p>
      <div class="input-group"><label>Recovery Key</label><input type="text" id="forgot-key" placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX" style="font-family:var(--font-mono);letter-spacing:.05em"></div>
      <div class="input-group" style="margin-top:10px"><label>New Password</label><input type="password" id="forgot-new-pass" placeholder="Choose a new password"></div>
      <div class="lock-err" id="forgot-err"></div>
      <button class="btn primary" onclick="recoverAccount()" style="width:100%;margin-bottom:8px">Reset Password</button>
      <button class="btn danger" onclick="if(confirm('This will DELETE all vault data and reset your account. This cannot be undone.'))nukeAccount()" style="width:100%;margin-bottom:8px">🗑️ Erase Everything &amp; Start Over</button>
      <button class="btn" onclick="biometricAuth()" id="bio-forgot-btn" style="width:100%;display:none">🔒 Unlock with Biometrics Instead</button>
      <div style="margin-top:8px"><a href="#" onclick="hideForgot();return false" style="color:var(--text3);font-size:.75rem;text-decoration:none">← Back to login</a></div>
    </div>
  </div>
</div>

<!-- Recovery Key Display -->
<div class="modal-overlay" id="modal-recovery" style="z-index:280">
  <div class="modal" style="text-align:center">
    <div style="font-size:2rem;margin-bottom:12px">🔑</div>
    <h2>Save Your Recovery Key</h2>
    <p style="color:var(--text2);font-size:.8125rem;line-height:1.6;margin-bottom:20px">If you forget your password, this key is the only way to recover your account. Save it somewhere safe — it won't be shown again.</p>
    <div style="background:var(--void);border:1px solid var(--glass-border);border-radius:12px;padding:18px;font-family:var(--font-mono);font-size:1.1rem;letter-spacing:.08em;font-weight:700;color:var(--glow);margin-bottom:16px;user-select:all" id="recovery-key-display">—</div>
    <div class="btn-group" style="justify-content:center;margin-bottom:16px">
      <button class="btn" onclick="copyText(E('recovery-key-display').textContent)">📋 Copy</button>
    </div>
    <button class="btn primary" onclick="E('modal-recovery').style.display='none';startTour()" style="width:100%">I've Saved It — Continue</button>
  </div>
</div>

<!-- Onboarding -->
<div class="onboard-overlay hidden" id="onboard">
  <div class="onboard-card">
    <div class="step-icon" id="ob-icon">👋</div>
    <h2 id="ob-title">Welcome</h2>
    <p id="ob-desc">Loading…</p>
    <div class="onboard-dots" id="ob-dots"></div>
    <div class="onboard-actions">
      <button class="btn" onclick="skipTour()">Skip Tour</button>
      <button class="btn primary" onclick="nextStep()" id="ob-next">Get Started →</button>
    </div>
  </div>
</div>

<div class="toast-container" id="toasts"></div>

<!-- Sidebar -->
<div class="sidebar">
  <div class="brand">
    <svg viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="url(#sg)"/><path d="M9 16l5 5 9-9" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="sg" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#4f46e5"/><stop offset="1" stop-color="#818cf8"/></linearGradient></defs></svg>
    <span>Check Please</span>
  </div>
  <nav>
    <a onclick="go('dashboard')" data-page="dashboard" class="active"><span class="icon">📊</span> Dashboard</a>
    <a onclick="go('audit')" data-page="audit"><span class="icon">🔍</span> Credential Audit</a>
    <a onclick="go('vault')" data-page="vault"><span class="icon">🔐</span> Password Vault <span class="badge" id="vault-count">0</span></a>
    <div class="sep"></div>
    <a onclick="go('providers')" data-page="providers"><span class="icon">🌐</span> Providers</a>
    <a onclick="go('settings')" data-page="settings"><span class="icon">⚙️</span> Settings</a>
  </nav>
  <div class="bottom"><a onclick="logout()" style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-radius:10px;color:var(--text3);font-size:.8125rem;cursor:pointer;text-decoration:none;transition:all .2s" onmouseover="this.style.color='var(--red)';this.style.background='var(--red-bg)'" onmouseout="this.style.color='var(--text3)';this.style.background='none'"><span class="icon">🚪</span> Log Out</a><div class="ver" style="margin-top:8px">v1.1.1 · Local Only · Encrypted</div></div>
</div>

<!-- Main -->
<div class="main">
<div class="topbar">
  <h1 id="page-title">Dashboard</h1>
  <div class="actions">
    <button class="btn sm" onclick="go('vault');openAddModal()">+ Add Password</button>
    <button class="btn primary sm" onclick="go('audit');runAudit()">Run Audit</button>
  </div>
</div>
<div class="content">

<!-- Dashboard -->
<div class="page active" id="page-dashboard">
  <div class="grid cols-4" style="margin-bottom:20px">
    <div class="stat accent"><div class="val" id="d-total">—</div><div class="lbl">Total Keys</div></div>
    <div class="stat green"><div class="val" id="d-valid">—</div><div class="lbl">Valid</div></div>
    <div class="stat red"><div class="val" id="d-failed">—</div><div class="lbl">Failed</div></div>
    <div class="stat"><div class="val" id="d-vault">0</div><div class="lbl">Vault Items</div></div>
  </div>
  <div class="grid cols-2">
    <div class="panel">
      <div class="panel-header"><h2>Quick Actions</h2></div>
      <div class="btn-group">
        <button class="btn primary" onclick="go('audit');runAudit()">🔍 Run Audit</button>
        <button class="btn" onclick="go('audit');runPreview()">📋 Dry Run</button>
        <button class="btn" onclick="go('audit');runSelfTest()">✅ Self-Test</button>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>Password Vault</h2></div>
      <div class="btn-group">
        <button class="btn primary" onclick="go('vault');openAddModal()">🔐 Add Password</button>
        <button class="btn" onclick="go('vault');importCSV()">📥 Import CSV</button>
        <button class="btn" onclick="exportCSV()">📤 Export</button>
      </div>
    </div>
  </div>
  <!-- .env upload zone -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-header"><div><h2>Load Credentials</h2><div class="sub">Upload a .env file, drag &amp; drop, or scan your shell environment</div></div></div>
    <div class="grid cols-2" style="gap:12px">
      <div class="drop-zone" id="drop-zone" onclick="E('env-file').click()">
        <div class="dz-icon">📄</div>
        <h3>Upload or Drop .env File</h3>
        <p>Drag &amp; drop your .env here, or click to browse</p>
      </div>
      <div class="drop-zone" onclick="scanEnv()" style="cursor:pointer">
        <div class="dz-icon">🔎</div>
        <h3>Scan Shell Environment</h3>
        <p>Detect API keys in ~/.bashrc, ~/.zshrc, ~/.profile</p>
      </div>
    </div>
    <input type="file" id="env-file" accept=".env,.txt" style="display:none" onchange="handleEnvUpload(this)">
    <div id="env-scan-results" style="margin-top:12px"></div>
  </div>
  <div class="panel" style="margin-top:16px">
    <div class="panel-header"><h2>Recent Audit Results</h2></div>
    <div id="dash-results"><div class="empty"><div class="icon">🔍</div><h3>No audit run yet</h3><p>Upload a .env file above or run an audit to validate your credentials.</p></div></div>
  </div>
</div>

<!-- Audit -->
<div class="page" id="page-audit">
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-header">
      <div><h2>Credential Audit</h2><div class="sub">Validate API keys against live provider endpoints</div></div>
      <div class="btn-group">
        <button class="btn primary" onclick="runAudit()">🔍 Run Audit</button>
        <button class="btn" onclick="runPreview()">📋 Dry Run</button>
        <button class="btn" onclick="runSelfTest()">✅ Self-Test</button>
      </div>
    </div>
    <div class="loader" id="audit-loader"><div class="spinner"></div><div class="msg" id="audit-msg">Validating credentials…</div></div>
    <div id="audit-stats" style="display:none">
      <div class="grid cols-4" style="margin-bottom:16px">
        <div class="stat accent"><div class="val" id="s-total">0</div><div class="lbl">Total</div></div>
        <div class="stat green"><div class="val" id="s-valid">0</div><div class="lbl">Valid</div></div>
        <div class="stat red"><div class="val" id="s-failed">0</div><div class="lbl">Failed</div></div>
        <div class="stat"><div class="val" id="s-providers">0</div><div class="lbl">Providers</div></div>
      </div>
    </div>
    <div id="audit-toolbar" style="display:none;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <select id="audit-sort" onchange="renderAuditResults()" style="background:var(--glass);color:var(--text);border:1px solid var(--glass-border);border-radius:8px;padding:6px 12px;font-size:.75rem;font-family:var(--font)">
          <option value="default">Sort: Default</option><option value="status">Sort: Status</option><option value="provider">Sort: Provider</option>
        </select>
        <select id="audit-filter" onchange="renderAuditResults()" style="background:var(--glass);color:var(--text);border:1px solid var(--glass-border);border-radius:8px;padding:6px 12px;font-size:.75rem;font-family:var(--font)">
          <option value="all">Show: All</option><option value="valid">✓ Valid Only</option><option value="failed">✗ Failed Only</option><option value="other">⚠ Warnings</option>
        </select>
        <label style="display:flex;align-items:center;gap:6px;font-size:.75rem;color:var(--text2);cursor:pointer;margin-left:auto"><input type="checkbox" id="audit-check-all" onchange="toggleAllAudit(this.checked)"> Select All</label>
        <button class="btn primary sm" onclick="openBuildEnv()" id="btn-build-env" style="display:none">📦 Build .env</button>
        <button class="btn danger sm" onclick="deleteSelected()" id="btn-del-selected" style="display:none">🗑️ Remove Selected</button>
      </div>
    </div>
    <div id="audit-results"></div>
  </div>
  <div class="panel" id="audit-output-card" style="display:none">
    <div class="panel-header"><h2>Raw Output</h2></div>
    <div class="pre" id="audit-output"></div>
  </div>
</div>

<!-- Vault -->
<div class="page" id="page-vault">
  <div class="panel">
    <div class="panel-header">
      <div><h2>Password Vault</h2><div class="sub">Encrypted local storage</div></div>
      <div class="btn-group">
        <button class="btn primary" onclick="openAddModal()">+ Add Entry</button>
        <button class="btn" onclick="importCSV()">📥 Import CSV</button>
        <button class="btn" onclick="exportCSV()">📤 Export</button>
        <button class="btn" onclick="openGenModal()">🎲 Generator</button>
      </div>
    </div>
    <div style="margin:16px 0"><div class="search-bar"><span class="si">🔍</span><input type="search" id="vault-search" placeholder="Search vault…" oninput="renderVault()"></div></div>
    <div id="vault-list"></div>
  </div>
</div>

<!-- Providers -->
<div class="page" id="page-providers">
  <div class="panel">
    <div class="panel-header"><div><h2>Supported Providers</h2><div class="sub">16 services with live API validation</div></div></div>
    <div class="loader" id="prov-loader"><div class="spinner"></div><div class="msg">Loading…</div></div>
    <div id="prov-list"></div>
  </div>
</div>

<!-- Settings -->
<div class="page" id="page-settings">
  <div class="grid cols-2">
    <div class="panel">
      <div class="panel-header"><h2>Account</h2></div>
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="input-group"><label>Username</label><input type="text" id="set-name" readonly></div>
        <div class="input-group"><label>Account Created</label><input type="text" id="set-created" readonly></div>
        <div class="input-group"><label>Change Password</label>
          <input type="password" id="set-old-pass" placeholder="Current password">
          <input type="password" id="set-new-pass" placeholder="New password">
        </div>
        <button class="btn primary" onclick="changePasskey()">🔑 Update Password</button>
        <div style="border-top:1px solid var(--glass-border);padding-top:14px;margin-top:4px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div><div style="font-weight:600;font-size:.875rem">Biometric Unlock</div><div style="color:var(--text3);font-size:.7rem;margin-top:2px" id="bio-status">Not set up</div></div>
            <span class="badge accent" id="bio-badge" style="display:none">Active</span>
          </div>
          <p style="color:var(--text2);font-size:.75rem;line-height:1.5;margin-bottom:10px">Use Face ID, Touch ID, fingerprint, or Windows Hello to unlock.</p>
          <div id="bio-unsupported" style="display:none;color:var(--amber);font-size:.75rem;padding:10px 14px;background:var(--amber-bg);border:1px solid var(--amber-border);border-radius:8px;margin-bottom:10px">⚠️ Biometrics require a browser. Open <a href="http://localhost:8457" style="color:var(--glow);font-family:var(--font-mono);user-select:all" onclick="copyText('http://localhost:8457');return false">http://localhost:8457</a> in Chrome/Edge/Firefox. <span style="color:var(--text3)">(click to copy)</span></div>
          <div class="btn-group">
            <button class="btn success" onclick="registerBiometric()" id="bio-setup-btn">🔒 Set Up Biometrics</button>
            <button class="btn danger sm" onclick="removeBiometric()" id="bio-remove-btn" style="display:none">Remove</button>
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>Application</h2></div>
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="input-group"><label>.env File</label><input type="text" value=".env (auto-detected)" readonly></div>
        <div class="input-group"><label>Vault Storage</label><input type="text" value=".vault.json (chmod 600)" readonly></div>
        <div class="input-group"><label>Server</label><input type="text" value="localhost:8457 (local only)" readonly></div>
        <div class="btn-group">
          <button class="btn danger" onclick="if(confirm('Clear all vault entries?'))clearVault()">🗑️ Clear Vault</button>
          <button class="btn danger" onclick="if(confirm('Stop server?'))location='/stop'">⏹ Stop</button>
        </div>
      </div>
    </div>
    <div class="panel" style="grid-column:1/-1">
      <div class="panel-header"><h2>Backup &amp; Recovery</h2></div>
      <p style="color:var(--text2);font-size:.8125rem;line-height:1.6;margin-bottom:14px">Export an encrypted backup of your vault and account. If you ever lose access, import the backup with your password to restore everything.</p>
      <div class="btn-group">
        <button class="btn primary" onclick="exportBackup()">📦 Export Encrypted Backup</button>
        <button class="btn" onclick="E('backup-file').click()">📥 Import Backup</button>
        <button class="btn" onclick="printEmergencySheet()">🖨️ Print Emergency Sheet</button>
      </div>
      <input type="file" id="backup-file" accept=".cpbackup" style="display:none" onchange="importBackup(this)">
      <div id="backup-status" style="color:var(--text3);font-size:.75rem;margin-top:10px"></div>
    </div>
    <div class="panel" style="grid-column:1/-1">
      <div class="panel-header"><h2>Help</h2></div>
      <div class="btn-group">
        <button class="btn" onclick="startTour()">🎓 Replay App Tour</button>
        <button class="btn" onclick="go('providers')">🌐 View Providers</button>
      </div>
      <div style="color:var(--text3);font-size:.75rem;line-height:1.6;margin-top:14px">
        <strong style="color:var(--text2)">Keyboard shortcuts:</strong> Escape — close dialogs · All data stored locally — nothing leaves your machine.
      </div>
    </div>
  </div>
</div>

</div></div>

<!-- Add/Edit Modal -->
<div class="modal-overlay" id="modal-add" onclick="if(event.target===this)closeModals()">
  <div class="modal">
    <h2 id="modal-add-title">Add Password</h2>
    <div class="form-grid">
      <div class="input-group"><label>Site / Service</label><input type="text" id="v-site" placeholder="e.g. github.com"></div>
      <div class="input-group"><label>Username / Email</label><input type="text" id="v-user" placeholder="e.g. user@example.com"></div>
      <div class="input-group"><label>Password</label>
        <div style="display:flex;gap:8px"><input type="password" id="v-pass" placeholder="Enter password" oninput="updateStrength()"><button class="btn sm" onclick="togglePw('v-pass')" type="button">👁</button><button class="btn sm" onclick="fillGenerated()" type="button">🎲</button></div>
        <div class="pw-meter"><div class="fill" id="pw-fill"></div></div>
        <div class="pw-label" id="pw-label"></div>
      </div>
      <div class="input-group"><label>Notes</label><textarea id="v-notes" placeholder="Optional notes…" rows="2"></textarea></div>
    </div>
    <input type="hidden" id="v-edit-id">
    <div class="form-actions"><button class="btn" onclick="closeModals()">Cancel</button><button class="btn primary" onclick="saveEntry()">Save</button></div>
  </div>
</div>

<!-- Generator Modal -->
<div class="modal-overlay" id="modal-gen" onclick="if(event.target===this)closeModals()">
  <div class="modal">
    <h2>Password Generator</h2>
    <div class="form-grid">
      <div class="input-group"><label>Site / App</label><input type="text" id="gen-site" placeholder="e.g. github.com (optional)"></div>
      <div class="input-group"><label>Username / Email</label><input type="text" id="gen-user" placeholder="e.g. user@example.com (optional)"></div>
      <div class="input-group"><label>Length</label><input type="text" id="gen-len" value="20"></div>
      <div style="display:flex;gap:16px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:6px;font-size:.8rem;cursor:pointer;color:var(--text2)"><input type="checkbox" id="gen-upper" checked> Uppercase</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8rem;cursor:pointer;color:var(--text2)"><input type="checkbox" id="gen-lower" checked> Lowercase</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8rem;cursor:pointer;color:var(--text2)"><input type="checkbox" id="gen-digits" checked> Digits</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8rem;cursor:pointer;color:var(--text2)"><input type="checkbox" id="gen-symbols" checked> Symbols</label>
      </div>
      <div class="input-group"><label>Generated Password</label><div style="display:flex;gap:8px"><input type="text" id="gen-result" readonly style="font-family:var(--font-mono)"><button class="btn sm" onclick="copyText(E('gen-result').value)">📋</button></div></div>
      <div class="btn-group">
        <button class="btn primary" onclick="generatePw()">🎲 Generate</button>
        <button class="btn success" onclick="saveGenerated()">💾 Save to Vault</button>
      </div>
    </div>
    <div class="form-actions"><button class="btn" onclick="closeModals()">Close</button></div>
  </div>
</div>

<!-- Build .env Modal -->
<div class="modal-overlay" id="modal-build-env" onclick="if(event.target===this)closeModals()">
  <div class="modal" style="max-width:600px">
    <h2>Build Custom .env</h2>
    <p style="color:var(--text2);font-size:.8125rem;margin-bottom:16px">Select credentials to include. They'll be organized by provider with clean formatting.</p>
    <div id="build-env-list" style="max-height:340px;overflow-y:auto;margin-bottom:16px"></div>
    <div style="background:var(--void);border:1px solid var(--glass-border);border-radius:12px;padding:14px;font-family:var(--font-mono);font-size:.7rem;max-height:180px;overflow-y:auto;white-space:pre;color:var(--text2);margin-bottom:16px;display:none" id="build-env-preview"></div>
    <div class="form-actions">
      <button class="btn" onclick="previewBuildEnv()">👁️ Preview</button>
      <button class="btn" onclick="closeModals()">Cancel</button>
      <button class="btn primary" onclick="downloadBuildEnv()">⬇️ Download .env</button>
      <button class="btn success" onclick="saveBuildEnv()">💾 Save as .env</button>
    </div>
  </div>
</div>

<!-- Scan Results Modal -->
<div class="modal-overlay" id="modal-scan" onclick="if(event.target===this)closeModals()">
  <div class="modal">
    <h2>Shell Environment Scan</h2>
    <p style="color:var(--text2);font-size:.8125rem;margin-bottom:16px" id="scan-summary">Scanning…</p>
    <div id="scan-list" style="max-height:300px;overflow-y:auto"></div>
    <div class="form-actions"><button class="btn" onclick="closeModals()">Cancel</button><button class="btn primary" onclick="importScanned()">Import Selected</button></div>
  </div>
</div>

<input type="file" id="csv-file" accept=".csv" style="display:none" onchange="handleCSVImport(this)">

<script>
const E=id=>document.getElementById(id);
const SI={valid:{i:'✓',l:'Valid'},auth_failed:{i:'✗',l:'Failed'},network_error:{i:'!',l:'Net Error'},quota_exhausted:{i:'!',l:'Quota'},suspended_account:{i:'✗',l:'Suspended'},insufficient_scope:{i:'!',l:'Limited'},invalid_format:{i:'?',l:'Bad Format'}};

// ── Ambient glow ──
const glow=E('ambient-glow');let mx=innerWidth/2,my=innerHeight/2,cx=mx,cy=my;
document.addEventListener('mousemove',e=>{mx=e.clientX;my=e.clientY});
(function anim(){cx+=(mx-cx)*.08;cy+=(my-cy)*.08;if(glow){glow.style.left=cx+'px';glow.style.top=cy+'px';}requestAnimationFrame(anim)})();

// ── Nav ──
function go(page){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a=>a.classList.remove('active'));
  const el=E('page-'+page);if(el)el.classList.add('active');
  const nav=document.querySelector(`[data-page="${page}"]`);if(nav)nav.classList.add('active');
  const titles={dashboard:'DASHBOARD',audit:'CREDENTIAL AUDIT',vault:'PASSWORD VAULT',providers:'PROVIDERS',settings:'SETTINGS'};
  E('page-title').textContent=titles[page]||page;
  if(page==='vault')renderVault();
  if(page==='providers'&&!E('prov-list').innerHTML)loadProviders();
}

// ── Toast ──
function toast(msg,type='info'){const d=document.createElement('div');d.className='toast '+type;d.textContent=msg;E('toasts').appendChild(d);setTimeout(()=>d.remove(),4000);}

// ── API ──
async function api(path,opts={}){try{const r=await fetch(path,opts);const ct=r.headers.get('content-type')||'';if(ct.includes('json'))return await r.json();return{output:await r.text()};}catch(e){return{error:e.message};}}
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
function escAttr(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// ── Loader ──
function setLoading(id,on,msg){const l=E(id);if(l){l.classList.toggle('on',on);if(msg){const m=l.querySelector('.msg');if(m)m.textContent=msg;}}}

// ── Audit ──
let auditData=[];
const FAIL_STATUSES=['auth_failed','suspended_account'];
const WARN_STATUSES=['network_error','quota_exhausted','insufficient_scope','invalid_format'];
function renderAuditResults(){
  const sort=E('audit-sort').value,filter=E('audit-filter').value;
  let items=[...auditData];
  if(filter==='valid')items=items.filter(k=>k.status==='valid');
  else if(filter==='failed')items=items.filter(k=>FAIL_STATUSES.includes(k.status));
  else if(filter==='other')items=items.filter(k=>WARN_STATUSES.includes(k.status));
  if(sort==='status')items.sort((a,b)=>(a.status==='valid'?0:1)-(b.status==='valid'?0:1)||a.provider.localeCompare(b.provider));
  else if(sort==='provider')items.sort((a,b)=>a.provider.localeCompare(b.provider));
  let h='';for(const k of items){const st=SI[k.status]?k.status:'network_error';const si=SI[st]||{i:'?',l:st};const fp=k.key_fingerprint||{};const fs=fp.prefix?esc(fp.prefix)+'…'+esc(fp.suffix)+' ('+esc(fp.length)+')':esc(fp.redacted||'');
    h+='<div class="kc v-'+escAttr(st)+'"><label style="display:flex;align-items:center;flex-shrink:0;cursor:pointer"><input type="checkbox" class="audit-cb" data-var="'+escAttr(k.env_var)+'" onchange="updateAuditActions()"></label><span class="ki">'+si.i+'</span><div class="km"><div class="kp">'+esc(k.provider)+'</div><div class="ke">'+esc(k.env_var)+' · '+fs+'</div></div><span class="ks t-'+escAttr(st)+'">'+esc(si.l)+'</span></div>';}
  E('audit-results').innerHTML=h||'<div class="empty"><div class="icon">✅</div><h3>No keys found</h3><p>Upload a .env file from the Dashboard.</p></div>';
}
function getCheckedVars(){return[...document.querySelectorAll('.audit-cb:checked')].map(c=>c.dataset.var);}
function updateAuditActions(){const n=getCheckedVars().length;E('btn-build-env').style.display=n?'inline-flex':'none';E('btn-del-selected').style.display=n?'inline-flex':'none';}
function toggleAllAudit(on){document.querySelectorAll('.audit-cb').forEach(c=>c.checked=on);updateAuditActions();}
async function deleteSelected(){const vars=getCheckedVars();if(!vars.length)return;if(!confirm('Remove '+vars.length+' credential(s) from your .env file?'))return;const d=await api('/api/env/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vars})});if(d.error){toast(d.error,'error');return;}toast('Removed '+d.removed+' credential(s)','success');runAudit();}
async function runAudit(){
  go('audit');setLoading('audit-loader',true,'Validating credentials against live APIs…');
  E('audit-stats').style.display='none';E('audit-results').innerHTML='';E('audit-output-card').style.display='none';E('audit-toolbar').style.display='none';
  document.querySelectorAll('.btn').forEach(b=>b.disabled=true);
  const d=await api('/api/audit');
  document.querySelectorAll('.btn').forEach(b=>b.disabled=false);setLoading('audit-loader',false);
  if(d.error){E('audit-results').innerHTML='<div class="empty"><div class="icon">⚠️</div><h3>Error</h3><p>'+esc(d.error)+'</p></div>';return;}
  const s=d.summary||{};E('audit-stats').style.display='block';E('audit-toolbar').style.display='block';
  E('s-total').textContent=s.total_keys||d.results?.length||0;E('s-valid').textContent=s.valid||0;E('s-failed').textContent=s.failed||0;E('s-providers').textContent=s.providers_checked||0;
  E('d-total').textContent=s.total_keys||d.results?.length||0;E('d-valid').textContent=s.valid||0;E('d-failed').textContent=s.failed||0;
  auditData=d.results||[];E('audit-sort').value='default';E('audit-filter').value='all';E('audit-check-all').checked=false;updateAuditActions();
  renderAuditResults();
  // mirror to dashboard
  let dh='';for(const k of auditData){const st=SI[k.status]?k.status:'network_error';const si=SI[st]||{i:'?',l:st};const fp=k.key_fingerprint||{};const fs=fp.prefix?esc(fp.prefix)+'…'+esc(fp.suffix)+' ('+esc(fp.length)+')':esc(fp.redacted||'');
    dh+='<div class="kc v-'+escAttr(st)+'"><span class="ki">'+si.i+'</span><div class="km"><div class="kp">'+esc(k.provider)+'</div><div class="ke">'+esc(k.env_var)+' · '+fs+'</div></div><span class="ks t-'+escAttr(st)+'">'+esc(si.l)+'</span></div>';}
  E('dash-results').innerHTML=dh||E('dash-results').innerHTML;
}
// ── Build .env ──
async function openBuildEnv(){
  const vars=getCheckedVars();if(!vars.length){toast('Select credentials first','info');return;}
  const d=await api('/api/env/read');if(d.error){toast(d.error,'error');return;}
  const envMap=d.vars||{};
  // group by provider from auditData
  const groups={};for(const k of auditData){if(!vars.includes(k.env_var))continue;const p=k.provider||'Other';if(!groups[p])groups[p]=[];groups[p].push(k);}
  let h='';for(const p of Object.keys(groups).sort()){
    h+='<div style="margin-bottom:12px"><div style="font-weight:700;font-size:.8125rem;color:var(--glow);margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em">'+esc(p)+'</div>';
    for(const k of groups[p]){const st=SI[k.status]?k.status:'network_error';const si=SI[st]||{i:'?',l:st};
      h+='<label style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--glass-border);font-size:.8125rem;cursor:pointer"><input type="checkbox" checked class="build-cb" data-var="'+escAttr(k.env_var)+'"><span style="font-weight:600;flex:1">'+esc(k.env_var)+'</span><span class="ks t-'+escAttr(st)+'" style="font-size:.6rem">'+esc(si.l)+'</span></label>';}
    h+='</div>';}
  E('build-env-list').innerHTML=h;E('build-env-preview').style.display='none';
  E('modal-build-env').classList.add('open');
}
function buildEnvText(){
  const checked=[...document.querySelectorAll('.build-cb:checked')].map(c=>c.dataset.var);
  const groups={};for(const k of auditData){if(!checked.includes(k.env_var))continue;const p=k.provider||'Other';if(!groups[p])groups[p]=[];groups[p].push(k);}
  let out='# Generated by Check Please\n# '+new Date().toISOString().slice(0,10)+'\n';
  for(const p of Object.keys(groups).sort()){out+='\n# ── '+p.toUpperCase()+' ──\n';for(const k of groups[p])out+=k.env_var+'=${'+k.env_var+'}\n';}
  return out;
}
async function previewBuildEnv(){
  const checked=[...document.querySelectorAll('.build-cb:checked')].map(c=>c.dataset.var);
  const d=await api('/api/env/read');const envMap=d.vars||{};
  const groups={};for(const k of auditData){if(!checked.includes(k.env_var))continue;const p=k.provider||'Other';if(!groups[p])groups[p]=[];groups[p].push(k);}
  let out='# Generated by Check Please\n# '+new Date().toISOString().slice(0,10)+'\n';
  for(const p of Object.keys(groups).sort()){out+='\n# ── '+p.toUpperCase()+' ──\n';for(const k of groups[p]){const v=envMap[k.env_var]||'';const masked=v?v.substring(0,6)+'…':'<not found>';out+=k.env_var+'='+masked+'\n';}}
  E('build-env-preview').textContent=out;E('build-env-preview').style.display='block';
}
async function saveBuildEnv(){
  const checked=new Set([...document.querySelectorAll('.build-cb:checked')].map(c=>c.dataset.var));
  if(!checked.size){toast('Select at least one credential','info');return;}
  const groups={};for(const k of auditData){if(!checked.has(k.env_var))continue;const p=k.provider||'Other';if(!groups[p])groups[p]=[];groups[p].push(k.env_var);}
  const d=await api('/api/env/build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vars:[...checked],groups})});
  if(d.error){toast(d.error,'error');return;}
  toast('Saved '+d.count+' credentials to '+d.path,'success');closeModals();
}
async function downloadBuildEnv(){
  const checked=[...document.querySelectorAll('.build-cb:checked')].map(c=>c.dataset.var);
  if(!checked.length){toast('Select at least one credential','info');return;}
  const groups={};for(const k of auditData){if(!checked.includes(k.env_var))continue;const p=k.provider||'Other';if(!groups[p])groups[p]=[];groups[p].push(k.env_var);}
  const d=await api('/api/env/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vars:checked,groups,template:false})});
  if(d.error){toast(d.error,'error');return;}
  toast('Exported to '+d.path,'success');closeModals();
}
async function runPreview(){go('audit');setLoading('audit-loader',true,'Loading preview…');E('audit-results').innerHTML='';const d=await api('/api/preview');setLoading('audit-loader',false);E('audit-output-card').style.display='block';E('audit-output').textContent=d.output||d.error||'No output';}
async function runSelfTest(){go('audit');setLoading('audit-loader',true,'Running self-test…');E('audit-results').innerHTML='';const d=await api('/api/self-test');setLoading('audit-loader',false);E('audit-output-card').style.display='block';E('audit-output').textContent=d.output||d.error||'No output';}
async function loadProviders(){setLoading('prov-loader',true);const d=await api('/api/providers');setLoading('prov-loader',false);if(d.output)E('prov-list').innerHTML='<div class="pre">'+d.output.replace(/</g,'&lt;')+'</div>';}

// ── Backup & Emergency ──
async function exportBackup(){
  const pw=prompt('Enter your password to encrypt the backup:');if(!pw)return;
  const d=await api('/api/backup/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passkey:pw})});
  if(d.error){toast(d.error,'error');return;}
  toast('Backup saved to '+d.path,'success');E('backup-status').textContent='Last backup: '+new Date().toLocaleString()+' → '+d.path;
}
async function importBackup(input){
  const file=input.files[0];if(!file)return;
  const pw=prompt('Enter the password used when this backup was created:');if(!pw){input.value='';return;}
  const text=await file.text();
  const d=await api('/api/backup/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:text,passkey:pw})});
  input.value='';if(d.error){toast(d.error,'error');return;}
  toast('Restored! '+d.vault_entries+' vault entries recovered.','success');loadVault();
}
function printEmergencySheet(){
  const user=E('set-name').value||'Unknown';const date=E('set-created').value||new Date().toLocaleString();
  const w=window.open('','_blank','width=700,height=900');
  w.document.write('<html><head><title>Emergency Sheet</title><style>body{font-family:Arial,sans-serif;max-width:600px;margin:40px auto;color:#111}h1{font-size:24px;border-bottom:3px solid #4f46e5;padding-bottom:12px}h2{font-size:16px;margin-top:28px;color:#4f46e5}.box{border:2px dashed #999;border-radius:8px;padding:16px;margin:12px 0;font-family:monospace;font-size:18px;letter-spacing:2px;text-align:center;min-height:28px}.info{font-size:13px;color:#555;line-height:1.7;margin:12px 0}.warn{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:14px;font-size:13px;margin:20px 0}.footer{margin-top:40px;font-size:11px;color:#999;border-top:1px solid #ddd;padding-top:12px}@media print{body{margin:20px}}</style></head><body>');
  w.document.write('<h1>🔑 Check Please — Emergency Recovery Sheet</h1>');
  w.document.write('<div class="info"><strong>Username:</strong> '+esc(user)+'<br><strong>Account Created:</strong> '+esc(date)+'<br><strong>Printed:</strong> '+esc(new Date().toLocaleString())+'</div>');
  w.document.write('<h2>Recovery Key</h2><div class="box" id="rk">Your recovery key was shown when you created your account.<br>Write it here:</div>');
  w.document.write('<h2>Instructions</h2><div class="info"><ol><li>Open Check Please and click <strong>Forgot password?</strong></li><li>Enter the recovery key above</li><li>Set a new password</li><li>Your vault key is unwrapped via the recovery wrap — vault data stays intact on accounts created with v1.1+</li></ol></div>');
  w.document.write('<div class="warn"><strong>⚠️ Keep this sheet in a safe place</strong> (safe, safety deposit box, etc). Anyone with this recovery key can reset your password and access your vault.</div>');
  w.document.write('<h2>If Recovery Key Is Lost</h2><div class="info">If you lose both your password and recovery key, import an <strong>encrypted backup</strong> file (.cpbackup). If no backup exists, the vault data cannot be recovered — this is by design for your security.</div>');
  w.document.write('<div class="footer">Generated by Check Please · github.com/Senpai-Sama7/check-please · This document contains sensitive recovery information.</div>');
  w.document.write('</body></html>');w.document.close();w.print();
}

// ── .env Upload & Drag/Drop ──
const dz=E('drop-zone');
['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('dragover')}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('dragover')}));
dz.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];if(f)uploadEnvFile(f);});
function handleEnvUpload(input){const f=input.files[0];if(f)uploadEnvFile(f);input.value='';}
async function uploadEnvFile(file){
  const text=await file.text();
  const d=await api('/api/env/upload',{method:'POST',headers:{'Content-Type':'text/plain'},body:text});
  if(d.error){toast(d.error,'error');return;}
  toast('Uploaded '+d.keys+' credentials from '+file.name,'success');
}

// ── Shell Scan ──
let scannedVars={};
async function scanEnv(){
  const d=await api('/api/env/scan');
  if(d.error){toast(d.error,'error');return;}
  scannedVars=d.found||{};
  const keys=Object.keys(scannedVars);
  if(!keys.length){toast('No API keys found in shell config files','info');return;}
  E('scan-summary').textContent='Found '+keys.length+' credential(s) in your shell config files. Select which to import:';
  let h='';for(const k of keys){h+='<label style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--glass-border);font-size:.8125rem;cursor:pointer"><input type="checkbox" checked data-key="'+escAttr(k)+'"><span style="font-weight:600">'+esc(k)+'</span><span style="color:var(--text3);font-family:var(--font-mono);font-size:.7rem">'+esc((scannedVars[k]||'').substring(0,8))+'…</span></label>';}
  E('scan-list').innerHTML=h;E('modal-scan').classList.add('open');
}
async function importScanned(){
  const vars={};E('scan-list').querySelectorAll('input[type=checkbox]:checked').forEach(cb=>{const k=cb.dataset.key;if(scannedVars[k])vars[k]=scannedVars[k];});
  if(!Object.keys(vars).length){toast('No credentials selected','info');return;}
  const d=await api('/api/env/scan-import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vars})});
  if(d.error){toast(d.error,'error');return;}
  toast('Imported '+d.added+' credentials to .env','success');closeModals();
}

// ── Vault ──
let vault=[];
async function loadVault(){const d=await api('/api/vault');vault=d.entries||[];E('vault-count').textContent=vault.length;E('d-vault').textContent=vault.length;renderVault();}
function renderVault(){
  const q=(E('vault-search')?.value||'').toLowerCase();
  const filtered=vault.filter(e=>!q||e.site?.toLowerCase().includes(q)||e.username?.toLowerCase().includes(q)||e.notes?.toLowerCase().includes(q));
  if(!filtered.length){E('vault-list').innerHTML='<div class="empty"><div class="icon">🔐</div><h3>No passwords yet</h3><p>Click "Add Entry" or import from CSV.</p></div>';return;}
  let h='<div class="table-wrap"><table><thead><tr><th>Site</th><th>Username</th><th>Password</th><th>Strength</th><th>Added</th><th>Actions</th></tr></thead><tbody>';
  for(const e of filtered){const str=pwStrength(e.password||'');const cls=str.score>=5?'green':str.score>=3?'amber':'red';
    h+='<tr><td style="font-weight:600">'+esc(e.site||'—')+'</td><td><span style="font-family:var(--font-mono);font-size:.75rem">'+esc(e.username||'—')+'</span></td>';
    h+='<td><span style="font-family:var(--font-mono);font-size:.75rem;color:var(--text2)" id="pw-'+e.id+'">••••••••</span> <button class="btn sm" onclick="toggleVaultPw(\''+e.id+'\')">👁</button> <button class="btn sm" onclick="copyVaultPw(\''+e.id+'\')">📋</button></td>';
    h+='<td><span class="badge '+cls+'">'+str.label+'</span></td>';
    h+='<td style="color:var(--text3);font-size:.7rem">'+(e.created?new Date(e.created).toLocaleDateString():'—')+'</td>';
    h+='<td><div class="btn-group"><button class="btn sm" onclick="editEntry(\''+e.id+'\')">✏️</button><button class="btn sm danger" onclick="deleteEntry(\''+e.id+'\')">🗑️</button></div></td></tr>';}
  h+='</tbody></table></div>';E('vault-list').innerHTML=h;
}
function pwStrength(pw){const l=pw.length,u=/[A-Z]/.test(pw),lo=/[a-z]/.test(pw),d=/\d/.test(pw),s=/[^A-Za-z0-9]/.test(pw);const score=[l>=8,l>=12,l>=16,u,lo,d,s].filter(Boolean).length;const labels=['Very Weak','Weak','Weak','Fair','Good','Strong','Very Strong','Excellent'];return{score,label:labels[Math.min(score,7)]};}
function toggleVaultPw(id){const el=E('pw-'+id);if(!el)return;const entry=vault.find(e=>e.id===id);if(!entry)return;el.textContent=el.textContent==='••••••••'?entry.password:'••••••••';}
function copyVaultPw(id){const entry=vault.find(e=>e.id===id);if(!entry)return;copyText(entry.password);}
function copyText(text){navigator.clipboard.writeText(text).then(()=>toast('Copied','success')).catch(()=>toast('Copy failed','error'));}

// ── Add/Edit ──
function openAddModal(){E('modal-add-title').textContent='Add Password';E('v-site').value='';E('v-user').value='';E('v-pass').value='';E('v-notes').value='';E('v-edit-id').value='';updateStrength();E('modal-add').classList.add('open');E('v-site').focus();}
function editEntry(id){const e=vault.find(v=>v.id===id);if(!e)return;E('modal-add-title').textContent='Edit Password';E('v-site').value=e.site||'';E('v-user').value=e.username||'';E('v-pass').value=e.password||'';E('v-notes').value=e.notes||'';E('v-edit-id').value=id;updateStrength();E('modal-add').classList.add('open');}
async function saveEntry(){const site=E('v-site').value.trim(),user=E('v-user').value.trim(),pass=E('v-pass').value,notes=E('v-notes').value.trim(),editId=E('v-edit-id').value;if(!site&&!user&&!pass){toast('Fill in at least one field','error');return;}const body={site,username:user,password:pass,notes};if(editId)body.id=editId;const d=await api('/api/vault',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(d.error){toast(d.error,'error');return;}toast(editId?'Updated':'Saved','success');closeModals();loadVault();}
async function deleteEntry(id){if(!confirm('Delete this entry?'))return;await api('/api/vault/'+id,{method:'DELETE'});toast('Deleted','success');loadVault();}
async function clearVault(){await api('/api/vault/clear',{method:'POST'});toast('Vault cleared','success');loadVault();}
function togglePw(id){const el=E(id);el.type=el.type==='password'?'text':'password';}
function updateStrength(){const pw=E('v-pass').value;const s=pwStrength(pw);const pct=Math.round((s.score/7)*100);const colors=['#ef4444','#ef4444','#f59e0b','#f59e0b','#22c55e','#22c55e','#34d399','#34d399'];E('pw-fill').style.width=pct+'%';E('pw-fill').style.background=colors[s.score]||'#ef4444';E('pw-label').textContent=pw?s.label+' ('+pw.length+' chars)':'';E('pw-label').style.color=colors[s.score]||'var(--text2)';}

// ── Generator ──
function openGenModal(){E('gen-site').value='';E('gen-user').value='';E('modal-gen').classList.add('open');generatePw();}
function generatePw(){const len=Math.max(4,Math.min(128,parseInt(E('gen-len').value)||20));let chars='';if(E('gen-upper').checked)chars+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';if(E('gen-lower').checked)chars+='abcdefghijklmnopqrstuvwxyz';if(E('gen-digits').checked)chars+='0123456789';if(E('gen-symbols').checked)chars+='!@#$%^&*()_+-=[]{}|;:,.<>?';if(!chars)chars='abcdefghijklmnopqrstuvwxyz0123456789';const arr=new Uint32Array(len);crypto.getRandomValues(arr);E('gen-result').value=Array.from(arr,v=>chars[v%chars.length]).join('');}
function fillGenerated(){generatePw();E('v-pass').value=E('gen-result').value;updateStrength();toast('Generated password filled','info');}
async function saveGenerated(){const pw=E('gen-result').value;if(!pw){toast('Generate a password first','error');return;}const body={site:E('gen-site').value.trim(),username:E('gen-user').value.trim(),password:pw,notes:'Generated by password generator'};const d=await api('/api/vault',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(d.error){toast(d.error,'error');return;}toast('Saved to vault','success');loadVault();}

// ── CSV ──
function importCSV(){E('csv-file').click();}
async function handleCSVImport(input){const file=input.files[0];if(!file)return;const text=await file.text();const d=await api('/api/vault/import',{method:'POST',headers:{'Content-Type':'text/csv'},body:text});if(d.error)toast(d.error,'error');else toast('Imported '+d.imported+' entries','success');input.value='';loadVault();}
function exportCSV(){window.open('/api/vault/export','_blank');toast('CSV download started','success');}

// ── Modals ──
function closeModals(){document.querySelectorAll('.modal-overlay').forEach(m=>m.classList.remove('open'));}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModals();});

// ── Account ──
async function checkAccount(){
  const d=await api('/api/account/status');
  if(d.users&&d.users.length){populateLogin(d.users);E('lock-setup').style.display='none';E('lock-login').style.display='block';
    if(d.has_biometric&&window.PublicKeyCredential){E('bio-login-btn').style.display='block';E('bio-forgot-btn').style.display='block';}
  }else{E('lock-setup').style.display='block';E('lock-login').style.display='none';}
}
function populateLogin(users){
  const inp=E('login-user-input');
  let dl=document.getElementById('user-suggestions');if(!dl){dl=document.createElement('datalist');dl.id='user-suggestions';document.body.appendChild(dl);}
  dl.innerHTML='';if(users)users.forEach(u=>{const o=document.createElement('option');o.value=u;dl.appendChild(o);});
  inp.setAttribute('list','user-suggestions');
  if(users&&users.length===1&&!inp.value)inp.value=users[0];
  E('lock-greeting').textContent=users&&users.length?'Welcome back.':'Sign in to your vault.';
}
function getLoginUser(){return E('login-user-input').value.trim();}
function showSetup(){E('lock-login').style.display='none';E('lock-forgot').style.display='none';E('lock-setup').style.display='block';}
function showLogin(){E('lock-setup').style.display='none';E('lock-forgot').style.display='none';E('lock-login').style.display='block';
  api('/api/account/status').then(d=>populateLogin(d.users||[]));}
function onUserPick(){E('login-err').textContent='';}
function logout(){api('/api/account/logout',{method:'POST'}).finally(()=>{E('lock-screen').classList.remove('hidden');E('login-pass').value='';E('login-err').textContent='';checkAccount();});}
async function createAccount(){const name=E('setup-name').value.trim(),p1=E('setup-pass').value,p2=E('setup-pass2').value;if(!name){E('setup-err').textContent='Username is required.';return;}if(!p1||p1.length<8){E('setup-err').textContent='Password must be at least 8 characters.';return;}if(p1!==p2){E('setup-err').textContent='Passwords do not match.';return;}const d=await api('/api/account/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,passkey:p1})});if(d.error){E('setup-err').textContent=d.error;return;}E('lock-screen').classList.add('hidden');if(d.recovery_key){E('recovery-key-display').textContent=d.recovery_key;E('modal-recovery').style.display='flex';}else{startTour();}}
async function unlock(){const pw=E('login-pass').value,user=getLoginUser();if(!user){E('login-err').textContent='Enter your username.';return;}if(!pw){E('login-err').textContent='Enter your password.';return;}const d=await api('/api/account/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,passkey:pw})});if(!d.ok){E('login-err').textContent=d.error||'Incorrect password.';return;}E('lock-screen').classList.add('hidden');loadVault();loadAccountSettings();}
async function changePasskey(){const old=E('set-old-pass').value,nw=E('set-new-pass').value;if(!old||!nw){toast('Fill in both fields','error');return;}if(nw.length<8){toast('Min 8 characters','error');return;}const d=await api('/api/account/change-passkey',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_passkey:old,new_passkey:nw})});if(d.error){toast(d.error,'error');return;}toast('Password updated','success');E('set-old-pass').value='';E('set-new-pass').value='';}
function showForgot(){E('lock-login').style.display='none';E('lock-forgot').style.display='block';E('forgot-err').textContent='';}
function hideForgot(){E('lock-forgot').style.display='none';E('lock-login').style.display='block';}
async function recoverAccount(){const key=E('forgot-key').value.trim(),pw=E('forgot-new-pass').value,user=getLoginUser();if(!key){E('forgot-err').textContent='Enter your recovery key.';return;}if(!pw||pw.length<8){E('forgot-err').textContent='New password must be at least 8 characters.';return;}const d=await api('/api/account/recover',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,recovery_key:key,new_passkey:pw})});if(d.error){E('forgot-err').textContent=d.error;return;}if(d.vault_preserved===false){toast(d.warning||'Password reset — vault may need a backup restore','info');}else{toast('Password reset successfully','success');}hideForgot();}
async function nukeAccount(){const pw=prompt('Enter your password to permanently delete your account:');if(!pw)return;const d=await api('/api/account/nuke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passkey:pw})});if(d.error){toast(d.error,'error');return;}toast('Account erased. Starting fresh.','info');location.reload();}

async function loadAccountSettings(){const d=await api('/api/account/status');if(d.name)E('set-name').value=d.name;if(d.created)E('set-created').value=new Date(d.created).toLocaleString();
  const bioOk=!!(window.PublicKeyCredential&&navigator.credentials?.create);
  if(!bioOk)E('bio-unsupported').style.display='block';
  if(d.has_biometric){E('bio-status').textContent='Active';E('bio-badge').style.display='inline-flex';E('bio-setup-btn').textContent='🔒 Re-register';E('bio-remove-btn').style.display='inline-flex';}else{E('bio-status').textContent='Not set up';E('bio-badge').style.display='none';E('bio-setup-btn').textContent='🔒 Set Up Biometrics';E('bio-remove-btn').style.display='none';}}

// ── WebAuthn ──
function bufToB64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)));}
function b64ToBuf(b64){return Uint8Array.from(atob(b64),c=>c.charCodeAt(0)).buffer;}
async function registerBiometric(){if(!window.PublicKeyCredential||!navigator.credentials?.create){E('bio-unsupported').style.display='block';toast('Biometrics not available — open in a browser instead','error');return;}try{const ch=await api('/api/webauthn/register-challenge');if(ch.error){toast(ch.error,'error');return;}const cred=await navigator.credentials.create({publicKey:{challenge:b64ToBuf(ch.challenge),rp:{name:'Check Please',id:'localhost'},user:{id:b64ToBuf(ch.user_id),name:ch.user_name||'user',displayName:ch.user_name||'User'},pubKeyCredParams:[{alg:-7,type:'public-key'},{alg:-257,type:'public-key'}],authenticatorSelection:{userVerification:'required',residentKey:'preferred'},timeout:60000}});const d=await api('/api/webauthn/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential_id:bufToB64(cred.rawId)})});if(d.error){toast(d.error,'error');return;}toast('Biometric registered!','success');loadAccountSettings();}catch(e){if(e.name==='NotAllowedError')toast('Cancelled','info');else toast(e.message,'error');}}
async function biometricAuth(){toast('Biometric-only unlock is disabled until full WebAuthn assertion verification ships. Enter your password.','info');E('login-pass').focus();}
async function removeBiometric(){if(!confirm('Remove biometric unlock?'))return;await api('/api/webauthn/remove',{method:'POST'});toast('Removed','success');loadAccountSettings();}

// ── Tour ──
const TOUR=[
  {icon:'👋',title:'Welcome to Check Please',desc:'Your secure credential broker and password vault. Everything runs locally — your secrets never leave this machine.'},
  {icon:'📄',title:'Load Your Credentials',desc:'Upload or drag & drop your .env file directly into the dashboard. Or scan your shell config files (~/.bashrc, ~/.zshrc) to auto-detect API keys.'},
  {icon:'🔍',title:'Credential Audit',desc:'Validate every API key against live provider endpoints. Supports 16 services including OpenAI, GitHub, Stripe, and more.'},
  {icon:'🔐',title:'Password Vault',desc:'Store passwords with encrypted local storage. Add manually, generate strong passwords, or import from CSV (Chrome, 1Password, Bitwarden).'},
  {icon:'🤖',title:'AI Agent Broker',desc:'Give your AI coding agents scoped access to credentials — with usage limits, expiry, and full audit logging.'},
  {icon:'🎲',title:'Password Generator',desc:'Cryptographically secure passwords with customizable length and character sets. Real-time strength meter.'},
  {icon:'✅',title:'You\'re All Set!',desc:'Head to the Dashboard to upload your .env and run your first audit. Replay this tour anytime from Settings → Help.'},
];
let tourStep=0;
function startTour(){tourStep=0;E('onboard').classList.remove('hidden');renderTourStep();}
function skipTour(){E('onboard').classList.add('hidden');loadVault();loadAccountSettings();}
function nextStep(){tourStep++;if(tourStep>=TOUR.length){E('onboard').classList.add('hidden');loadVault();loadAccountSettings();return;}renderTourStep();}
function renderTourStep(){const s=TOUR[tourStep];E('ob-icon').textContent=s.icon;E('ob-title').textContent=s.title;E('ob-desc').textContent=s.desc;let dots='';for(let i=0;i<TOUR.length;i++)dots+='<div class="dot'+(i===tourStep?' active':'')+'"></div>';E('ob-dots').innerHTML=dots;E('ob-next').textContent=tourStep===TOUR.length-1?'Finish ✓':'Next →';}

// ── Init ──
checkAccount();
</script>
</body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a: object) -> None:
        pass

    def _sec_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")

    def _check_session(self) -> bool:
        """Validate session cookie. Returns False and sends 401 if invalid."""
        cookie = self.headers.get("Cookie", "")
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                token = part[8:]
                break
        if not token or not _session_token or not _hmac.compare_digest(token, _session_token):
            self._json({"error": "Not authenticated"}, 401)
            return False
        return True

    def _set_session_cookie(self):
        """Generate new session token and queue cookie for next response."""
        global _session_token
        _session_token = secrets.token_urlsafe(32)
        self._pending_session_cookie = _session_token

    def _clear_session_cookie(self):
        """Queue cookie deletion for next response."""
        self._pending_clear_session = True

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._sec_headers()
        if getattr(self, "_pending_session_cookie", None):
            self.send_header("Set-Cookie", f"session={self._pending_session_cookie}; HttpOnly; SameSite=Strict; Path=/")
            self._pending_session_cookie = None
        if getattr(self, "_pending_clear_session", False):
            self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            self._pending_clear_session = False
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str, code: int = 200) -> None:
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def _csv_response(self, text: str, filename: str) -> None:
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self._sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def _run_cmd(self, args: list[str]) -> dict:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "credential_auditor"] + args,
                capture_output=True, text=True, cwd=str(DIR), timeout=120,
            )
            return {"output": r.stdout + r.stderr, "exit_code": r.returncode}
        except Exception as e:
            return {"error": str(e)}

    def _read_body(self) -> bytes:
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except (TypeError, ValueError):
            self._json({"error": "Invalid Content-Length"}, 400)
            return b""
        if length < 0:
            self._json({"error": "Invalid Content-Length"}, 400)
            return b""
        if length > _MAX_BODY_BYTES:
            self._json({"error": "Request body too large"}, 413)
            return b""
        return self.rfile.read(length) if length else b""

    # Endpoints that don't require a session
    _PUBLIC_PATHS = {"/", "/api/account/create", "/api/account/verify", "/api/account/recover",
                     "/api/account/status", "/api/account/users", "/api/webauthn/auth-challenge",
                     "/api/webauthn/auth", "/api/vault/strength"}

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path not in self._PUBLIC_PATHS and path.startswith("/api/"):
            if not self._check_session():
                return

        if path == "/":
            self._html(HTML)
        elif path == "/api/audit":
            env = DATA_DIR / ".env"
            if not env.is_file():
                self._json({"error": "No .env file found. Create a .env file with your API keys."}, 400)
                return
            r = subprocess.run(
                [sys.executable, "-m", "credential_auditor", "--env", str(env), "--json", "--timeout", "30"],
                capture_output=True, text=True, cwd=str(DIR), timeout=120,
            )
            try:
                self._json(json.loads(r.stdout))
            except json.JSONDecodeError:
                self._json({"error": r.stderr or r.stdout or "Audit failed"})
        elif path == "/api/preview":
            env = DATA_DIR / ".env"
            if not env.is_file():
                self._json({"error": "No .env file found"}, 400)
                return
            self._json(self._run_cmd(["--dry-run", "--env", str(env)]))
        elif path == "/api/env/read":
            env_path = DATA_DIR / ".env"
            if not env_path.is_file():
                self._json({"vars": {}})
                return
            vs: dict[str, str] = {}
            for line in env_path.read_text().splitlines():
                if line.strip() and not line.strip().startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    vs[k.strip()] = v.strip()
            self._json({"vars": vs})
        elif path == "/api/env/scan":
            # Scan shell rc files for exported env vars
            found: dict[str, str] = {}
            for rc in [Path.home() / ".bashrc", Path.home() / ".zshrc", Path.home() / ".bash_profile", Path.home() / ".profile"]:
                if rc.is_file():
                    try:
                        for line in rc.read_text().splitlines():
                            line = line.strip()
                            if line.startswith("export ") and "=" in line:
                                part = line[7:].strip()
                                k, _, v = part.partition("=")
                                k = k.strip()
                                v = v.strip().strip("'\"")
                                if k and v and any(p in k.upper() for p in ("KEY", "TOKEN", "SECRET", "PASSWORD", "API")):
                                    found[k] = v
                    except Exception:
                        pass
            self._json({"found": found, "count": len(found)})
        elif path == "/api/self-test":
            self._json(self._run_cmd(["--self-test"]))
        elif path == "/api/providers":
            self._json(self._run_cmd(["--list-providers"]))
        elif path == "/api/account/status":
            _migrate_legacy()
            users = _list_users()
            acct = _load_account()
            if acct:
                self._json({"exists": True, "users": users, "name": acct.get("name", ""), "created": acct.get("created", ""), "has_biometric": bool(acct.get("webauthn_credentials"))})
            elif users:
                self._json({"exists": True, "users": users})
            else:
                self._json({"exists": False, "users": []})
        elif path == "/api/webauthn/register-challenge":
            acct = _load_account()
            if not acct:
                self._json({"error": "No account"}, 400)
                return
            challenge = base64.b64encode(secrets.token_bytes(32)).decode()
            acct["_webauthn_challenge"] = challenge
            _save_account(acct)
            user_id = base64.b64encode(hashlib.sha256(acct.get("name", "user").encode()).digest()[:16]).decode()
            self._json({"challenge": challenge, "user_id": user_id, "user_name": acct.get("name", "user")})
        elif path == "/api/webauthn/auth-challenge":
            acct = _load_account()
            if not acct or not acct.get("webauthn_credentials"):
                self._json({"error": "No biometric registered"}, 400)
                return
            challenge = base64.b64encode(secrets.token_bytes(32)).decode()
            acct["_webauthn_challenge"] = challenge
            _save_account(acct)
            cred_ids = [c["id"] for c in acct["webauthn_credentials"]]
            self._json({"challenge": challenge, "credentials": cred_ids})
        elif path == "/api/vault":
            self._json({"entries": _load_vault()})
        elif path == "/api/vault/export":
            entries = _load_vault()

            def _csv_safe(v: str) -> str:
                # Prevent CSV formula injection (Excel/Sheets)
                if v and v[0] in ("=", "+", "-", "@", "|", "%"):
                    return "'" + v
                return v

            out = io.StringIO()
            w = csv.writer(out, quoting=csv.QUOTE_ALL)
            w.writerow(["site", "username", "password", "notes"])
            for e in entries:
                w.writerow([
                    _csv_safe(e.get("site", "")),
                    _csv_safe(e.get("username", "")),
                    _csv_safe(e.get("password", "")),
                    _csv_safe(e.get("notes", "")),
                ])
            self._csv_response(out.getvalue(), "vault_export.csv")
        elif path == "/stop":
            if not self._check_session():
                return
            self._html("<h1>Server stopped</h1><p>You can close this tab.</p>")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._html("<h1>Not found</h1>", 404)

    def do_POST(self) -> None:
        global _current_user, _session_passkey
        path = self.path.split("?")[0]
        if path not in self._PUBLIC_PATHS and path.startswith("/api/"):
            if not self._check_session():
                return
        body = self._read_body()

        if path == "/api/account/create":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            username = data.get("name", "").strip()
            if not _valid_username(username):
                self._json({"error": "Username must be 1–64 chars: letters, digits, _ . -"}, 400)
                return
            if _acct_path(username).is_file():
                self._json({"error": "Username already taken"}, 400)
                return
            passkey = data.get("passkey", "")
            if len(passkey) < _MIN_PASSKEY_LEN:
                self._json({"error": f"Password must be at least {_MIN_PASSKEY_LEN} characters"}, 400)
                return
            _current_user = username
            recovery_key = _make_recovery_key()
            vault_key = _new_vault_key()
            _session_passkey = vault_key
            check_blob = _encrypt("check_please_ok", passkey)
            recovery_salt = secrets.token_bytes(16)
            recovery_hash = hashlib.pbkdf2_hmac("sha256", recovery_key.encode(), recovery_salt, 200_000).hex()
            _save_account({
                "name": username,
                "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "check": check_blob,
                "recovery_hash": recovery_hash,
                "recovery_salt": recovery_salt.hex(),
                # Vault key wrapped by passkey AND recovery key so recovery preserves vault
                "vault_key_wrap": _encrypt(vault_key, passkey),
                "vault_key_recovery_wrap": _encrypt(vault_key, recovery_key),
            })
            # Ensure new accounts start with an encrypted empty vault
            _save_vault([])
            self._set_session_cookie()
            self._json({"ok": True, "recovery_key": recovery_key})
        elif path == "/api/account/verify":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            username = data.get("username", "") or (_list_users() or [""])[0]
            if not _valid_username(username):
                self._json({"ok": False, "error": "Invalid username"}, 400)
                return
            wait = _check_rate_limit(username)
            if wait > 0:
                self._json({"ok": False, "error": f"Too many attempts. Try again in {int(wait)+1}s."}, 429)
                return
            passkey = data.get("passkey", "")
            ok = _verify_passkey(passkey, username)
            if ok:
                _current_user = username
                _clear_fails(username)
                acct = _load_account(username) or {}
                vault_key = _unwrap_vault_key(acct, passkey)
                if vault_key:
                    _session_passkey = vault_key
                else:
                    # Legacy account: passkey was the vault key — migrate to wrapped vault key
                    _session_passkey = passkey
                    vf = _vault_path(username)
                    entries: list[dict] = []
                    if vf.is_file():
                        try:
                            raw = json.loads(vf.read_text())
                            if isinstance(raw, list):
                                entries = raw
                            elif isinstance(raw, dict) and "encrypted" in raw:
                                entries = _load_vault()
                        except Exception:
                            entries = []
                    vault_key = _new_vault_key()
                    acct["vault_key_wrap"] = _encrypt(vault_key, passkey)
                    # No recovery wrap available without the recovery key (user must re-save via recover)
                    _save_account(acct, username)
                    _session_passkey = vault_key
                    _save_vault(entries)
                self._set_session_cookie()
            else:
                _record_fail(username)
            self._json({"ok": ok})
        elif path == "/api/account/logout":
            _clear_session()
            self._clear_session_cookie()
            self._json({"ok": True})
        elif path == "/api/account/change-passkey":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            old_passkey = data.get("old_passkey", "")
            if not _verify_passkey(old_passkey):
                self._json({"error": "Current passkey is incorrect"}, 403)
                return
            new_passkey = data.get("new_passkey", "")
            if len(new_passkey) < _MIN_PASSKEY_LEN:
                self._json({"error": f"New passkey must be at least {_MIN_PASSKEY_LEN} characters"}, 400)
                return
            acct = _load_account() or {}
            vault_key = _unwrap_vault_key(acct, old_passkey) or _session_passkey or old_passkey
            acct["check"] = _encrypt("check_please_ok", new_passkey)
            acct["vault_key_wrap"] = _encrypt(vault_key, new_passkey)
            _session_passkey = vault_key
            _save_account(acct)
            # Vault ciphertext stays as-is — same vault_key, only the wrap rotates
            self._json({"ok": True})
        elif path == "/api/account/recover":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            username = data.get("username", "") or (_list_users() or [""])[0]
            if not _valid_username(username):
                self._json({"error": "Invalid username"}, 400)
                return
            acct = _load_account(username)
            if not acct:
                self._json({"error": "No account exists"}, 400)
                return
            key = data.get("recovery_key", "")
            stored_salt = acct.get("recovery_salt", "")
            if stored_salt:
                key_hash = hashlib.pbkdf2_hmac("sha256", key.encode(), bytes.fromhex(stored_salt), 200_000).hex()
            else:
                key_hash = hashlib.sha256(key.encode()).hexdigest()  # legacy fallback
            if not _hmac.compare_digest(key_hash, acct.get("recovery_hash", "")):
                self._json({"error": "Invalid recovery key"}, 403)
                return
            new_pw = data.get("new_passkey", "")
            if len(new_pw) < _MIN_PASSKEY_LEN:
                self._json({"error": f"Password must be at least {_MIN_PASSKEY_LEN} characters"}, 400)
                return
            vault_key = _unwrap_vault_key(acct, key, "vault_key_recovery_wrap")
            acct["check"] = _encrypt("check_please_ok", new_pw)
            if vault_key:
                acct["vault_key_wrap"] = _encrypt(vault_key, new_pw)
                # Refresh recovery wrap under the same recovery key (new salt/nonce)
                acct["vault_key_recovery_wrap"] = _encrypt(vault_key, key)
                _save_account(acct, username)
                self._json({"ok": True, "vault_preserved": True})
            else:
                # Legacy account without recovery wrap — password resets, vault stays undecryptable
                _save_account(acct, username)
                self._json({
                    "ok": True,
                    "vault_preserved": False,
                    "warning": "Password reset, but this account has no recovery vault-key wrap. "
                               "Restore vault data from an encrypted .cpbackup if available.",
                })
        elif path == "/api/account/nuke":
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            if _current_user:
                if not _verify_passkey(data.get("passkey", "")):
                    self._json({"error": "Password required to delete account"}, 403)
                    return
                ap = _acct_path(_current_user)
                vp = _vault_path(_current_user)
                if ap.is_file(): ap.unlink()
                if vp.is_file(): vp.unlink()
                _clear_session()
                self._clear_session_cookie()
            # Also clean legacy files
            if _LEGACY_ACCOUNT.is_file(): _LEGACY_ACCOUNT.unlink()
            if _LEGACY_VAULT.is_file(): _LEGACY_VAULT.unlink()
            self._json({"ok": True})
        elif path == "/api/backup/export":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            passkey = data.get("passkey", "")
            if not _verify_passkey(passkey):
                self._json({"error": "Incorrect password"}, 403)
                return
            acct = _load_account()
            vault = _load_vault()
            payload = json.dumps({"account": acct, "vault": vault, "exported": time.strftime("%Y-%m-%dT%H:%M:%S"), "version": 1})
            encrypted = _encrypt(payload, passkey)
            backup = json.dumps({"check_please_backup": True, "data": encrypted}, indent=2)
            dl = Path.home() / "Downloads"
            dl.mkdir(exist_ok=True)
            name = _current_user or "backup"
            dest = dl / f"check_please_{name}_{time.strftime('%Y%m%d')}.cpbackup"
            dest.write_text(backup)
            os.chmod(dest, 0o600)
            self._json({"ok": True, "path": str(dest)})
        elif path == "/api/backup/import":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            passkey = data.get("passkey", "")
            try:
                backup = json.loads(data.get("data", ""))
            except Exception:
                self._json({"error": "Invalid backup file"}, 400)
                return
            if not backup.get("check_please_backup"):
                self._json({"error": "Not a Check Please backup file"}, 400)
                return
            decrypted = _decrypt(backup.get("data", {}), passkey)
            if not decrypted:
                self._json({"error": "Wrong password — cannot decrypt backup"}, 403)
                return
            try:
                payload = json.loads(decrypted)
            except Exception:
                self._json({"error": "Corrupted backup data"}, 400)
                return
            # Restore account
            acct = payload.get("account", {})
            if acct and acct.get("name"):
                if not _valid_username(acct["name"]):
                    self._json({"error": "Backup contains invalid username"}, 400)
                    return
                _current_user = acct["name"]
                vault_key = _unwrap_vault_key(acct, passkey)
                if not vault_key:
                    # Legacy backup: passkey was vault key — create wraps
                    vault_key = _new_vault_key()
                    acct["vault_key_wrap"] = _encrypt(vault_key, passkey)
                _session_passkey = vault_key
                _save_account(acct)
                self._set_session_cookie()
            # Restore vault (re-encrypted under current session vault key)
            vault = payload.get("vault", [])
            if isinstance(vault, list):
                _save_vault(vault)
            self._json({"ok": True, "vault_entries": len(vault) if isinstance(vault, list) else 0})
        elif path == "/api/webauthn/register":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            acct = _load_account()
            if not acct:
                self._json({"error": "No account"}, 400)
                return
            if not acct.get("_webauthn_challenge"):
                self._json({"error": "No pending challenge"}, 400)
                return
            acct.pop("_webauthn_challenge", None)
            cred_entry = {"id": data.get("credential_id", ""), "registered": time.strftime("%Y-%m-%dT%H:%M:%S")}
            acct.setdefault("webauthn_credentials", [])
            acct["webauthn_credentials"] = [c for c in acct["webauthn_credentials"] if c["id"] != cred_entry["id"]]
            acct["webauthn_credentials"].append(cred_entry)
            _save_account(acct)
            self._json({"ok": True})
        elif path == "/api/webauthn/auth":
            # Credential-ID-only checks are not WebAuthn. Do not mint a session.
            # Full assertion verification (signature / clientDataJSON / origin / RP ID)
            # is required before biometric unlock can be trusted.
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            acct = _load_account()
            if acct and acct.get("_webauthn_challenge"):
                acct.pop("_webauthn_challenge", None)
                _save_account(acct)
            self._json({
                "ok": False,
                "requires_password": True,
                "error": "Biometric-only session minting is disabled. Use password unlock.",
            })
        elif path == "/api/webauthn/remove":
            acct = _load_account()
            if acct:
                acct["webauthn_credentials"] = []
                acct.pop("_webauthn_challenge", None)
                _save_account(acct)
            self._json({"ok": True})
        elif path == "/api/vault":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            entries = _load_vault()
            edit_id = data.get("id")
            if edit_id:
                for e in entries:
                    if e["id"] == edit_id:
                        e["site"] = data.get("site", e.get("site", ""))
                        e["username"] = data.get("username", e.get("username", ""))
                        e["password"] = data.get("password", e.get("password", ""))
                        e["notes"] = data.get("notes", e.get("notes", ""))
                        e["modified"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                        break
            else:
                entries.append({
                    "id": _vault_id(),
                    "site": data.get("site", ""),
                    "username": data.get("username", ""),
                    "password": data.get("password", ""),
                    "notes": data.get("notes", ""),
                    "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                })
            _save_vault(entries)
            self._json({"ok": True})
        elif path == "/api/vault/import":
            text = body.decode("utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            entries = _load_vault()
            count = 0
            for row in reader:
                pw = row.get("password") or row.get("Password") or row.get("pass") or ""
                site = row.get("site") or row.get("Site") or row.get("url") or row.get("URL") or row.get("name") or row.get("Name") or ""
                user = row.get("username") or row.get("Username") or row.get("login") or row.get("Login") or row.get("email") or row.get("Email") or ""
                notes = row.get("notes") or row.get("Notes") or ""
                if site or user or pw:
                    entries.append({"id": _vault_id(), "site": site, "username": user, "password": pw, "notes": notes, "created": time.strftime("%Y-%m-%dT%H:%M:%S")})
                    count += 1
            _save_vault(entries)
            self._json({"imported": count})
        elif path == "/api/env/upload":
            text = body.decode("utf-8", errors="replace")
            env_path = DATA_DIR / ".env"
            env_path.write_text(text)
            os.chmod(env_path, 0o600)
            count = sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#") and "=" in line)
            self._json({"ok": True, "keys": count})
        elif path == "/api/env/scan-import":
            # Write scanned vars to .env
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            env_path = DATA_DIR / ".env"
            lines = []
            if env_path.is_file():
                lines = env_path.read_text().splitlines()
            existing = {l.split("=", 1)[0].strip() for l in lines if "=" in l and not l.strip().startswith("#")}
            added = 0
            for k, v in data.get("vars", {}).items():
                if not _valid_env_key(k):
                    continue
                # Sanitize value: strip newlines and control chars that could break .env format
                v_clean = str(v).replace("\n", "").replace("\r", "")
                if len(v_clean) > 4096:
                    v_clean = v_clean[:4096]
                if k not in existing:
                    lines.append(f"{k}={v_clean}")
                    added += 1
            env_path.write_text("\n".join(lines) + "\n")
            os.chmod(env_path, 0o600)
            self._json({"ok": True, "added": added})
        elif path == "/api/env/remove":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            to_remove = set(data.get("vars", []))
            env_path = DATA_DIR / ".env"
            if not env_path.is_file():
                self._json({"error": "No .env file"}, 400)
                return
            lines = env_path.read_text().splitlines()
            kept = [l for l in lines if not (l.strip() and not l.strip().startswith("#") and "=" in l and l.split("=", 1)[0].strip() in to_remove)]
            env_path.write_text("\n".join(kept) + "\n")
            os.chmod(env_path, 0o600)
            self._json({"ok": True, "removed": len(to_remove)})
        elif path == "/api/env/build":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            wanted = set(data.get("vars", []))
            groups: dict[str, list[str]] = data.get("groups", {})  # provider->vars
            env_path = DATA_DIR / ".env"
            existing: dict[str, str] = {}
            if env_path.is_file():
                for line in env_path.read_text().splitlines():
                    if line.strip() and not line.strip().startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        existing[k.strip()] = v.strip()
            out = "# Generated by Check Please\n"
            count = 0
            written: set[str] = set()
            if groups:
                for p in sorted(groups.keys()):
                    out += f"\n# ── {p.upper()} ──\n"
                    for k in sorted(groups[p]):
                        if k in existing and k in wanted:
                            out += f"{k}={existing[k]}\n"
                            count += 1
                            written.add(k)
            for k in sorted(wanted - written):
                if k in existing:
                    out += f"{k}={existing[k]}\n"
                    count += 1
            env_path.write_text(out)
            os.chmod(env_path, 0o600)
            self._json({"ok": True, "count": count, "path": str(env_path)})
        elif path == "/api/env/export":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            wanted = set(data.get("vars", []))
            groups: dict[str, list[str]] = data.get("groups", {})
            template = data.get("template", False)
            env_path = DATA_DIR / ".env"
            existing: dict[str, str] = {}
            if env_path.is_file():
                for line in env_path.read_text().splitlines():
                    if line.strip() and not line.strip().startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        existing[k.strip()] = v.strip()
            out = "# Generated by Check Please\n"
            written: set[str] = set()
            if groups:
                for p in sorted(groups.keys()):
                    out += f"\n# ── {p.upper()} ──\n"
                    for k in sorted(groups[p]):
                        if k in wanted:
                            val = f"YOUR_{k}_HERE" if template else existing.get(k, "")
                            out += f"{k}={val}\n"
                            written.add(k)
            for k in sorted(wanted - written):
                val = f"YOUR_{k}_HERE" if template else existing.get(k, "")
                out += f"{k}={val}\n"
            dl = Path.home() / "Downloads"
            dl.mkdir(exist_ok=True)
            dest = dl / ".env"
            dest.write_text(out)
            os.chmod(dest, 0o600)
            self._json({"ok": True, "path": str(dest)})
        elif path == "/api/vault/clear":
            _save_vault([])
            self._json({"ok": True})
        elif path == "/api/vault/strength":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            self._json(_pw_strength(data.get("password", "")))
        else:
            self._json({"error": "Not found"}, 404)

    def do_DELETE(self) -> None:
        path = self.path.split("?")[0]
        if not self._check_session():
            return
        if path.startswith("/api/vault/"):
            entry_id = path.split("/")[-1]
            entries = _load_vault()
            entries = [e for e in entries if e.get("id") != entry_id]
            _save_vault(entries)
            self._json({"ok": True})
        else:
            self._json({"error": "Not found"}, 404)


# ── Server entry point ────────────────────────────────────────────────────

def run(port: int = PORT) -> int:
    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer(("localhost", port), Handler)
    server.daemon_threads = True
    url = f"http://localhost:{port}"
    print(f"\n  🌐 Check Please — Web Interface")
    print(f"  ────────────────────────────────")
    print(f"  Open in your browser: {url}")
    print(f"  Press Ctrl+C to stop\n")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
    server.server_close()
    return 0


def main() -> int:
    from user_friendly_errors import wrap_main
    return wrap_main(run, "running web interface")


if __name__ == "__main__":
    sys.exit(main())
