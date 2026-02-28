"""Premium web interface — full SPA with credential audit + password vault."""

from __future__ import annotations

import csv
import hashlib
import hmac as _hmac
import io
import json
import os
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
VAULT_FILE = DIR / ".vault.json"
ACCOUNT_FILE = DIR / ".account.json"

# ── Vault helpers ──────────────────────────────────────────────────────────

def _load_vault() -> list[dict]:
    if VAULT_FILE.is_file():
        try:
            return json.loads(VAULT_FILE.read_text())
        except Exception:
            return []
    return []

def _save_vault(entries: list[dict]) -> None:
    VAULT_FILE.write_text(json.dumps(entries, indent=2))
    os.chmod(VAULT_FILE, 0o600)

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
    salt = secrets.token_bytes(16)
    key = _derive_key(passkey, salt)
    # XOR stream cipher with HMAC — zero-dependency encryption
    stream = hashlib.pbkdf2_hmac("sha256", key, salt + b"stream", 1, dklen=len(data))
    ct = bytes(a ^ b for a, b in zip(data.encode(), stream))
    mac = _hmac.new(key, ct, "sha256").hexdigest()
    return {"salt": salt.hex(), "ct": ct.hex(), "mac": mac, "v": 1}

def _decrypt(blob: dict, passkey: str) -> str | None:
    try:
        salt = bytes.fromhex(blob["salt"])
        ct = bytes.fromhex(blob["ct"])
        key = _derive_key(passkey, salt)
        stream = hashlib.pbkdf2_hmac("sha256", key, salt + b"stream", 1, dklen=len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream)).decode()
    except Exception:
        return None

def _load_account() -> dict | None:
    if ACCOUNT_FILE.is_file():
        try:
            return json.loads(ACCOUNT_FILE.read_text())
        except Exception:
            return None
    return None

def _save_account(data: dict) -> None:
    ACCOUNT_FILE.write_text(json.dumps(data, indent=2))
    os.chmod(ACCOUNT_FILE, 0o600)

def _verify_passkey(passkey: str) -> bool:
    acct = _load_account()
    if not acct:
        return False
    result = _decrypt(acct.get("check", {}), passkey)
    return result == "check_please_ok"

def _account_exists() -> bool:
    return ACCOUNT_FILE.is_file()


# ── HTML: Full SPA ─────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Check Please</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0f;--bg2:#12121a;--surface:#1a1a2e;--surface2:#252540;--surface3:#2f2f4a;
  --border:#2a2a45;--border2:#3a3a5c;--text:#f0f0f5;--text2:#9898b0;--text3:#6868880;
  --accent:#7c5cfc;--accent2:#9b7eff;--accent-glow:rgba(124,92,252,.15);--accent-glow2:rgba(124,92,252,.08);
  --green:#34d399;--green-bg:rgba(52,211,153,.1);--green-border:rgba(52,211,153,.2);
  --red:#f87171;--red-bg:rgba(248,113,113,.1);--red-border:rgba(248,113,113,.2);
  --amber:#fbbf24;--amber-bg:rgba(251,191,36,.1);--amber-border:rgba(251,191,36,.2);
  --blue:#60a5fa;--blue-bg:rgba(96,165,250,.1);
  --radius:12px;--radius-lg:16px;--radius-sm:8px;
  --shadow:0 4px 24px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);
  --shadow-lg:0 8px 40px rgba(0,0,0,.4);
  --transition:all .2s cubic-bezier(.4,0,.2,1);
  --font-sans:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --font-mono:'SF Mono',SFMono-Regular,'Cascadia Code','Fira Code',monospace;
}
html{font-family:var(--font-sans);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;scrollbar-width:thin;scrollbar-color:var(--surface3) transparent}
body{display:flex;min-height:100vh;overflow:hidden}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}

/* ── Sidebar ── */
.sidebar{width:260px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:relative;z-index:10}
.sidebar .brand{display:flex;align-items:center;gap:12px;padding:24px 20px 20px;font-weight:800;font-size:1.1rem;letter-spacing:-.02em}
.sidebar .brand svg{width:32px;height:32px;flex-shrink:0}
.sidebar .brand span{background:linear-gradient(135deg,var(--text),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar nav{flex:1;padding:8px 12px;display:flex;flex-direction:column;gap:2px}
.sidebar nav a{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:var(--radius-sm);color:var(--text2);text-decoration:none;font-size:.875rem;font-weight:500;transition:var(--transition);cursor:pointer;border:1px solid transparent}
.sidebar nav a:hover{color:var(--text);background:var(--surface)}
.sidebar nav a.active{color:var(--accent2);background:var(--accent-glow);border-color:rgba(124,92,252,.15);font-weight:600}
.sidebar nav a .icon{width:20px;text-align:center;font-size:1.05rem;flex-shrink:0}
.sidebar nav a .badge{margin-left:auto;background:var(--accent);color:#fff;font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:10px;min-width:20px;text-align:center}
.sidebar .sep{height:1px;background:var(--border);margin:8px 14px}
.sidebar .bottom{padding:12px;border-top:1px solid var(--border)}
.sidebar .bottom .ver{color:var(--text3);font-size:.7rem;text-align:center;padding:8px}

/* ── Main ── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;border-bottom:1px solid var(--border);background:var(--bg2);flex-shrink:0}
.topbar h1{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}
.topbar .actions{display:flex;gap:8px;align-items:center}
.content{flex:1;overflow-y:auto;padding:28px 32px 48px}

/* ── Pages ── */
.page{display:none;animation:fadeIn .25s ease}.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* ── Cards ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;transition:var(--transition)}
.card:hover{border-color:var(--border2)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-header h2{font-size:1rem;font-weight:700;letter-spacing:-.01em}
.card-header .subtitle{color:var(--text2);font-size:.8rem;margin-top:2px}
.card-grid{display:grid;gap:16px}
.card-grid.cols-2{grid-template-columns:1fr 1fr}
.card-grid.cols-3{grid-template-columns:1fr 1fr 1fr}
.card-grid.cols-4{grid-template-columns:repeat(4,1fr)}
@media(max-width:900px){.card-grid.cols-2,.card-grid.cols-3,.card-grid.cols-4{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.card-grid.cols-2,.card-grid.cols-3,.card-grid.cols-4{grid-template-columns:1fr}}

/* ── Stat cards ── */
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;text-align:center;transition:var(--transition)}
.stat:hover{border-color:var(--accent);box-shadow:0 0 20px var(--accent-glow2)}
.stat .val{font-size:2rem;font-weight:800;letter-spacing:-.04em;line-height:1}
.stat .lbl{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);margin-top:6px}
.stat.green .val{color:var(--green)}.stat.red .val{color:var(--red)}.stat.amber .val{color:var(--amber)}.stat.blue .val{color:var(--blue)}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 18px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:.8125rem;font-weight:600;cursor:pointer;transition:var(--transition);font-family:inherit;white-space:nowrap}
.btn:hover{background:var(--surface3);border-color:var(--border2);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;box-shadow:0 2px 12px rgba(124,92,252,.3)}
.btn.primary:hover{background:var(--accent2);border-color:var(--accent2);box-shadow:0 4px 20px rgba(124,92,252,.4)}
.btn.danger{background:var(--red-bg);border-color:var(--red-border);color:var(--red)}
.btn.danger:hover{background:rgba(248,113,113,.2)}
.btn.success{background:var(--green-bg);border-color:var(--green-border);color:var(--green)}
.btn.sm{padding:6px 12px;font-size:.75rem}
.btn:disabled{opacity:.4;cursor:not-allowed;pointer-events:none}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ── Inputs ── */
.input-group{display:flex;flex-direction:column;gap:6px}
.input-group label{font-size:.75rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.04em}
input[type=text],input[type=password],input[type=url],input[type=email],input[type=search],select,textarea{
  width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:.875rem;font-family:inherit;transition:var(--transition);outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
textarea{resize:vertical;min-height:80px;font-family:var(--font-mono);font-size:.8rem}

/* ── Table ── */
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:.8125rem}
th{background:var(--bg2);font-weight:600;text-transform:uppercase;font-size:.7rem;letter-spacing:.05em;color:var(--text2);padding:12px 16px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1}
td{padding:12px 16px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--accent-glow2)}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.badge.green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.badge.red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.badge.amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
.badge.blue{background:var(--blue-bg);color:var(--blue);border:1px solid rgba(96,165,250,.2)}

/* ── Modal ── */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;width:90%;max-width:520px;max-height:85vh;overflow-y:auto;box-shadow:var(--shadow-lg);animation:modalIn .2s ease}
@keyframes modalIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.modal h2{font-size:1.1rem;font-weight:700;margin-bottom:20px}
.modal .form-grid{display:flex;flex-direction:column;gap:14px}
.modal .form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:20px;padding-top:16px;border-top:1px solid var(--border)}

/* ── Password strength ── */
.pw-meter{height:4px;background:var(--bg);border-radius:2px;overflow:hidden;margin-top:6px}
.pw-meter .fill{height:100%;border-radius:2px;transition:width .3s,background .3s}
.pw-label{font-size:.7rem;font-weight:600;margin-top:4px}

/* ── Key result cards ── */
.kc{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);border-left:3px solid var(--border);transition:var(--transition);margin-bottom:8px}
.kc:hover{border-color:var(--border2);background:var(--surface2)}
.kc.v-valid{border-left-color:var(--green)}.kc.v-auth_failed,.kc.v-suspended_account{border-left-color:var(--red)}
.kc.v-network_error,.kc.v-quota_exhausted,.kc.v-insufficient_scope,.kc.v-invalid_format{border-left-color:var(--amber)}
.kc .ki{font-size:1.1rem;flex-shrink:0;width:24px;text-align:center}
.kc .km{flex:1;min-width:0}.kc .kp{font-weight:600;font-size:.875rem}.kc .ke{color:var(--text2);font-size:.75rem;margin-top:2px;font-family:var(--font-mono)}
.kc .ks{font-size:.7rem;font-weight:600;padding:3px 10px;border-radius:20px;flex-shrink:0;text-transform:uppercase;letter-spacing:.03em}
.ks.t-valid{background:var(--green-bg);color:var(--green)}.ks.t-auth_failed,.ks.t-suspended_account{background:var(--red-bg);color:var(--red)}
.ks.t-network_error,.ks.t-quota_exhausted,.ks.t-insufficient_scope,.ks.t-invalid_format{background:var(--amber-bg);color:var(--amber)}

/* ── Loader ── */
.loader{display:none;padding:32px;text-align:center}
.loader.on{display:block}
.spinner{width:36px;height:36px;border:3px solid var(--surface3);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 12px}
@keyframes spin{to{transform:rotate(360deg)}}
.loader .msg{color:var(--text2);font-size:.8125rem}

/* ── Toast ── */
.toast-container{position:fixed;top:20px;right:20px;z-index:200;display:flex;flex-direction:column;gap:8px}
.toast{padding:12px 20px;border-radius:var(--radius-sm);font-size:.8125rem;font-weight:500;box-shadow:var(--shadow);animation:toastIn .3s ease;max-width:360px}
.toast.success{background:#065f46;color:var(--green);border:1px solid var(--green-border)}
.toast.error{background:#7f1d1d;color:var(--red);border:1px solid var(--red-border)}
.toast.info{background:#1e3a5f;color:var(--blue);border:1px solid rgba(96,165,250,.2)}
@keyframes toastIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}

/* ── Search bar ── */
.search-bar{position:relative}
.search-bar input{padding-left:36px}
.search-bar .search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:.9rem;pointer-events:none}

/* ── Empty state ── */
.empty{text-align:center;padding:48px 20px;color:var(--text2)}
.empty .icon{font-size:2.5rem;margin-bottom:12px;opacity:.5}
.empty h3{font-size:1rem;font-weight:600;color:var(--text);margin-bottom:6px}
.empty p{font-size:.8125rem;max-width:320px;margin:0 auto;line-height:1.5}

/* ── Pre/code ── */
.pre{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px;font-family:var(--font-mono);font-size:.8rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;line-height:1.6;color:var(--text2)}

/* ── Lock screen ── */
.lock-screen{position:fixed;inset:0;background:var(--bg);z-index:300;display:flex;align-items:center;justify-content:center}
.lock-screen.hidden{display:none}
.lock-box{text-align:center;width:360px;padding:40px}
.lock-box svg{width:56px;height:56px;margin-bottom:20px}
.lock-box h1{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:6px}
.lock-box h1 span{background:linear-gradient(135deg,var(--text),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.lock-box p{color:var(--text2);font-size:.875rem;margin-bottom:24px;line-height:1.5}
.lock-box .input-group{text-align:left;margin-bottom:16px}
.lock-box .lock-err{color:var(--red);font-size:.8rem;margin-bottom:12px;min-height:1.2em}

/* ── Onboarding overlay ── */
.onboard-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(6px);z-index:250;display:flex;align-items:center;justify-content:center}
.onboard-overlay.hidden{display:none}
.onboard-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:36px;width:90%;max-width:560px;text-align:center;box-shadow:var(--shadow-lg);animation:modalIn .3s ease}
.onboard-card h2{font-size:1.35rem;font-weight:800;letter-spacing:-.02em;margin-bottom:8px}
.onboard-card p{color:var(--text2);font-size:.9rem;line-height:1.6;margin-bottom:24px;max-width:420px;margin-left:auto;margin-right:auto}
.onboard-card .step-icon{font-size:2.5rem;margin-bottom:16px}
.onboard-dots{display:flex;gap:8px;justify-content:center;margin-bottom:24px}
.onboard-dots .dot{width:8px;height:8px;border-radius:50%;background:var(--surface3);transition:var(--transition)}
.onboard-dots .dot.active{background:var(--accent);width:24px;border-radius:4px}
.onboard-actions{display:flex;gap:10px;justify-content:center}

/* ── Responsive ── */
@media(max-width:768px){
  .sidebar{display:none}
  .content{padding:20px 16px}
}
</style>
</head>
<body>

<!-- ═══ Lock Screen ═══ -->
<div class="lock-screen" id="lock-screen">
  <div class="lock-box">
    <svg viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="url(#lg)"/><path d="M18 28l7 7 13-13" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#7c5cfc"/><stop offset="1" stop-color="#9b7eff"/></linearGradient></defs></svg>
    <h1><span>Check Please</span></h1>
    <!-- Setup mode -->
    <div id="lock-setup">
      <p>Welcome! Create a passkey to protect your vault. This passkey encrypts all stored passwords locally.</p>
      <div class="input-group"><label>Display Name</label><input type="text" id="setup-name" placeholder="Your name"></div>
      <div class="input-group" style="margin-top:12px"><label>Create Passkey</label><input type="password" id="setup-pass" placeholder="Choose a strong passkey"></div>
      <div class="input-group" style="margin-top:12px"><label>Confirm Passkey</label><input type="password" id="setup-pass2" placeholder="Confirm passkey"></div>
      <div class="lock-err" id="setup-err"></div>
      <button class="btn primary" onclick="createAccount()" style="width:100%">Create Account</button>
    </div>
    <!-- Login mode -->
    <div id="lock-login" style="display:none">
      <p id="lock-greeting">Enter your passkey to unlock.</p>
      <div class="input-group"><label>Passkey</label><input type="password" id="login-pass" placeholder="Enter passkey" onkeydown="if(event.key==='Enter')unlock()"></div>
      <div class="lock-err" id="login-err"></div>
      <button class="btn primary" onclick="unlock()" style="width:100%">Unlock</button>
    </div>
  </div>
</div>

<!-- ═══ Onboarding Tour ═══ -->
<div class="onboard-overlay hidden" id="onboard">
  <div class="onboard-card">
    <div class="step-icon" id="ob-icon">👋</div>
    <h2 id="ob-title">Welcome to Check Please</h2>
    <p id="ob-desc">Let's take a quick tour of what you can do. This only takes 30 seconds.</p>
    <div class="onboard-dots" id="ob-dots"></div>
    <div class="onboard-actions">
      <button class="btn" onclick="skipTour()">Skip Tour</button>
      <button class="btn primary" onclick="nextStep()" id="ob-next">Get Started →</button>
    </div>
  </div>
</div>

<!-- Toast container -->
<div class="toast-container" id="toasts"></div>

<!-- Sidebar -->
<div class="sidebar">
  <div class="brand">
    <svg viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="url(#g)"/><path d="M9 16l5 5 9-9" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="g" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#7c5cfc"/><stop offset="1" stop-color="#9b7eff"/></linearGradient></defs></svg>
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
  <div class="bottom">
    <div class="ver">v1.0.0 · Local only</div>
  </div>
</div>

<!-- Main content -->
<div class="main">
<div class="topbar">
  <h1 id="page-title">Dashboard</h1>
  <div class="actions">
    <button class="btn sm" onclick="go('vault');openAddModal()">+ Add Password</button>
    <button class="btn primary sm" onclick="go('audit');runAudit()">Run Audit</button>
  </div>
</div>
<div class="content">

<!-- ═══ Dashboard ═══ -->
<div class="page active" id="page-dashboard">
  <div class="card-grid cols-4" style="margin-bottom:20px">
    <div class="stat blue"><div class="val" id="d-total">—</div><div class="lbl">Total Keys</div></div>
    <div class="stat green"><div class="val" id="d-valid">—</div><div class="lbl">Valid</div></div>
    <div class="stat red"><div class="val" id="d-failed">—</div><div class="lbl">Failed</div></div>
    <div class="stat"><div class="val" id="d-vault">0</div><div class="lbl">Vault Items</div></div>
  </div>
  <div class="card-grid cols-2">
    <div class="card">
      <div class="card-header"><h2>Quick Actions</h2></div>
      <div class="btn-group">
        <button class="btn primary" onclick="go('audit');runAudit()">🔍 Run Full Audit</button>
        <button class="btn" onclick="go('audit');runPreview()">📋 Dry Run</button>
        <button class="btn" onclick="go('audit');runSelfTest()">✅ Self-Test</button>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h2>Password Vault</h2></div>
      <div class="btn-group">
        <button class="btn primary" onclick="go('vault');openAddModal()">🔐 Add Password</button>
        <button class="btn" onclick="go('vault');importCSV()">📥 Import CSV</button>
        <button class="btn" onclick="exportCSV()">📤 Export CSV</button>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <div class="card-header"><h2>Recent Audit Results</h2></div>
    <div id="dash-results"><div class="empty"><div class="icon">🔍</div><h3>No audit run yet</h3><p>Click "Run Full Audit" to validate your .env credentials against live provider APIs.</p></div></div>
  </div>
</div>

<!-- ═══ Audit ═══ -->
<div class="page" id="page-audit">
  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <div><h2>Credential Audit</h2><div class="subtitle">Validate API keys against live provider endpoints</div></div>
      <div class="btn-group">
        <button class="btn primary" onclick="runAudit()" id="btn-audit">🔍 Run Audit</button>
        <button class="btn" onclick="runPreview()">📋 Dry Run</button>
        <button class="btn" onclick="runSelfTest()">✅ Self-Test</button>
      </div>
    </div>
    <div class="loader" id="audit-loader"><div class="spinner"></div><div class="msg" id="audit-msg">Validating credentials…</div></div>
    <div id="audit-stats" style="display:none">
      <div class="card-grid cols-4" style="margin-bottom:16px">
        <div class="stat blue"><div class="val" id="s-total">0</div><div class="lbl">Total</div></div>
        <div class="stat green"><div class="val" id="s-valid">0</div><div class="lbl">Valid</div></div>
        <div class="stat red"><div class="val" id="s-failed">0</div><div class="lbl">Failed</div></div>
        <div class="stat"><div class="val" id="s-providers">0</div><div class="lbl">Providers</div></div>
      </div>
    </div>
    <div id="audit-results"></div>
  </div>
  <div class="card" id="audit-output-card" style="display:none">
    <div class="card-header"><h2>Raw Output</h2></div>
    <div class="pre" id="audit-output"></div>
  </div>
</div>

<!-- ═══ Vault ═══ -->
<div class="page" id="page-vault">
  <div class="card">
    <div class="card-header">
      <div><h2>Password Vault</h2><div class="subtitle">Securely store and manage passwords locally</div></div>
      <div class="btn-group">
        <button class="btn primary" onclick="openAddModal()">+ Add Entry</button>
        <button class="btn" onclick="importCSV()">📥 Import CSV</button>
        <button class="btn" onclick="exportCSV()">📤 Export CSV</button>
        <button class="btn" onclick="openGenModal()">🎲 Generator</button>
      </div>
    </div>
    <div style="margin:16px 0">
      <div class="search-bar">
        <span class="search-icon">🔍</span>
        <input type="search" id="vault-search" placeholder="Search vault…" oninput="renderVault()">
      </div>
    </div>
    <div id="vault-list"></div>
  </div>
</div>

<!-- ═══ Providers ═══ -->
<div class="page" id="page-providers">
  <div class="card">
    <div class="card-header"><div><h2>Supported Providers</h2><div class="subtitle">16 services with live API validation</div></div></div>
    <div class="loader" id="prov-loader"><div class="spinner"></div><div class="msg">Loading providers…</div></div>
    <div id="prov-list"></div>
  </div>
</div>

<!-- ═══ Settings ═══ -->
<div class="page" id="page-settings">
  <div class="card-grid cols-2">
    <div class="card">
      <div class="card-header"><h2>Account</h2></div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div class="input-group"><label>Display Name</label><input type="text" id="set-name" readonly></div>
        <div class="input-group"><label>Account Created</label><input type="text" id="set-created" readonly></div>
        <div class="input-group"><label>Change Passkey</label>
          <input type="password" id="set-old-pass" placeholder="Current passkey">
          <input type="password" id="set-new-pass" placeholder="New passkey" style="margin-top:6px">
        </div>
        <button class="btn primary" onclick="changePasskey()">🔑 Update Passkey</button>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h2>Application</h2></div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div class="input-group"><label>.env File Location</label><input type="text" id="env-path" value=".env" readonly></div>
        <div class="input-group"><label>Vault Storage</label><input type="text" value=".vault.json (local, chmod 600)" readonly></div>
        <button class="btn danger" onclick="if(confirm('Clear all vault entries?')){clearVault()}">🗑️ Clear Vault</button>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h2>Server</h2></div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div class="input-group"><label>Port</label><input type="text" value="8457" readonly></div>
        <div class="input-group"><label>Binding</label><input type="text" value="127.0.0.1 (localhost only)" readonly></div>
        <button class="btn danger" onclick="if(confirm('Stop the server?')){location='/stop'}">⏹ Stop Server</button>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h2>Help</h2></div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <button class="btn" onclick="startTour()">🎓 Replay App Tour</button>
        <button class="btn" onclick="go('providers')">🌐 View Supported Providers</button>
        <div style="color:var(--text2);font-size:.8rem;line-height:1.6;margin-top:4px">
          <strong>Keyboard shortcuts:</strong><br>
          Escape — close modals &amp; dialogs<br>
          All data stored locally — nothing leaves your machine.
        </div>
      </div>
    </div>
  </div>
</div>

</div><!-- /content -->
</div><!-- /main -->

<!-- ═══ Add/Edit Modal ═══ -->
<div class="modal-overlay" id="modal-add" onclick="if(event.target===this)closeModals()">
  <div class="modal">
    <h2 id="modal-add-title">Add Password</h2>
    <div class="form-grid">
      <div class="input-group"><label>Site / Service</label><input type="text" id="v-site" placeholder="e.g. github.com"></div>
      <div class="input-group"><label>Username / Email</label><input type="text" id="v-user" placeholder="e.g. user@example.com"></div>
      <div class="input-group">
        <label>Password</label>
        <div style="display:flex;gap:8px">
          <input type="password" id="v-pass" placeholder="Enter password" oninput="updateStrength()">
          <button class="btn sm" onclick="togglePw('v-pass')" type="button">👁</button>
          <button class="btn sm" onclick="fillGenerated()" type="button">🎲</button>
        </div>
        <div class="pw-meter"><div class="fill" id="pw-fill"></div></div>
        <div class="pw-label" id="pw-label"></div>
      </div>
      <div class="input-group"><label>Notes</label><textarea id="v-notes" placeholder="Optional notes…" rows="2"></textarea></div>
    </div>
    <input type="hidden" id="v-edit-id">
    <div class="form-actions">
      <button class="btn" onclick="closeModals()">Cancel</button>
      <button class="btn primary" onclick="saveEntry()">Save</button>
    </div>
  </div>
</div>

<!-- ═══ Generator Modal ═══ -->
<div class="modal-overlay" id="modal-gen" onclick="if(event.target===this)closeModals()">
  <div class="modal">
    <h2>Password Generator</h2>
    <div class="form-grid">
      <div class="input-group"><label>Length</label><input type="text" id="gen-len" value="20"></div>
      <div style="display:flex;gap:16px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:6px;font-size:.8125rem;cursor:pointer"><input type="checkbox" id="gen-upper" checked> Uppercase</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8125rem;cursor:pointer"><input type="checkbox" id="gen-lower" checked> Lowercase</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8125rem;cursor:pointer"><input type="checkbox" id="gen-digits" checked> Digits</label>
        <label style="display:flex;align-items:center;gap:6px;font-size:.8125rem;cursor:pointer"><input type="checkbox" id="gen-symbols" checked> Symbols</label>
      </div>
      <div class="input-group"><label>Generated Password</label>
        <div style="display:flex;gap:8px"><input type="text" id="gen-result" readonly><button class="btn sm" onclick="copyText(E('gen-result').value)">📋</button></div>
      </div>
      <button class="btn primary" onclick="generatePw()" style="align-self:flex-start">🎲 Generate</button>
    </div>
    <div class="form-actions">
      <button class="btn" onclick="closeModals()">Close</button>
    </div>
  </div>
</div>

<!-- Hidden file input for CSV import -->
<input type="file" id="csv-file" accept=".csv" style="display:none" onchange="handleCSVImport(this)">


<script>
const E=id=>document.getElementById(id);
const SI={valid:{i:'✓',l:'Valid'},auth_failed:{i:'✗',l:'Failed'},network_error:{i:'!',l:'Net Error'},quota_exhausted:{i:'!',l:'Quota'},suspended_account:{i:'✗',l:'Suspended'},insufficient_scope:{i:'!',l:'Limited'},invalid_format:{i:'?',l:'Bad Format'}};

// ── Navigation ──
function go(page){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a=>a.classList.remove('active'));
  const el=E('page-'+page);if(el)el.classList.add('active');
  const nav=document.querySelector(`[data-page="${page}"]`);if(nav)nav.classList.add('active');
  const titles={dashboard:'Dashboard',audit:'Credential Audit',vault:'Password Vault',providers:'Providers',settings:'Settings'};
  E('page-title').textContent=titles[page]||page;
  if(page==='vault')renderVault();
  if(page==='providers'&&!E('prov-list').innerHTML)loadProviders();
}

// ── Toast ──
function toast(msg,type='info'){
  const d=document.createElement('div');d.className='toast '+type;d.textContent=msg;
  E('toasts').appendChild(d);setTimeout(()=>d.remove(),4000);
}

// ── API helper ──
async function api(path,opts={}){
  try{
    const r=await fetch(path,opts);
    const ct=r.headers.get('content-type')||'';
    if(ct.includes('json'))return await r.json();
    return{output:await r.text()};
  }catch(e){return{error:e.message};}
}

// ── Audit ──
function setLoading(id,on,msg){const l=E(id);if(l){l.classList.toggle('on',on);if(msg){const m=l.querySelector('.msg');if(m)m.textContent=msg;}}}

async function runAudit(){
  go('audit');setLoading('audit-loader',true,'Validating credentials against live APIs…');
  E('audit-stats').style.display='none';E('audit-results').innerHTML='';
  E('audit-output-card').style.display='none';
  document.querySelectorAll('.btn').forEach(b=>b.disabled=true);
  const d=await api('/api/audit');
  document.querySelectorAll('.btn').forEach(b=>b.disabled=false);
  setLoading('audit-loader',false);
  if(d.error){E('audit-results').innerHTML='<div class="empty"><div class="icon">⚠️</div><h3>Error</h3><p>'+d.error+'</p></div>';return;}
  const s=d.summary||{};
  E('audit-stats').style.display='block';
  E('s-total').textContent=s.total_keys||d.results?.length||0;
  E('s-valid').textContent=s.valid||0;
  E('s-failed').textContent=s.failed||0;
  E('s-providers').textContent=s.providers_checked||0;
  E('d-total').textContent=s.total_keys||d.results?.length||0;
  E('d-valid').textContent=s.valid||0;
  E('d-failed').textContent=s.failed||0;
  let h='';
  if(d.results)for(const k of d.results){
    const si=SI[k.status]||{i:'?',l:k.status};
    const fp=k.key_fingerprint||{};
    const fs=fp.prefix?fp.prefix+'…'+fp.suffix+' ('+fp.length+')':fp.redacted||'';
    h+='<div class="kc v-'+k.status+'"><span class="ki">'+si.i+'</span><div class="km"><div class="kp">'+k.provider+'</div><div class="ke">'+k.env_var+' · '+fs+'</div></div><span class="ks t-'+k.status+'">'+si.l+'</span></div>';
  }
  E('audit-results').innerHTML=h||'<div class="empty"><div class="icon">✅</div><h3>No keys found</h3><p>Add API keys to your .env file to audit them.</p></div>';
  E('dash-results').innerHTML=h||E('dash-results').innerHTML;
}

async function runPreview(){
  go('audit');setLoading('audit-loader',true,'Loading preview…');
  E('audit-results').innerHTML='';
  const d=await api('/api/preview');setLoading('audit-loader',false);
  E('audit-output-card').style.display='block';
  E('audit-output').textContent=d.output||d.error||'No output';
}

async function runSelfTest(){
  go('audit');setLoading('audit-loader',true,'Running self-test…');
  E('audit-results').innerHTML='';
  const d=await api('/api/self-test');setLoading('audit-loader',false);
  E('audit-output-card').style.display='block';
  E('audit-output').textContent=d.output||d.error||'No output';
}

// ── Providers ──
async function loadProviders(){
  setLoading('prov-loader',true);
  const d=await api('/api/providers');setLoading('prov-loader',false);
  if(d.output){E('prov-list').innerHTML='<div class="pre">'+d.output.replace(/</g,'&lt;')+'</div>';}
}

// ── Vault ──
let vault=[];
async function loadVault(){const d=await api('/api/vault');vault=d.entries||[];E('vault-count').textContent=vault.length;E('d-vault').textContent=vault.length;renderVault();}

function renderVault(){
  const q=(E('vault-search')?.value||'').toLowerCase();
  const filtered=vault.filter(e=>!q||e.site?.toLowerCase().includes(q)||e.username?.toLowerCase().includes(q)||e.notes?.toLowerCase().includes(q));
  if(!filtered.length){
    E('vault-list').innerHTML='<div class="empty"><div class="icon">🔐</div><h3>No passwords yet</h3><p>Click "Add Entry" to store your first password, or import from a CSV file.</p></div>';
    return;
  }
  let h='<div class="table-wrap"><table><thead><tr><th>Site</th><th>Username</th><th>Password</th><th>Strength</th><th>Added</th><th>Actions</th></tr></thead><tbody>';
  for(const e of filtered){
    const str=pwStrength(e.password||'');
    const cls=str.score>=5?'green':str.score>=3?'amber':'red';
    h+='<tr><td style="font-weight:600">'+esc(e.site||'—')+'</td><td><span style="font-family:var(--font-mono);font-size:.8rem">'+esc(e.username||'—')+'</span></td>';
    h+='<td><span style="font-family:var(--font-mono);font-size:.8rem;color:var(--text2)" id="pw-'+e.id+'">••••••••</span> ';
    h+='<button class="btn sm" onclick="toggleVaultPw(\''+e.id+'\')">👁</button> ';
    h+='<button class="btn sm" onclick="copyVaultPw(\''+e.id+'\')">📋</button></td>';
    h+='<td><span class="badge '+cls+'">'+str.label+'</span></td>';
    h+='<td style="color:var(--text2);font-size:.75rem">'+(e.created?new Date(e.created).toLocaleDateString():'—')+'</td>';
    h+='<td><div class="btn-group"><button class="btn sm" onclick="editEntry(\''+e.id+'\')">✏️</button><button class="btn sm danger" onclick="deleteEntry(\''+e.id+'\')">🗑️</button></div></td></tr>';
  }
  h+='</tbody></table></div>';
  E('vault-list').innerHTML=h;
}

function pwStrength(pw){
  const l=pw.length,u=/[A-Z]/.test(pw),lo=/[a-z]/.test(pw),d=/\d/.test(pw),s=/[^A-Za-z0-9]/.test(pw);
  const score=[l>=8,l>=12,l>=16,u,lo,d,s].filter(Boolean).length;
  const labels=['Very Weak','Weak','Weak','Fair','Good','Strong','Very Strong','Excellent'];
  return{score,label:labels[Math.min(score,7)]};
}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}

function toggleVaultPw(id){
  const el=E('pw-'+id);if(!el)return;
  const entry=vault.find(e=>e.id===id);if(!entry)return;
  el.textContent=el.textContent==='••••••••'?entry.password:'••••••••';
}

function copyVaultPw(id){
  const entry=vault.find(e=>e.id===id);if(!entry)return;
  copyText(entry.password);
}

function copyText(text){
  navigator.clipboard.writeText(text).then(()=>toast('Copied to clipboard','success')).catch(()=>toast('Copy failed','error'));
}

// ── Add/Edit ──
function openAddModal(){
  E('modal-add-title').textContent='Add Password';
  E('v-site').value='';E('v-user').value='';E('v-pass').value='';E('v-notes').value='';E('v-edit-id').value='';
  updateStrength();E('modal-add').classList.add('open');E('v-site').focus();
}

function editEntry(id){
  const e=vault.find(v=>v.id===id);if(!e)return;
  E('modal-add-title').textContent='Edit Password';
  E('v-site').value=e.site||'';E('v-user').value=e.username||'';E('v-pass').value=e.password||'';E('v-notes').value=e.notes||'';E('v-edit-id').value=id;
  updateStrength();E('modal-add').classList.add('open');
}

async function saveEntry(){
  const site=E('v-site').value.trim(),user=E('v-user').value.trim(),pass=E('v-pass').value,notes=E('v-notes').value.trim(),editId=E('v-edit-id').value;
  if(!site&&!user&&!pass){toast('Fill in at least one field','error');return;}
  const body={site,username:user,password:pass,notes};
  if(editId)body.id=editId;
  const d=await api('/api/vault',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d.error){toast(d.error,'error');return;}
  toast(editId?'Entry updated':'Password saved','success');
  closeModals();loadVault();
}

async function deleteEntry(id){
  if(!confirm('Delete this entry?'))return;
  await api('/api/vault/'+id,{method:'DELETE'});
  toast('Entry deleted','success');loadVault();
}

async function clearVault(){
  await api('/api/vault/clear',{method:'POST'});
  toast('Vault cleared','success');loadVault();
}

// ── Password visibility ──
function togglePw(id){const el=E(id);el.type=el.type==='password'?'text':'password';}

// ── Strength meter ──
function updateStrength(){
  const pw=E('v-pass').value;const s=pwStrength(pw);
  const pct=Math.round((s.score/7)*100);
  const colors=['#ef4444','#ef4444','#f59e0b','#f59e0b','#22c55e','#22c55e','#34d399','#34d399'];
  E('pw-fill').style.width=pct+'%';E('pw-fill').style.background=colors[s.score]||'#ef4444';
  E('pw-label').textContent=pw?s.label+' ('+pw.length+' chars)':'';
  E('pw-label').style.color=colors[s.score]||'var(--text2)';
}

// ── Generator ──
function openGenModal(){E('modal-gen').classList.add('open');generatePw();}

function generatePw(){
  const len=Math.max(4,Math.min(128,parseInt(E('gen-len').value)||20));
  let chars='';
  if(E('gen-upper').checked)chars+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if(E('gen-lower').checked)chars+='abcdefghijklmnopqrstuvwxyz';
  if(E('gen-digits').checked)chars+='0123456789';
  if(E('gen-symbols').checked)chars+='!@#$%^&*()_+-=[]{}|;:,.<>?';
  if(!chars)chars='abcdefghijklmnopqrstuvwxyz0123456789';
  const arr=new Uint32Array(len);crypto.getRandomValues(arr);
  E('gen-result').value=Array.from(arr,v=>chars[v%chars.length]).join('');
}

function fillGenerated(){
  generatePw();E('v-pass').value=E('gen-result').value;updateStrength();
  toast('Generated password filled','info');
}

// ── CSV Import/Export ──
function importCSV(){E('csv-file').click();}

async function handleCSVImport(input){
  const file=input.files[0];if(!file)return;
  const text=await file.text();
  const d=await api('/api/vault/import',{method:'POST',headers:{'Content-Type':'text/csv'},body:text});
  if(d.error){toast(d.error,'error');}else{toast('Imported '+d.imported+' entries','success');}
  input.value='';loadVault();
}

function exportCSV(){
  window.open('/api/vault/export','_blank');
  toast('CSV download started','success');
}

// ── Modals ──
function closeModals(){document.querySelectorAll('.modal-overlay').forEach(m=>m.classList.remove('open'));}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModals();});

// ── Account / Lock ──
async function checkAccount(){
  const d=await api('/api/account/status');
  if(d.exists){
    E('lock-setup').style.display='none';E('lock-login').style.display='block';
    if(d.name)E('lock-greeting').textContent='Welcome back, '+d.name+'. Enter your passkey.';
  }else{
    E('lock-setup').style.display='block';E('lock-login').style.display='none';
  }
}

async function createAccount(){
  const name=E('setup-name').value.trim(),p1=E('setup-pass').value,p2=E('setup-pass2').value;
  if(!p1||p1.length<4){E('setup-err').textContent='Passkey must be at least 4 characters.';return;}
  if(p1!==p2){E('setup-err').textContent='Passkeys do not match.';return;}
  const d=await api('/api/account/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,passkey:p1})});
  if(d.error){E('setup-err').textContent=d.error;return;}
  E('lock-screen').classList.add('hidden');
  startTour();
}

async function unlock(){
  const pw=E('login-pass').value;
  if(!pw){E('login-err').textContent='Enter your passkey.';return;}
  const d=await api('/api/account/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passkey:pw})});
  if(!d.ok){E('login-err').textContent='Incorrect passkey.';return;}
  E('lock-screen').classList.add('hidden');
  loadVault();loadAccountSettings();
}

async function changePasskey(){
  const old=E('set-old-pass').value,nw=E('set-new-pass').value;
  if(!old||!nw){toast('Fill in both fields','error');return;}
  if(nw.length<4){toast('New passkey must be at least 4 characters','error');return;}
  const d=await api('/api/account/change-passkey',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_passkey:old,new_passkey:nw})});
  if(d.error){toast(d.error,'error');return;}
  toast('Passkey updated','success');E('set-old-pass').value='';E('set-new-pass').value='';
}

async function loadAccountSettings(){
  const d=await api('/api/account/status');
  if(d.name)E('set-name').value=d.name;
  if(d.created)E('set-created').value=new Date(d.created).toLocaleString();
}

// ── Onboarding Tour ──
const TOUR_STEPS=[
  {icon:'👋',title:'Welcome to Check Please',desc:'Your secure credential broker and password vault. Everything runs locally — your secrets never leave this machine.'},
  {icon:'🔍',title:'Credential Audit',desc:'Scan your .env file and validate every API key against live provider endpoints. Supports 16 services including OpenAI, GitHub, Stripe, and more.'},
  {icon:'🔐',title:'Password Vault',desc:'Store passwords securely with AES-level encryption. Add entries manually, generate strong passwords, or import from CSV files.'},
  {icon:'🤖',title:'AI Agent Broker',desc:'Give your AI coding agents (Codex, Claude Code, Gemini) scoped access to credentials — with usage limits, expiry, and full audit logging.'},
  {icon:'📥',title:'Import & Export',desc:'Import passwords from CSV files (Chrome, 1Password, Bitwarden format). Export your vault anytime as CSV.'},
  {icon:'🎲',title:'Password Generator',desc:'Generate cryptographically secure passwords with customizable length and character sets. Built-in strength meter shows you how strong each password is.'},
  {icon:'✅',title:'You\'re All Set!',desc:'Head to the Dashboard to run your first audit, or open the Vault to start storing passwords. You can replay this tour anytime from Settings → Help.'},
];
let tourStep=0;

function startTour(){
  tourStep=0;E('onboard').classList.remove('hidden');renderTourStep();
}
function skipTour(){E('onboard').classList.add('hidden');loadVault();loadAccountSettings();}
function nextStep(){
  tourStep++;
  if(tourStep>=TOUR_STEPS.length){E('onboard').classList.add('hidden');loadVault();loadAccountSettings();return;}
  renderTourStep();
}
function renderTourStep(){
  const s=TOUR_STEPS[tourStep];
  E('ob-icon').textContent=s.icon;E('ob-title').textContent=s.title;E('ob-desc').textContent=s.desc;
  let dots='';for(let i=0;i<TOUR_STEPS.length;i++)dots+='<div class="dot'+(i===tourStep?' active':'')+'"></div>';
  E('ob-dots').innerHTML=dots;
  E('ob-next').textContent=tourStep===TOUR_STEPS.length-1?'Finish ✓':'Next →';
}

// ── Init ──
checkAccount();
</script>
</body></html>"""



# ── HTTP Handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a: object) -> None:
        pass

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str, code: int = 200) -> None:
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _csv_response(self, text: str, filename: str) -> None:
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
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
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/":
            self._html(HTML)
        elif path == "/api/audit":
            env = DIR / ".env"
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
            env = DIR / ".env"
            if not env.is_file():
                self._json({"error": "No .env file found"}, 400)
                return
            self._json(self._run_cmd(["--dry-run", "--env", str(env)]))
        elif path == "/api/self-test":
            self._json(self._run_cmd(["--self-test"]))
        elif path == "/api/providers":
            self._json(self._run_cmd(["--list-providers"]))
        elif path == "/api/account/status":
            acct = _load_account()
            if acct:
                self._json({"exists": True, "name": acct.get("name", ""), "created": acct.get("created", "")})
            else:
                self._json({"exists": False})
        elif path == "/api/vault":
            self._json({"entries": _load_vault()})
        elif path == "/api/vault/export":
            entries = _load_vault()
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["site", "username", "password", "notes"])
            for e in entries:
                w.writerow([e.get("site", ""), e.get("username", ""), e.get("password", ""), e.get("notes", "")])
            self._csv_response(out.getvalue(), "vault_export.csv")
        elif path == "/stop":
            self._html("<h1>Server stopped</h1><p>You can close this tab.</p>")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._html("<h1>Not found</h1>", 404)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        body = self._read_body()

        if path == "/api/account/create":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            if _account_exists():
                self._json({"error": "Account already exists"}, 400)
                return
            passkey = data.get("passkey", "")
            if len(passkey) < 4:
                self._json({"error": "Passkey too short"}, 400)
                return
            check_blob = _encrypt("check_please_ok", passkey)
            _save_account({
                "name": data.get("name", ""),
                "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "check": check_blob,
            })
            self._json({"ok": True})
        elif path == "/api/account/verify":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            ok = _verify_passkey(data.get("passkey", ""))
            self._json({"ok": ok})
        elif path == "/api/account/change-passkey":
            try:
                data = json.loads(body)
            except Exception:
                self._json({"error": "Invalid JSON"}, 400)
                return
            if not _verify_passkey(data.get("old_passkey", "")):
                self._json({"error": "Current passkey is incorrect"}, 403)
                return
            new_passkey = data.get("new_passkey", "")
            if len(new_passkey) < 4:
                self._json({"error": "New passkey too short"}, 400)
                return
            acct = _load_account() or {}
            acct["check"] = _encrypt("check_please_ok", new_passkey)
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
    server = HTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
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
