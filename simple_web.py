"""Simple web interface — browser-based UI using built-in http.server."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs

DIR = Path(__file__).resolve().parent
PORT = 8457  # uncommon port to avoid conflicts

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Check Please</title>
<style>
:root{--bg:#09090b;--surface:#18181b;--surface2:#27272a;--border:#3f3f46;--text:#fafafa;--text2:#a1a1aa;--accent:#6366f1;--accent2:#818cf8;--green:#22c55e;--green-bg:rgba(34,197,94,.1);--red:#ef4444;--red-bg:rgba(239,68,68,.1);--amber:#f59e0b;--amber-bg:rgba(245,158,11,.1);--radius:10px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}

/* Layout */
.shell{max-width:960px;margin:0 auto;padding:24px 20px 48px}

/* Nav */
nav{display:flex;align-items:center;justify-content:space-between;padding:16px 0 24px;border-bottom:1px solid var(--border);margin-bottom:32px}
nav .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.15rem;letter-spacing:-.02em}
nav .brand svg{width:28px;height:28px}
nav .links{display:flex;gap:6px}
nav .links a{color:var(--text2);text-decoration:none;font-size:.8125rem;padding:6px 12px;border-radius:6px;transition:all .15s}
nav .links a:hover{color:var(--text);background:var(--surface)}

/* Hero */
.hero{text-align:center;padding:20px 0 36px}
.hero h1{font-size:2.25rem;font-weight:800;letter-spacing:-.04em;line-height:1.15;background:linear-gradient(135deg,var(--text) 0%,var(--accent2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--text2);font-size:1.05rem;margin-top:10px;max-width:480px;margin-left:auto;margin-right:auto;line-height:1.5}
.hero .pill{display:inline-flex;align-items:center;gap:6px;margin-top:14px;padding:5px 14px;border-radius:20px;font-size:.75rem;font-weight:600;letter-spacing:.02em;text-transform:uppercase;background:var(--green-bg);color:var(--green);border:1px solid rgba(34,197,94,.2)}

/* Grid */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:640px){.grid{grid-template-columns:1fr}}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;transition:border-color .2s}
.card:hover{border-color:var(--accent)}
.card.full{grid-column:1/-1}
.card .label{font-size:.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--accent2);margin-bottom:10px}
.card h2{font-size:1.125rem;font-weight:700;letter-spacing:-.02em;margin-bottom:6px}
.card .desc{color:var(--text2);font-size:.875rem;line-height:1.5;margin-bottom:18px}

/* Buttons */
.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:8px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:.8125rem;font-weight:600;cursor:pointer;transition:all .15s;text-decoration:none}
.btn:hover{background:var(--border);border-color:#52525b}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{background:var(--accent2);border-color:var(--accent2)}
.btn:disabled{opacity:.4;cursor:not-allowed;pointer-events:none}

/* Stats row */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:18px;display:none}
.stats .s{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.stats .s .n{font-size:1.5rem;font-weight:800;letter-spacing:-.03em}
.stats .s .l{font-size:.6875rem;color:var(--text2);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.n.c-green{color:var(--green)}.n.c-red{color:var(--red)}

/* Results */
.results-wrap{margin-top:16px;display:none}
.results-pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;white-space:pre-wrap;font-family:'SF Mono',SFMono-Regular,ui-monospace,'Cascadia Code',Menlo,monospace;font-size:.8125rem;max-height:520px;overflow-y:auto;line-height:1.65;color:var(--text2)}

/* Key cards */
.kc{display:flex;align-items:center;gap:14px;padding:12px 16px;margin:6px 0;background:var(--bg);border:1px solid var(--border);border-radius:8px;border-left:3px solid var(--border);transition:border-color .15s}
.kc:hover{border-color:var(--accent)}
.kc.v-valid{border-left-color:var(--green)}
.kc.v-auth_failed,.kc.v-suspended_account{border-left-color:var(--red)}
.kc.v-network_error,.kc.v-quota_exhausted,.kc.v-insufficient_scope,.kc.v-invalid_format{border-left-color:var(--amber)}
.kc .ki{font-size:1.1rem;flex-shrink:0;width:24px;text-align:center}
.kc .km{flex:1;min-width:0}
.kc .kp{font-weight:600;font-size:.875rem}
.kc .ke{color:var(--text2);font-size:.75rem;margin-top:1px;font-family:monospace}
.kc .ks{font-size:.6875rem;font-weight:600;padding:3px 10px;border-radius:20px;flex-shrink:0;text-transform:uppercase;letter-spacing:.03em}
.ks.t-valid{background:var(--green-bg);color:var(--green)}
.ks.t-auth_failed,.ks.t-suspended_account{background:var(--red-bg);color:var(--red)}
.ks.t-network_error,.ks.t-quota_exhausted,.ks.t-insufficient_scope,.ks.t-invalid_format{background:var(--amber-bg);color:var(--amber)}

/* Tip */
.tip{border:1px solid rgba(34,197,94,.2);background:var(--green-bg);border-radius:8px;padding:14px 16px;margin-top:12px;font-size:.8125rem;line-height:1.6;color:var(--green)}
.tip.warn{border-color:rgba(245,158,11,.2);background:var(--amber-bg);color:var(--amber)}

/* Loading */
.loader{display:none;text-align:center;padding:20px 0}
.loader .bar{width:200px;height:3px;background:var(--surface2);border-radius:2px;margin:0 auto 10px;overflow:hidden}
.loader .bar::after{content:'';display:block;width:40%;height:100%;background:var(--accent);border-radius:2px;animation:slide 1s ease-in-out infinite}
@keyframes slide{0%{transform:translateX(-100%)}100%{transform:translateX(350%)}}
.loader .lt{color:var(--text2);font-size:.8125rem}

/* Help links */
.help-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
@media(max-width:640px){.help-grid{grid-template-columns:1fr 1fr}}
.help-grid a{display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:8px;background:var(--bg);border:1px solid var(--border);color:var(--text);text-decoration:none;font-size:.8125rem;font-weight:500;transition:all .15s}
.help-grid a:hover{border-color:var(--accent);color:var(--accent2)}
.help-grid a .hi{font-size:1rem}

/* Footer */
footer{text-align:center;padding:24px 0 0;margin-top:40px;border-top:1px solid var(--border);color:var(--text2);font-size:.75rem}
footer a{color:var(--text2);text-decoration:none;transition:color .15s}
footer a:hover{color:var(--text)}
</style>
</head>
<body>
<div class="shell">
<nav>
  <div class="brand">
    <svg viewBox="0 0 28 28" fill="none"><rect width="28" height="28" rx="6" fill="#6366f1"/><path d="M8 14l4 4 8-8" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
    Check Please
  </div>
  <div class="links">
    <a href="/help/security">Security</a>
    <a href="/help/getting-started">Docs</a>
    <a href="/stop" onclick="return confirm('Stop server?')">Stop</a>
  </div>
</nav>

<div class="hero">
  <h1>Credential Audit Pipeline</h1>
  <p>Validate your API keys against live provider endpoints. Private, local, instant.</p>
  <div class="pill">● Local only — keys never leave your machine</div>
</div>

<div class="grid">
<div class="card full">
  <div class="label">Audit</div>
  <h2>Validate Credentials</h2>
  <div class="desc">Scan your .env and verify each key against its provider API. Takes 10–30s.</div>
  <div class="actions">
    <button class="btn primary" onclick="runAudit()">Run Audit</button>
    <button class="btn" onclick="runPreview()">Dry Run</button>
    <button class="btn" onclick="runSelfTest()">Self-Test</button>
  </div>
  <div class="loader" id="loader"><div class="bar"></div><div class="lt" id="loader-text">Checking keys…</div></div>
  <div class="stats" id="stats">
    <div class="s"><div class="n" id="s-total">-</div><div class="l">Total</div></div>
    <div class="s"><div class="n c-green" id="s-valid">-</div><div class="l">Valid</div></div>
    <div class="s"><div class="n c-red" id="s-failed">-</div><div class="l">Failed</div></div>
    <div class="s"><div class="n" id="s-providers">-</div><div class="l">Providers</div></div>
  </div>
  <div class="results-wrap" id="results-wrap"><div id="results"></div></div>
</div>

<div class="card">
  <div class="label">Providers</div>
  <h2>16 Supported Services</h2>
  <div class="desc">OpenAI, GitHub, Stripe, Anthropic, Google, and more.</div>
  <button class="btn" onclick="listProviders()">View All</button>
  <div class="results-wrap" id="prov-wrap"><div class="results-pre" id="providers"></div></div>
</div>

<div class="card">
  <div class="label">Resources</div>
  <h2>Help & Docs</h2>
  <div class="desc">Guides, security info, and troubleshooting.</div>
  <div class="help-grid">
    <a href="/help/getting-started"><span class="hi">🚀</span> Getting Started</a>
    <a href="/help/api-keys"><span class="hi">🔑</span> API Keys 101</a>
    <a href="/help/results"><span class="hi">📊</span> Reading Results</a>
    <a href="/help/security"><span class="hi">🛡️</span> Security</a>
    <a href="/help/troubleshooting"><span class="hi">🔧</span> Troubleshooting</a>
    <a href="/help/glossary"><span class="hi">📖</span> Glossary</a>
  </div>
</div>
</div>

<footer>Check Please &middot; Credential Audit Tool &middot; <a href="/help/security">Your keys are safe</a></footer>
</div>

<script>
const $=s=>document.getElementById(s);
const SI={valid:{i:'✓',l:'Valid'},auth_failed:{i:'✗',l:'Failed'},network_error:{i:'!',l:'Net Error'},quota_exhausted:{i:'!',l:'Quota'},suspended_account:{i:'✗',l:'Suspended'},insufficient_scope:{i:'!',l:'Limited'},invalid_format:{i:'?',l:'Bad Format'}};
const TIPS={auth_failed:'Rotate this key — create a new one in the provider dashboard.',network_error:'Check your internet connection and try again.',quota_exhausted:'Add credits or wait for your rate limit to reset.',suspended_account:'Check your account status on this service.',insufficient_scope:'This key is missing required permissions.',invalid_format:'The key value doesn\'t match the expected pattern.'};

async function api(path,msg){
  $('loader').style.display='block';
  if(msg)$('loader-text').textContent=msg;
  document.querySelectorAll('.btn').forEach(b=>b.disabled=true);
  try{const r=await fetch(path);return await r.json();}
  finally{$('loader').style.display='none';document.querySelectorAll('.btn').forEach(b=>b.disabled=false);}
}

async function runAudit(){
  const d=await api('/api/audit','Validating credentials…');
  const rw=$('results-wrap');rw.style.display='block';
  if(d.error){$('results').innerHTML='<div class="tip warn">'+d.error+'</div>';return;}
  const sb=$('stats');sb.style.display='grid';
  const s=d.summary||{};
  $('s-total').textContent=s.total_keys||d.results.length;
  $('s-valid').textContent=s.valid||0;
  $('s-failed').textContent=s.failed||0;
  $('s-providers').textContent=s.providers_checked||'-';
  let h='',issues=false;
  for(const k of d.results){
    const si=SI[k.status]||{i:'?',l:k.status};
    if(k.status!=='valid')issues=true;
    const fp=k.key_fingerprint;
    const fs=fp.prefix?fp.prefix+'…'+fp.suffix+' ('+fp.length+')':fp.redacted||'';
    h+='<div class="kc v-'+k.status+'">';
    h+='<span class="ki">'+si.i+'</span>';
    h+='<div class="km"><div class="kp">'+k.provider+'</div><div class="ke">'+k.env_var+' · '+fs+'</div></div>';
    h+='<span class="ks t-'+k.status+'">'+si.l+'</span></div>';
  }
  if(!issues)h+='<div class="tip">All credentials validated successfully.</div>';
  else{
    h+='<div class="tip warn"><strong>Action needed:</strong><br>';
    const seen=new Set();
    for(const k of d.results){const t=TIPS[k.status];if(t&&!seen.has(k.status)){seen.add(k.status);h+=SI[k.status].i+' <strong>'+SI[k.status].l+'</strong> — '+t+'<br>';}}
    h+='</div>';
  }
  $('results').innerHTML=h;
}

async function runPreview(){
  const d=await api('/api/preview','Loading preview…');
  $('results-wrap').style.display='block';
  $('results').innerHTML='<div class="results-pre">'+(d.output||d.error||'No output')+'</div>';
}
async function runSelfTest(){
  const d=await api('/api/self-test','Running self-test…');
  $('results-wrap').style.display='block';
  $('results').innerHTML='<div class="results-pre">'+(d.output||d.error||'No output')+'</div>';
}
async function listProviders(){
  const d=await api('/api/providers');
  $('prov-wrap').style.display='block';
  $('providers').textContent=d.output||d.error||'No output';
}
</script>
</body>
</html>"""

HELP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Check Please</title>
<style>
:root{{--bg:#09090b;--surface:#18181b;--border:#3f3f46;--text:#fafafa;--text2:#a1a1aa;--accent:#6366f1;--accent2:#818cf8}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:680px;margin:0 auto;padding:32px 20px}}
.back{{display:inline-flex;align-items:center;gap:6px;color:var(--text2);text-decoration:none;font-size:.8125rem;font-weight:500;padding:6px 12px;border-radius:6px;margin-bottom:24px;transition:all .15s}}
.back:hover{{color:var(--text);background:var(--surface)}}
h1{{font-size:1.75rem;font-weight:800;letter-spacing:-.03em;margin-bottom:20px}}
pre{{background:var(--surface);border:1px solid var(--border);padding:24px;border-radius:10px;line-height:1.75;white-space:pre-wrap;font-family:system-ui,sans-serif;font-size:.875rem;color:var(--text2)}}
</style></head><body><div class="wrap">
<a class="back" href="/">← Dashboard</a>
<h1>{title}</h1>
<pre>{body}</pre>
</div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # suppress request logs

    def _json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str, code: int = 200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._html(HTML)
        elif path == "/api/audit":
            env = DIR / ".env"
            if not env.is_file():
                self._json({"error": "No .env file found in project folder"}, 400)
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
        elif path.startswith("/help/"):
            topic = path[6:]
            from help_system import TOPICS
            t = TOPICS.get(topic)
            if t:
                self._html(HELP_HTML.format(title=t["title"], body=t["body"]))
            else:
                self._html("<h1>Topic not found</h1><a href='/'>Back</a>", 404)
        elif path == "/stop":
            self._html("<h1>Server stopped</h1><p>You can close this tab.</p>")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._html("<h1>Not found</h1><a href='/'>Back</a>", 404)


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
