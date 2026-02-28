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
<title>Check Please — API Key Auditor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f23;color:#e0e0e0;min-height:100vh}
.container{max-width:800px;margin:0 auto;padding:20px}
header{text-align:center;padding:30px 0;border-bottom:1px solid #333}
header h1{font-size:2em;margin-bottom:8px}
header p{color:#9aa5ce;font-size:1.1em}
.badge{display:inline-block;background:#1a3a1a;color:#4ade80;padding:4px 12px;border-radius:12px;font-size:.85em;margin-top:8px}
.card{background:#1a1a2e;border-radius:12px;padding:24px;margin:20px 0;border:1px solid #333}
.card h2{margin-bottom:12px;font-size:1.3em}
.card p{color:#9aa5ce;line-height:1.6;margin-bottom:16px}
.btn{display:inline-block;padding:12px 28px;border-radius:8px;border:none;font-size:1em;cursor:pointer;text-decoration:none;color:#fff;margin:6px;transition:opacity .2s}
.btn:hover{opacity:.85}
.btn-primary{background:#3b82f6}
.btn-green{background:#22c55e}
.btn-amber{background:#f59e0b;color:#000}
.btn-red{background:#ef4444}
.btn:disabled{opacity:.5;cursor:not-allowed}
.results{background:#0d1117;border-radius:8px;padding:16px;margin-top:16px;white-space:pre-wrap;font-family:'Fira Code',monospace;font-size:.9em;max-height:500px;overflow-y:auto;line-height:1.5}
.status-bar{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.stat{background:#16213e;padding:10px 16px;border-radius:8px;text-align:center;flex:1;min-width:100px}
.stat .num{font-size:1.5em;font-weight:bold}
.stat .label{font-size:.8em;color:#9aa5ce}
.valid{color:#4ade80}.failed{color:#f87171}.warn{color:#fbbf24}
.help-link{color:#60a5fa;text-decoration:none;font-size:.9em}
.help-link:hover{text-decoration:underline}
.spinner{display:none;border:3px solid #333;border-top:3px solid #3b82f6;border-radius:50%;width:24px;height:24px;animation:spin 1s linear infinite;margin:0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-msg{display:none;text-align:center;color:#9aa5ce;margin:12px 0;font-size:.95em}
.key-card{background:#16213e;border-radius:8px;padding:12px 16px;margin:8px 0;display:flex;align-items:center;gap:12px;border-left:4px solid #333}
.key-card.s-valid{border-left-color:#4ade80}.key-card.s-auth_failed{border-left-color:#f87171}
.key-card.s-network_error{border-left-color:#fbbf24}.key-card.s-quota_exhausted{border-left-color:#fbbf24}
.key-card.s-suspended_account{border-left-color:#f87171}.key-card.s-insufficient_scope{border-left-color:#fbbf24}
.key-card.s-invalid_format{border-left-color:#fb923c}
.key-card .icon{font-size:1.3em;flex-shrink:0}
.key-card .info{flex:1;min-width:0}
.key-card .provider{font-weight:bold;text-transform:capitalize}
.key-card .env-var{color:#9aa5ce;font-size:.85em}
.key-card .status{font-size:.85em;padding:2px 8px;border-radius:4px;flex-shrink:0}
.key-card .status.valid{background:#1a3a1a}.key-card .status.auth_failed{background:#3a1a1a}
.key-card .status.network_error,.key-card .status.quota_exhausted,.key-card .status.insufficient_scope{background:#3a3a1a}
.key-card .status.invalid_format{background:#3a2a1a}
.tip-box{background:#1a2a1a;border:1px solid #2a4a2a;border-radius:8px;padding:14px;margin-top:12px;font-size:.9em;line-height:1.6}
.tip-box.warn{background:#2a2a1a;border-color:#4a4a2a}
footer{text-align:center;padding:20px;color:#555;font-size:.85em;border-top:1px solid #222;margin-top:30px}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🔐 Check Please</h1>
  <p>Check if your API keys still work — safely and privately</p>
  <div class="badge">🛡️ Your keys never leave your computer</div>
</header>

<div class="card">
  <h2>🔍 Check Your API Keys</h2>
  <p>Click the button below to scan your .env file and verify each key with its service.
     This usually takes 10-30 seconds.</p>
  <button class="btn btn-primary" onclick="runAudit()">Check My Keys</button>
  <button class="btn btn-amber" onclick="runPreview()">Preview Only</button>
  <button class="btn btn-green" onclick="runSelfTest()">Self-Test</button>
  <div class="spinner" id="spinner"></div>
  <div class="loading-msg" id="loading-msg">⏳ Checking your keys... this usually takes 10-30 seconds</div>
  <div id="status-bar" class="status-bar" style="display:none">
    <div class="stat"><div class="num" id="s-total">-</div><div class="label">Total</div></div>
    <div class="stat"><div class="num valid" id="s-valid">-</div><div class="label">Valid</div></div>
    <div class="stat"><div class="num failed" id="s-failed">-</div><div class="label">Failed</div></div>
    <div class="stat"><div class="num" id="s-providers">-</div><div class="label">Providers</div></div>
  </div>
  <div class="results" id="results" style="display:none"></div>
</div>

<div class="card">
  <h2>📚 Help & Information</h2>
  <p>New to API keys? Not sure what something means? We've got you covered.</p>
  <a class="help-link" href="/help/getting-started">🚀 Getting Started</a> &nbsp;
  <a class="help-link" href="/help/api-keys">🔑 What Are API Keys?</a> &nbsp;
  <a class="help-link" href="/help/results">📊 Understanding Results</a> &nbsp;
  <a class="help-link" href="/help/security">🛡️ Security</a> &nbsp;
  <a class="help-link" href="/help/troubleshooting">🔧 Troubleshooting</a> &nbsp;
  <a class="help-link" href="/help/glossary">📖 Glossary</a>
</div>

<div class="card">
  <h2>📋 Supported Services</h2>
  <p>We can check keys for 16 services including OpenAI, GitHub, Stripe, Google, Anthropic, and more.</p>
  <button class="btn btn-primary" onclick="listProviders()">Show All Providers</button>
  <div class="results" id="providers" style="display:none"></div>
</div>

<footer>
  Check Please — Credential Audit Tool &nbsp;|&nbsp;
  <a class="help-link" href="/help/security">Your keys are safe</a> &nbsp;|&nbsp;
  <a class="help-link" href="/stop" onclick="return confirm('Stop the web server?')">Stop Server</a>
</footer>
</div>

<script>
async function api(path,msg){
  const sp=document.getElementById('spinner');
  const lm=document.getElementById('loading-msg');
  sp.style.display='block';
  if(msg){lm.textContent=msg;lm.style.display='block';}
  document.querySelectorAll('.btn').forEach(b=>b.disabled=true);
  try{
    const resp=await fetch(path);
    const data=await resp.json();
    return data;
  }finally{
    sp.style.display='none';
    lm.style.display='none';
    document.querySelectorAll('.btn').forEach(b=>b.disabled=false);
  }
}
const STATUS_INFO={
  valid:{icon:'✅',label:'Valid',cls:'valid',tip:''},
  auth_failed:{icon:'❌',label:'Failed',cls:'auth_failed',tip:'Log into this service and create a new key'},
  network_error:{icon:'⚠️',label:'Network Error',cls:'network_error',tip:'Check your internet connection and try again'},
  quota_exhausted:{icon:'⚠️',label:'Quota Used',cls:'quota_exhausted',tip:'Add credits or wait for your limit to reset'},
  suspended_account:{icon:'🚫',label:'Suspended',cls:'suspended_account',tip:'Check your account status on this service'},
  insufficient_scope:{icon:'⚠️',label:'Limited',cls:'insufficient_scope',tip:'This key is missing some permissions'},
  invalid_format:{icon:'🔶',label:'Bad Format',cls:'invalid_format',tip:'The key doesn\'t match the expected pattern for this service'},
};
async function runAudit(){
  const data=await api('/api/audit','⏳ Checking your keys... this usually takes 10-30 seconds');
  const r=document.getElementById('results');
  r.style.display='block';
  if(data.error){r.innerHTML='<div class="tip-box warn">❌ '+data.error+'</div>';return;}
  const sb=document.getElementById('status-bar');
  sb.style.display='flex';
  const s=data.summary||{};
  document.getElementById('s-total').textContent=s.total_keys||data.results.length;
  document.getElementById('s-valid').textContent=s.valid||0;
  document.getElementById('s-failed').textContent=s.failed||0;
  document.getElementById('s-providers').textContent=s.providers_checked||'-';
  let html='';
  let hasIssues=false;
  for(const k of data.results){
    const si=STATUS_INFO[k.status]||{icon:'❓',label:k.status,cls:'',tip:''};
    if(k.status!=='valid')hasIssues=true;
    const fp=k.key_fingerprint;
    const fpStr=fp.prefix?fp.prefix+'...'+fp.suffix+' ('+fp.length+')':fp.redacted||'';
    html+='<div class="key-card s-'+k.status+'">';
    html+='<span class="icon">'+si.icon+'</span>';
    html+='<div class="info"><div class="provider">'+k.provider+'</div><div class="env-var">'+k.env_var+' &middot; '+fpStr+'</div></div>';
    html+='<span class="status '+k.status+'">'+si.label+'</span></div>';
  }
  if(!hasIssues){
    html+='<div class="tip-box">🎉 All your keys are valid! Everything looks good.</div>';
  }else{
    html+='<div class="tip-box warn"><strong>What to do about failed keys:</strong><br>';
    const seen=new Set();
    for(const k of data.results){
      const si=STATUS_INFO[k.status];
      if(si&&si.tip&&!seen.has(k.status)){seen.add(k.status);html+=si.icon+' <strong>'+si.label+'</strong>: '+si.tip+'<br>';}
    }
    html+='</div>';
  }
  r.innerHTML=html;
}
async function runPreview(){
  const data=await api('/api/preview','👀 Loading preview...');
  const r=document.getElementById('results');
  r.style.display='block';
  r.textContent=data.output||data.error||'No output';
}
async function runSelfTest(){
  const data=await api('/api/self-test','🧪 Running self-test...');
  const r=document.getElementById('results');
  r.style.display='block';
  r.textContent=data.output||data.error||'No output';
}
async function listProviders(){
  const data=await api('/api/providers');
  const p=document.getElementById('providers');
  p.style.display='block';
  p.textContent=data.output||data.error||'No output';
}
</script>
</body>
</html>"""

HELP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Check Please</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f23;color:#e0e0e0;min-height:100vh}}
.container{{max-width:700px;margin:0 auto;padding:30px}}
h1{{margin-bottom:20px}}
pre{{background:#1a1a2e;padding:20px;border-radius:8px;line-height:1.7;white-space:pre-wrap}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
.back{{display:inline-block;margin-bottom:20px}}
</style></head><body><div class="container">
<a class="back" href="/">← Back to dashboard</a>
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
