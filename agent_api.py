"""Credential broker for AI agents.

Modes:
  --serve           HTTP API on localhost (default)
  --env CMD         Launch CMD with allowed credentials as env vars
  --export          Print shell export statements for eval/source
  --write-env PATH  Write allowed credentials to a file (KEY=VALUE)
  --mcp             MCP (Model Context Protocol) stdio server

Owner controls access via .check_please_agent_permissions.json.
Zero new dependencies — stdlib only (+ python-dotenv for .env parsing).
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

from dotenv import dotenv_values


DEFAULT_PORT = 8458
PERMISSIONS_FILE = ".check_please_agent_permissions.json"
LOG_FILE = "agent_access.log"
USAGE_LOG = "agent_usage.log"


def _parse_duration(s: str) -> float:
    """Parse '30m', '2h', '1d' to seconds. Returns 0 on failure."""
    if not s:
        return 0
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        return float(s[:-1]) * units[s[-1]]
    except (KeyError, ValueError, IndexError):
        return 0


from collections import deque
import threading
import urllib.request


class _UsageTracker:
    """In-memory usage counters with RPM sliding window and token totals."""

    def __init__(self, base_dir: Path):
        self._base_dir = base_dir
        self._lock = threading.Lock()
        # {key: deque of timestamps} for RPM
        self._rpm_windows: dict[str, deque] = {}
        # {key: total_requests}
        self._requests: dict[str, int] = {}
        # {key: total_tokens}
        self._tokens: dict[str, int] = {}
        # {(key, agent): total_tokens}
        self._tokens_by_agent: dict[tuple[str, str], int] = {}

    def record_request(self, key: str, agent: str = "") -> None:
        now = time.time()
        with self._lock:
            self._requests[key] = self._requests.get(key, 0) + 1
            if key not in self._rpm_windows:
                self._rpm_windows[key] = deque()
            self._rpm_windows[key].append(now)

    def check_rpm(self, key: str, limit: int) -> str | None:
        """Return error string if over RPM limit, else None."""
        if limit <= 0:
            return None
        now = time.time()
        with self._lock:
            dq = self._rpm_windows.get(key)
            if not dq:
                return None
            # Evict entries older than 60s
            while dq and dq[0] < now - 60:
                dq.popleft()
            if len(dq) >= limit:
                return f"rate limit exceeded: {len(dq)}/{limit} RPM for {key}"
        return None

    def record_tokens(self, key: str, tokens: int, agent: str = "",
                      model: str = "") -> None:
        with self._lock:
            self._tokens[key] = self._tokens.get(key, 0) + tokens
            if agent:
                k = (key, agent)
                self._tokens_by_agent[k] = self._tokens_by_agent.get(k, 0) + tokens
        # Append to usage log
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "key": key,
                 "tokens": tokens, "agent": agent, "model": model}
        try:
            with open(self._base_dir / USAGE_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def get_rpm(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._rpm_windows.get(key)
            if not dq:
                return 0
            while dq and dq[0] < now - 60:
                dq.popleft()
            return len(dq)

    def summary(self, key: str = "") -> dict:
        with self._lock:
            if key:
                return {"key": key, "requests": self._requests.get(key, 0),
                        "tokens": self._tokens.get(key, 0),
                        "rpm": self.get_rpm(key)}
            return {k: {"requests": self._requests.get(k, 0),
                        "tokens": self._tokens.get(k, 0),
                        "rpm": self.get_rpm(k)}
                    for k in set(list(self._requests) + list(self._tokens))}


def _send_alert(msg: str, webhook: str = "", key: str = "",
                agent: str = "") -> None:
    """Print alert to stderr; optionally POST to webhook."""
    print(f"\033[33m⚠ ALERT: {msg}\033[0m", file=sys.stderr)
    if webhook:
        payload = json.dumps({"text": f"🔔 check_please: {msg}",
                              "key": key, "agent": agent}).encode()
        try:
            req = urllib.request.Request(webhook, data=payload,
                                        headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass


class _CredScope:
    """Per-credential access scope."""
    __slots__ = ("max_uses", "expires_at", "uses", "rpm_limit")

    def __init__(self, max_uses: int = 0, expires: str = "", rpm_limit: int = 0):
        self.max_uses = max_uses  # 0 = unlimited
        ttl = _parse_duration(expires)
        self.expires_at = time.time() + ttl if ttl > 0 else 0  # 0 = never
        self.uses = 0
        self.rpm_limit = rpm_limit  # 0 = unlimited

    def check(self) -> str | None:
        """Return error string if access denied, else None."""
        if self.expires_at and time.time() > self.expires_at:
            return "credential access expired"
        if self.max_uses and self.uses >= self.max_uses:
            return f"max uses ({self.max_uses}) exhausted"
        return None

    def record_use(self):
        self.uses += 1


def _load_env(env_path: Path) -> dict[str, str]:
    vals = dotenv_values(env_path)
    return {k: v for k, v in vals.items() if v}


def _load_permissions(base_dir: Path) -> dict:
    p = base_dir / PERMISSIONS_FILE
    if not p.exists():
        return {"allowed": [], "deny_all": True, "scopes": {}, "token_ttl": 0,
                "alerts": {}}
    try:
        data = json.loads(p.read_text())
        if "allowed" not in data:
            data["allowed"] = []
        data["deny_all"] = False
        # Parse scoped entries: strings become unlimited, dicts get scope
        names, scopes = [], {}
        for entry in data["allowed"]:
            if isinstance(entry, str):
                names.append(entry)
                scopes[entry] = _CredScope()
            elif isinstance(entry, dict) and "name" in entry:
                n = entry["name"]
                names.append(n)
                scopes[n] = _CredScope(
                    max_uses=entry.get("max_uses", 0),
                    expires=entry.get("expires", ""),
                    rpm_limit=entry.get("rpm_limit", 0),
                )
        data["allowed"] = names
        data["scopes"] = scopes
        data["token_ttl"] = _parse_duration(data.get("token_ttl", ""))
        data["alerts"] = data.get("alerts", {})
        return data
    except (json.JSONDecodeError, OSError):
        return {"allowed": [], "deny_all": True, "scopes": {}, "token_ttl": 0,
                "alerts": {}}


def _log_access(base_dir: Path, event: str, env_var: str = "", agent: str = "", granted: bool = False):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "env_var": env_var,
        "agent": agent,
        "granted": granted,
    }
    try:
        with open(base_dir / LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _make_handler(token: str, env_vars: dict[str, str], permissions: dict, base_dir: Path,
                  token_expires: float = 0, tracker: _UsageTracker | None = None):

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # suppress default stderr logging

        def _check_auth(self) -> Optional[str]:
            if token_expires and time.time() > token_expires:
                self.send_error(401, "Bearer token expired")
                _log_access(base_dir, "token_expired")
                return None
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != token:
                self.send_error(401, "Invalid or missing bearer token")
                _log_access(base_dir, "auth_failed")
                return None
            return auth[7:]

        def _json_response(self, code: int, data: dict):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _get_agent_id(self) -> str:
            return self.headers.get("X-Agent-Id", "unknown")

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", 0))
            if length > 10_485_760:  # 10MB cap
                self._json_response(413, {"error": "Request body too large"})
                return b""
            return self.rfile.read(length) if length else b""

        def do_GET(self):
            if not self._check_auth():
                return

            if self.path == "/providers":
                # List env var names grouped by detected provider — no values
                from credential_auditor.providers import discover_providers, Provider
                discover_providers()
                registry = Provider.get_registry()
                providers = {}
                for var in env_vars:
                    for name, cls in registry.items():
                        inst = cls()
                        if inst.matches_env_var(var):
                            providers.setdefault(name, []).append(var)
                            break
                _log_access(base_dir, "list_providers", agent=self._get_agent_id(), granted=True)
                self._json_response(200, {"providers": providers})

            elif self.path == "/credentials":
                # List allowed credential names — no values
                if permissions.get("deny_all"):
                    self._json_response(403, {"error": "No permissions configured",
                                               "setup": f"Create {PERMISSIONS_FILE} with allowed env var names"})
                    return
                allowed = [v for v in permissions["allowed"] if v in env_vars]
                _log_access(base_dir, "list_credentials", agent=self._get_agent_id(), granted=True)
                self._json_response(200, {"allowed_credentials": allowed, "total": len(allowed)})

            elif self.path == "/health":
                self._json_response(200, {"status": "ok", "credentials_loaded": len(env_vars)})

            elif self.path == "/usage":
                if tracker:
                    self._json_response(200, {"usage": tracker.summary()})
                else:
                    self._json_response(200, {"usage": {}})

            elif self.path.startswith("/usage/"):
                key = self.path[len("/usage/"):]
                if tracker:
                    s = tracker.summary(key)
                    s["rpm_limit"] = 0
                    scope = permissions.get("scopes", {}).get(key)
                    if scope:
                        s["rpm_limit"] = scope.rpm_limit
                    self._json_response(200, s)
                else:
                    self._json_response(200, {"key": key, "requests": 0, "tokens": 0, "rpm": 0})

            else:
                self.send_error(404)

        def do_POST(self):
            if not self._check_auth():
                return

            agent = self._get_agent_id()

            # POST /usage — agent reports token usage
            if self.path == "/usage":
                if not tracker:
                    self._json_response(200, {"status": "ok"})
                    return
                try:
                    data = json.loads(self._read_body())
                except (json.JSONDecodeError, ValueError):
                    self._json_response(400, {"error": "invalid JSON"})
                    return
                key = data.get("key", "")
                tokens = int(data.get("tokens", 0))
                model = data.get("model", "")
                if key and tokens > 0:
                    tracker.record_tokens(key, tokens, agent=agent, model=model)
                    # Check alert thresholds
                    alerts = permissions.get("alerts", {})
                    token_threshold = alerts.get("token_threshold", 0)
                    if token_threshold and tracker.summary(key).get("tokens", 0) >= token_threshold:
                        _send_alert(f"{key} exceeded {token_threshold} tokens",
                                    webhook=alerts.get("webhook", ""),
                                    key=key, agent=agent)
                self._json_response(200, {"status": "ok"})
                return

            # POST /credentials/{env_var} — get actual value
            if not self.path.startswith("/credentials/"):
                self.send_error(404)
                return

            var_name = self.path[len("/credentials/"):]

            if permissions.get("deny_all"):
                _log_access(base_dir, "credential_request", env_var=var_name, agent=agent, granted=False)
                self._json_response(403, {"error": "No permissions configured"})
                return

            if var_name not in permissions["allowed"]:
                _log_access(base_dir, "credential_denied", env_var=var_name, agent=agent, granted=False)
                self._json_response(403, {"error": f"Access to {var_name} not permitted",
                                           "hint": f"Add \"{var_name}\" to allowed list in {PERMISSIONS_FILE}"})
                return

            if var_name not in env_vars:
                _log_access(base_dir, "credential_not_found", env_var=var_name, agent=agent, granted=False)
                self._json_response(404, {"error": f"{var_name} not found in .env"})
                return

            # Enforce scoped limits
            scope = permissions.get("scopes", {}).get(var_name)
            if scope:
                err = scope.check()
                if err:
                    _log_access(base_dir, "scope_denied", env_var=var_name, agent=agent, granted=False)
                    self._json_response(403, {"error": err})
                    return
                # RPM check
                if tracker and scope.rpm_limit:
                    rpm_err = tracker.check_rpm(var_name, scope.rpm_limit)
                    if rpm_err:
                        _log_access(base_dir, "rpm_denied", env_var=var_name, agent=agent, granted=False)
                        _send_alert(rpm_err, webhook=permissions.get("alerts", {}).get("webhook", ""),
                                    key=var_name, agent=agent)
                        self._json_response(429, {"error": rpm_err})
                        return
                scope.record_use()

            # Track request
            if tracker:
                tracker.record_request(var_name, agent=agent)

            _log_access(base_dir, "credential_granted", env_var=var_name, agent=agent, granted=True)
            self._json_response(200, {"env_var": var_name, "value": env_vars[var_name]})

    return Handler


def create_permissions_template(base_dir: Path) -> Path:
    p = base_dir / PERMISSIONS_FILE
    template = {
        "allowed": [],
        "token_ttl": "1h",
        "alerts": {"token_threshold": 100000, "webhook": ""},
        "_comment": "Strings = unlimited. Objects = scoped: {name, max_uses, expires, rpm_limit}. token_ttl limits bearer token lifetime.",
        "_example": ["OPENAI_API_KEY", {"name": "ANTHROPIC_API_KEY", "max_uses": 50, "expires": "2h", "rpm_limit": 60}]
    }
    p.write_text(json.dumps(template, indent=2) + "\n")
    return p


def serve(env_path: Path, port: int = DEFAULT_PORT):
    base_dir = env_path.parent
    env_vars = _load_env(env_path)
    if not env_vars:
        print(f"\033[31m✗ No credentials found in {env_path}\033[0m")
        sys.exit(1)

    permissions = _load_permissions(base_dir)
    token = secrets.token_urlsafe(32)
    token_ttl = permissions.get("token_ttl", 0)
    token_expires = time.time() + token_ttl if token_ttl else 0
    tracker = _UsageTracker(base_dir)

    if permissions.get("deny_all"):
        print(f"\033[33m⚠ No permissions file found.\033[0m")
        p = create_permissions_template(base_dir)
        print(f"  Created template: {p}")
        print(f"  Edit it to allow agent access to specific credentials.\n")
        # Reload after creating template
        permissions = _load_permissions(base_dir)

    allowed_count = len([v for v in permissions.get("allowed", []) if v in env_vars])

    print(f"\033[1m╔══════════════════════════════════════════════╗\033[0m")
    print(f"\033[1m║  check_please — Agent Credential Broker      ║\033[0m")
    print(f"\033[1m╚══════════════════════════════════════════════╝\033[0m")
    print(f"\n\033[36m  Credentials loaded:\033[0m {len(env_vars)}")
    print(f"\033[36m  Allowed for agents:\033[0m {allowed_count}")
    if token_ttl:
        print(f"\033[36m  Token expires in:\033[0m  {int(token_ttl)}s")
    print(f"\033[36m  Usage tracking:\033[0m    enabled")
    print(f"\033[36m  Listening on:\033[0m      http://127.0.0.1:{port}")
    print(f"\n\033[1m  Bearer Token (give to your agent):\033[0m")
    print(f"\033[32m  {token}\033[0m")
    print(f"\n\033[2m  Access log: {base_dir / LOG_FILE}\033[0m")
    print(f"\033[2m  Usage log:  {base_dir / USAGE_LOG}\033[0m")
    print(f"\033[2m  Permissions: {base_dir / PERMISSIONS_FILE}\033[0m")
    print(f"\n\033[36m  Example:\033[0m")
    print(f"  curl -H 'Authorization: Bearer {token}' http://127.0.0.1:{port}/credentials")
    print(f"  curl -H 'Authorization: Bearer {token}' http://127.0.0.1:{port}/usage")
    print(f"\n\033[2m  Press Ctrl+C to stop\033[0m\n")

    handler = _make_handler(token, env_vars, permissions, base_dir, token_expires, tracker)
    server = HTTPServer(("127.0.0.1", port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[36m▸ Agent API stopped\033[0m")
        server.server_close()


def _get_allowed_creds(env_path: Path) -> dict[str, str]:
    """Load env and filter to only allowed credentials (respects scoped expiry)."""
    base_dir = env_path.parent
    env_vars = _load_env(env_path)
    permissions = _load_permissions(base_dir)
    if permissions.get("deny_all"):
        print(f"\033[33m⚠ No permissions file found.\033[0m", file=sys.stderr)
        create_permissions_template(base_dir)
        print(f"  Created {PERMISSIONS_FILE} — edit it to allow credentials.\n", file=sys.stderr)
        return {}
    result = {}
    for k, v in env_vars.items():
        if k not in permissions["allowed"]:
            continue
        scope = permissions.get("scopes", {}).get(k)
        if scope and scope.check():
            continue  # expired or exhausted
        result[k] = v
    return result


# ── Mode: --env CMD (launch agent with credentials as env vars) ──

def run_with_env(env_path: Path, cmd: list[str]):
    creds = _get_allowed_creds(env_path)
    if not creds:
        print("\033[31m✗ No allowed credentials to inject\033[0m", file=sys.stderr)
        sys.exit(1)
    # Start with current env, overlay allowed creds
    env = dict(os.environ)
    env.update(creds)
    _log_access(env_path.parent, "env_inject", env_var=",".join(creds.keys()),
                agent=cmd[0] if cmd else "unknown", granted=True)
    n = len(creds)
    print(f"\033[36m▸ Injecting {n} credential{'s' if n != 1 else ''} into: {' '.join(cmd)}\033[0m",
          file=sys.stderr)
    sys.exit(subprocess.call(cmd, env=env))


# ── Mode: --export (print shell export statements) ──

def print_exports(env_path: Path):
    creds = _get_allowed_creds(env_path)
    if not creds:
        print("# No allowed credentials. Edit .check_please_agent_permissions.json", file=sys.stderr)
        sys.exit(1)
    _log_access(env_path.parent, "shell_export", env_var=",".join(creds.keys()), granted=True)
    for k, v in creds.items():
        print(f"export {k}={shlex.quote(v)}")


# ── Mode: --env-file (write credentials to a file) ──

def write_env_file(env_path: Path, output_path: Path):
    """Write allowed credentials to a file in KEY=VALUE format."""
    creds = _get_allowed_creds(env_path)
    if not creds:
        return
    output_path.write_text(
        "".join(f"{k}={v}\n" for k, v in sorted(creds.items()))
    )
    os.chmod(output_path, 0o600)
    print(f"Wrote {len(creds)} credentials to {output_path}", file=sys.stderr)


# ── Mode: --mcp (Model Context Protocol stdio server) ──

def run_mcp(env_path: Path):
    """MCP JSON-RPC stdio server. Compatible with Claude Code, Copilot, etc."""
    creds = _get_allowed_creds(env_path)
    base_dir = env_path.parent
    permissions = _load_permissions(base_dir)
    tracker = _UsageTracker(base_dir)

    def _respond(id, result):
        msg = {"jsonrpc": "2.0", "id": id, "result": result}
        body = json.dumps(msg)
        sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
        sys.stdout.flush()

    def _error(id, code, message):
        msg = {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}
        body = json.dumps(msg)
        sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
        sys.stdout.flush()

    def _read_message() -> Optional[dict]:
        # Read Content-Length header
        while True:
            line = sys.stdin.readline()
            if not line:
                return None
            line = line.strip()
            if line.startswith("Content-Length:"):
                length = int(line.split(":", 1)[1].strip())
                sys.stdin.readline()  # empty line
                body = sys.stdin.read(length)
                return json.loads(body)
            if line == "":
                continue

    tools = [
        {
            "name": "get_credential",
            "description": "Get an API key or credential value by env var name. Only returns credentials the owner has explicitly allowed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Environment variable name (e.g. OPENAI_API_KEY)"}
                },
                "required": ["name"]
            }
        },
        {
            "name": "list_credentials",
            "description": "List available credential names that the owner has allowed access to. Returns names only, not values.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "report_usage",
            "description": "Report token usage for a credential. Call this after making API requests to help the owner track costs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Env var name (e.g. OPENAI_API_KEY)"},
                    "tokens": {"type": "integer", "description": "Total tokens used"},
                    "model": {"type": "string", "description": "Model name (e.g. gpt-4)"}
                },
                "required": ["key", "tokens"]
            }
        },
    ]

    print("check_please MCP credential server ready", file=sys.stderr)

    while True:
        msg = _read_message()
        if msg is None:
            break

        method = msg.get("method", "")
        id = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            _respond(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "check_please", "version": "1.0.0"}
            })
        elif method == "notifications/initialized":
            pass  # no response needed
        elif method == "tools/list":
            _respond(id, {"tools": tools})
        elif method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            if tool_name == "list_credentials":
                names = list(creds.keys())
                _log_access(base_dir, "mcp_list", granted=True)
                _respond(id, {"content": [{"type": "text", "text": json.dumps(names)}]})
            elif tool_name == "get_credential":
                var = args.get("name", "")
                if var in creds:
                    scope = permissions.get("scopes", {}).get(var)
                    if scope:
                        err = scope.check()
                        if err:
                            _log_access(base_dir, "mcp_scope_denied", env_var=var, granted=False)
                            _respond(id, {"content": [{"type": "text", "text": err}], "isError": True})
                            continue
                        if scope.rpm_limit:
                            rpm_err = tracker.check_rpm(var, scope.rpm_limit)
                            if rpm_err:
                                _log_access(base_dir, "mcp_rpm_denied", env_var=var, granted=False)
                                _send_alert(rpm_err, webhook=permissions.get("alerts", {}).get("webhook", ""),
                                            key=var)
                                _respond(id, {"content": [{"type": "text", "text": rpm_err}], "isError": True})
                                continue
                        scope.record_use()
                    tracker.record_request(var)
                    _log_access(base_dir, "mcp_get", env_var=var, granted=True)
                    _respond(id, {"content": [{"type": "text", "text": creds[var]}]})
                else:
                    _log_access(base_dir, "mcp_denied", env_var=var, granted=False)
                    _respond(id, {"content": [{"type": "text", "text": f"Access denied: {var}"}], "isError": True})
            elif tool_name == "report_usage":
                key = args.get("key", "")
                tokens = int(args.get("tokens", 0))
                model = args.get("model", "")
                if key and tokens > 0:
                    tracker.record_tokens(key, tokens, model=model)
                    alerts = permissions.get("alerts", {})
                    token_threshold = alerts.get("token_threshold", 0)
                    if token_threshold and tracker.summary(key).get("tokens", 0) >= token_threshold:
                        _send_alert(f"{key} exceeded {token_threshold} tokens",
                                    webhook=alerts.get("webhook", ""), key=key)
                _log_access(base_dir, "mcp_usage_report", env_var=key, granted=True)
                _respond(id, {"content": [{"type": "text", "text": "usage recorded"}]})
            else:
                _error(id, -32601, f"Unknown tool: {tool_name}")
        elif method == "ping":
            _respond(id, {})
        else:
            if id is not None:
                _error(id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    args = sys.argv[1:]
    env_path = Path(".env")

    # Parse --env-file before mode flags
    if "--env-file" in args:
        idx = args.index("--env-file")
        env_path = Path(args[idx + 1])
        args = args[:idx] + args[idx + 2:]

    if not args or args[0] == "--serve":
        port = DEFAULT_PORT
        if len(args) > 1 and args[-1].isdigit():
            port = int(args[-1])
        serve(env_path, port)
    elif args[0] == "--export":
        print_exports(env_path)
    elif args[0] == "--write-env":
        if len(args) < 2:
            print("Usage: agent_api.py --write-env OUTPUT_PATH", file=sys.stderr)
            sys.exit(2)
        write_env_file(env_path, Path(args[1]))
    elif args[0] == "--mcp":
        run_mcp(env_path)
    elif args[0] == "--env":
        if len(args) < 2:
            print("Usage: agent_api.py --env COMMAND [ARGS...]", file=sys.stderr)
            sys.exit(2)
        run_with_env(env_path, args[1:])
    else:
        print(f"""Usage: agent_api.py [MODE] [OPTIONS]

Modes:
  --serve            HTTP credential broker (default)
  --env CMD...       Launch CMD with allowed credentials as env vars
  --export           Print shell export statements (use with eval)
  --write-env PATH   Write credentials to a file in KEY=VALUE format
  --mcp              MCP stdio server for Claude Code, Copilot, etc.

Options:
  --env-file PATH  Path to .env file (default: .env)
""", file=sys.stderr)
        sys.exit(2)
