"""Credential broker for AI agents.

Modes:
  --serve       HTTP API on localhost (default)
  --env CMD     Launch CMD with allowed credentials as env vars
  --export      Print shell export statements for eval/source
  --mcp         MCP (Model Context Protocol) stdio server

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


def _load_env(env_path: Path) -> dict[str, str]:
    vals = dotenv_values(env_path)
    return {k: v for k, v in vals.items() if v}


def _load_permissions(base_dir: Path) -> dict:
    p = base_dir / PERMISSIONS_FILE
    if not p.exists():
        return {"allowed": [], "deny_all": True}
    try:
        data = json.loads(p.read_text())
        if "allowed" not in data:
            data["allowed"] = []
        data["deny_all"] = False
        return data
    except (json.JSONDecodeError, OSError):
        return {"allowed": [], "deny_all": True}


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


def _make_handler(token: str, env_vars: dict[str, str], permissions: dict, base_dir: Path):

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # suppress default stderr logging

        def _check_auth(self) -> Optional[str]:
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
            self.end_headers()
            self.wfile.write(body)

        def _get_agent_id(self) -> str:
            return self.headers.get("X-Agent-Id", "unknown")

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

            else:
                self.send_error(404)

        def do_POST(self):
            if not self._check_auth():
                return

            # POST /credentials/{env_var} — get actual value
            if not self.path.startswith("/credentials/"):
                self.send_error(404)
                return

            var_name = self.path[len("/credentials/"):]
            agent = self._get_agent_id()

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

            _log_access(base_dir, "credential_granted", env_var=var_name, agent=agent, granted=True)
            self._json_response(200, {"env_var": var_name, "value": env_vars[var_name]})

    return Handler


def create_permissions_template(base_dir: Path) -> Path:
    p = base_dir / PERMISSIONS_FILE
    template = {
        "allowed": [],
        "_comment": "Add env var names that agents can access. Example: [\"OPENAI_API_KEY\", \"ANTHROPIC_API_KEY\"]"
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
    print(f"\033[36m  Listening on:\033[0m      http://127.0.0.1:{port}")
    print(f"\n\033[1m  Bearer Token (give to your agent):\033[0m")
    print(f"\033[32m  {token}\033[0m")
    print(f"\n\033[2m  Access log: {base_dir / LOG_FILE}\033[0m")
    print(f"\033[2m  Permissions: {base_dir / PERMISSIONS_FILE}\033[0m")
    print(f"\n\033[36m  Example:\033[0m")
    print(f"  curl -H 'Authorization: Bearer {token}' http://127.0.0.1:{port}/credentials")
    print(f"\n\033[2m  Press Ctrl+C to stop\033[0m\n")

    handler = _make_handler(token, env_vars, permissions, base_dir)
    server = HTTPServer(("127.0.0.1", port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[36m▸ Agent API stopped\033[0m")
        server.server_close()


def _get_allowed_creds(env_path: Path) -> dict[str, str]:
    """Load env and filter to only allowed credentials."""
    base_dir = env_path.parent
    env_vars = _load_env(env_path)
    permissions = _load_permissions(base_dir)
    if permissions.get("deny_all"):
        print(f"\033[33m⚠ No permissions file found.\033[0m", file=sys.stderr)
        create_permissions_template(base_dir)
        print(f"  Created {PERMISSIONS_FILE} — edit it to allow credentials.\n", file=sys.stderr)
        return {}
    return {k: v for k, v in env_vars.items() if k in permissions["allowed"]}


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


# ── Mode: --mcp (Model Context Protocol stdio server) ──

def run_mcp(env_path: Path):
    """MCP JSON-RPC stdio server. Compatible with Claude Code, Copilot, etc."""
    creds = _get_allowed_creds(env_path)
    base_dir = env_path.parent

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
        }
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
                    _log_access(base_dir, "mcp_get", env_var=var, granted=True)
                    _respond(id, {"content": [{"type": "text", "text": creds[var]}]})
                else:
                    _log_access(base_dir, "mcp_denied", env_var=var, granted=False)
                    _respond(id, {"content": [{"type": "text", "text": f"Access denied: {var}"}], "isError": True})
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
  --serve          HTTP credential broker (default)
  --env CMD...     Launch CMD with allowed credentials as env vars
  --export         Print shell export statements (use with eval)
  --mcp            MCP stdio server for Claude Code, Copilot, etc.

Options:
  --env-file PATH  Path to .env file (default: .env)
""", file=sys.stderr)
        sys.exit(2)
