"""Credential broker API for AI agents.

Localhost HTTP server that vends credentials to authorized agents.
Owner controls access via .check_please_agent_permissions.json.

Zero new dependencies — uses stdlib http.server.
"""

from __future__ import annotations

import json
import os
import secrets
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


if __name__ == "__main__":
    env = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".env")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    serve(env, port)
