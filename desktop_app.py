"""Native desktop app — embeds the web UI in a real OS window via pywebview."""
from __future__ import annotations

import socket
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _pick_port(preferred: int, attempts: int = 20) -> int:
    """Use preferred port if free; otherwise find the next available port."""
    for port in range(preferred, preferred + attempts):
        if _port_free(port):
            return port
    raise OSError(f"No free port in range {preferred}–{preferred + attempts - 1}")


def main() -> int:
    try:
        import webview
    except ImportError:
        print("pywebview required: pip install pywebview", file=sys.stderr)
        return 1

    # Import the web server
    app_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(app_dir))
    from simple_web import Handler, PORT

    # Never kill arbitrary processes on the port — bind a free port instead
    try:
        port = _pick_port(PORT)
    except OSError as exc:
        print(f"Cannot start desktop app: {exc}", file=sys.stderr)
        return 1

    if port != PORT:
        print(f"Port {PORT} busy — using {port}", file=sys.stderr)

    server = HTTPServer(("localhost", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    # Wait for server
    url = f"http://localhost:{port}"
    for _ in range(50):
        try:
            import urllib.request
            urllib.request.urlopen(url, timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)

    # Launch native window
    webview.create_window(
        "Check Please",
        url,
        width=1100,
        height=800,
        min_size=(800, 600),
    )
    try:
        webview.start(gui="gtk")
    except Exception:
        webview.start()
    server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
