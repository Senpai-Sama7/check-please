"""Native desktop app — embeds the web UI in a real OS window via pywebview."""
from __future__ import annotations

import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path


def _bind_free_server(handler_cls, preferred: int, attempts: int = 20):
    """Try to bind ThreadingHTTPServer directly, avoiding TOCTOU between check and bind."""
    last_exc = None
    for port in range(preferred, preferred + attempts):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
            server.daemon_threads = True
            return server, port
        except OSError as exc:
            last_exc = exc
            continue
    raise OSError(
        f"No free port in range {preferred}–{preferred + attempts - 1}: {last_exc}"
    )


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

    # Bind server with retry to avoid port race
    try:
        server, port = _bind_free_server(Handler, PORT)
    except OSError as exc:
        print(f"Cannot start desktop app: {exc}", file=sys.stderr)
        return 1

    if port != PORT:
        print(f"Port {PORT} busy — using {port}", file=sys.stderr)
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
