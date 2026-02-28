"""Native desktop app — embeds the web UI in a real OS window via pywebview."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

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
    from http.server import HTTPServer

    # Start web server in background thread
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    # Wait for server
    url = f"http://127.0.0.1:{PORT}"
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
    webview.start()
    server.shutdown()
    return 0

if __name__ == "__main__":
    sys.exit(main())
