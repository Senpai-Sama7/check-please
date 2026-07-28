"""Native desktop app — embeds the web UI in a real OS window via pywebview."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

__version__ = "1.1.1"


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


def _window_state_path() -> Path:
    """Path to the persistent window state JSON file."""
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "check-please"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        return Path.home() / ".check_please_window.json"
    return base / "window.json"


def _load_window_state() -> dict:
    """Load persisted window geometry; return safe defaults on any failure."""
    p = _window_state_path()
    if not p.is_file():
        return {"width": 1100, "height": 800, "x": None, "y": None}
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            return {"width": 1100, "height": 800, "x": None, "y": None}
        # Validate
        w = int(data.get("width", 1100))
        h = int(data.get("height", 800))
        if w < 800 or h < 600 or w > 7680 or h > 4320:
            w, h = 1100, 800
        x = data.get("x")
        y = data.get("y")
        x = int(x) if isinstance(x, (int, float)) else None
        y = int(y) if isinstance(y, (int, float)) else None
        return {"width": w, "height": h, "x": x, "y": y}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"width": 1100, "height": 800, "x": None, "y": None}


def _save_window_state(state: dict) -> None:
    """Persist window geometry; swallow any error to avoid exit noise."""
    try:
        _window_state_path().write_text(json.dumps(state))
        try:
            os.chmod(_window_state_path(), 0o600)
        except OSError:
            pass
    except OSError:
        pass


def main() -> int:
    try:
        import webview
    except ImportError:
        print("pywebview required: pip install pywebview", file=sys.stderr)
        return 1

    # Import the web server
    app_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(app_dir))
    try:
        from simple_web import Handler, PORT
    except ImportError as exc:
        print(f"Cannot import web server: {exc}", file=sys.stderr)
        return 1

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

    # Load persisted window geometry
    state = _load_window_state()
    win_kwargs: dict = {
        "title": f"Check Please v{__version__}",
        "url": url,
        "width": state["width"],
        "height": state["height"],
        "min_size": (800, 600),
    }
    if state["x"] is not None and state["y"] is not None:
        try:
            win_kwargs["x"] = int(state["x"])
            win_kwargs["y"] = int(state["y"])
        except (TypeError, ValueError):
            pass

    # Launch native window
    window = webview.create_window(**win_kwargs)

    def _persist_geometry():
        try:
            new_state = {
                "width": int(window.width),
                "height": int(window.height),
                "x": int(window.x) if window.x is not None else None,
                "y": int(window.y) if window.y is not None else None,
            }
            _save_window_state(new_state)
        except Exception:
            pass

    # Persist on close (some platforms)
    if window is not None:
        try:
            window.events.closing += _persist_geometry  # type: ignore[attr-defined]
        except AttributeError:
            pass

    try:
        webview.start(gui="gtk")
    except Exception:
        webview.start()
    _persist_geometry()
    server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
