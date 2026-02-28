"""User-friendly error messages with plain-language recovery steps."""

from __future__ import annotations

# Map technical errors to (friendly_message, recovery_steps)
_ERRORS: dict[str, tuple[str, list[str]]] = {
    "FileNotFoundError": (
        "We couldn't find that file.",
        [
            "Make sure your .env file is in the same folder as start.sh",
            "Check for typos in the file name",
            "Try: ./start.sh --env /full/path/to/your/.env",
        ],
    ),
    "PermissionError": (
        "We don't have permission to access that file.",
        [
            "Run: chmod 600 .env  (makes it readable by you only)",
            "Run: chmod +x start.sh  (if the launcher won't start)",
            "Make sure you own the file: ls -la .env",
        ],
    ),
    "ConnectionError": (
        "We couldn't connect to the internet.",
        [
            "Check your Wi-Fi or ethernet connection",
            "Try opening a website in your browser to confirm internet works",
            "If you're behind a corporate firewall, ask IT about proxy settings",
        ],
    ),
    "TimeoutError": (
        "The request took too long and timed out.",
        [
            "Your internet connection might be slow — try again",
            "The service might be temporarily down — wait a few minutes",
            "Try increasing the timeout: ./start.sh --timeout 60",
        ],
    ),
    "JSONDecodeError": (
        "We received an unexpected response from a service.",
        [
            "This usually means the service is having issues — try again later",
            "If it keeps happening, the service's API may have changed",
        ],
    ),
    "ModuleNotFoundError": (
        "A required component is missing.",
        [
            "Delete the .venv folder and run ./start.sh again",
            "This will reinstall everything from scratch",
            "If that doesn't work, make sure Python 3.10+ is installed",
        ],
    ),
    "KeyboardInterrupt": (
        "You stopped the process — that's totally fine!",
        ["Just run the command again whenever you're ready."],
    ),
    "IsADirectoryError": (
        "That path is a folder, not a file.",
        [
            "Make sure you're pointing to your .env file, not a folder",
            "Example: ./start.sh --env .env",
        ],
    ),
}


def friendly_error(exc: BaseException, context: str = "") -> str:
    """Return a user-friendly error message with recovery steps."""
    etype = type(exc).__name__
    match = _ERRORS.get(etype)

    # Try partial matching for subclasses (e.g., httpx.ConnectError → ConnectionError)
    if not match:
        for base in type(exc).__mro__:
            match = _ERRORS.get(base.__name__)
            if match:
                break

    if match:
        msg, steps = match
    else:
        msg = "Something unexpected went wrong."
        steps = [
            "Try running the command again",
            "If it keeps happening, check the troubleshooting guide: python help_system.py",
        ]

    lines = [f"\n  😕 {msg}"]
    if context:
        lines.append(f"     (while {context})")
    lines.append("")
    lines.append("  Let's fix it:")
    for i, step in enumerate(steps, 1):
        lines.append(f"    {i}. {step}")
    lines.append("")
    lines.append("  💡 For more help, run: python help_system.py")
    lines.append(f"     Technical detail: {etype}: {exc}")
    lines.append("")
    return "\n".join(lines)


def print_friendly_error(exc: BaseException, context: str = "") -> None:
    """Print a user-friendly error message."""
    print(friendly_error(exc, context))


def wrap_main(func, context: str = "running the tool"):
    """Run func(), catching exceptions and printing friendly messages. Returns exit code."""
    try:
        return func()
    except KeyboardInterrupt:
        print_friendly_error(KeyboardInterrupt(), context)
        return 130
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except Exception as e:
        print_friendly_error(e, context)
        return 1
