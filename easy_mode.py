"""Easy mode — guided wizard for non-technical users."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent
_NAME_FILE = DIR / ".check_please_name"


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _ask(prompt: str, options: list[str] | None = None, default: str = "") -> str:
    """Ask a question, optionally with numbered options."""
    if options:
        for i, opt in enumerate(options, 1):
            print(f"    {i}. {opt}")
        print()
    while True:
        raw = input(f"  {prompt} ").strip()
        if not raw and default:
            return default
        if options:
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            except ValueError:
                pass
            print(f"    Please enter a number 1-{len(options)}.")
        else:
            return raw if raw else default


def _banner():
    _clear()
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║         🔐 Check Please — Easy Mode         ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()


def _find_env() -> Path | None:
    """Look for .env in common locations."""
    for p in [DIR / ".env", Path.cwd() / ".env", Path.home() / ".env"]:
        if p.is_file():
            return p
    return None


def _get_name() -> str:
    """Get name — remembered from last run."""
    if _NAME_FILE.is_file():
        return _NAME_FILE.read_text().strip() or "friend"
    name = _ask("What's your name? (or press Enter to skip):", default="friend")
    if name != "friend":
        _NAME_FILE.write_text(name)
    return name


def run() -> int:
    _banner()

    name = _get_name()
    print(f"  👋 Hi {name}! Let's check your API keys.\n")

    # Find .env automatically — no confirmation needed
    env_path = _find_env()
    if env_path:
        count = sum(1 for l in env_path.read_text().splitlines() if "=" in l and not l.strip().startswith("#"))
        print(f"  ✅ Found {count} keys in {env_path.name}\n")
    else:
        print("  📄 Where is your .env file?")
        print("     (This is the file with your API keys, one per line)\n")
        while True:
            raw = _ask("Path to .env file (or 'q' to quit):")
            if raw.lower() in ("q", "quit"):
                print("\n  👋 No problem! Come back anytime.\n")
                return 0
            p = Path(raw).expanduser()
            if p.is_file():
                env_path = p
                break
            print(f"    Couldn't find a file at: {raw}\n")

    # Single decision: what to do
    action = _ask("What would you like to do?\n", [
        "🔍 Check my keys — see which ones work",
        "👀 Preview only — no network calls",
        "📚 Help — learn about API keys and security",
    ])

    if "Help" in action:
        from help_system import interactive
        interactive()
        return 0

    dry = "Preview" in action
    print("\n  ⏳ Checking your keys... this usually takes 10-30 seconds.\n" if not dry else "")

    cmd = [sys.executable, "-m", "credential_auditor", "--env", str(env_path), "--timeout", "30"]
    if dry:
        cmd.append("--dry-run")

    result = subprocess.run(cmd, cwd=str(DIR))

    # Clear, actionable result message
    print()
    if result.returncode == 0:
        print("  🎉 All your keys are valid! Everything looks good.")
    elif result.returncode == 1:
        print("  ⚠️  Some keys have issues — here's what to do:")
        print("     • Keys marked 'auth_failed' → log into that service and create a new key")
        print("     • Keys marked 'network_error' → check your internet and try again")
        print("     • Keys marked 'quota_exhausted' → add credits or wait for limit reset")
    else:
        print("  😕 Something went wrong. Run  python help_system.py  for troubleshooting.")

    # Quick next-step menu
    print(f"\n  What next, {name}?\n")
    nxt = _ask("Pick one:", ["Run again", "Open help topics", "Try the simple menu", "Quit"])
    if "again" in nxt.lower():
        return run()
    if "help" in nxt.lower():
        from help_system import interactive
        interactive()
    if "simple" in nxt.lower():
        from simple_cli import run as simple_run
        return simple_run()

    print(f"\n  👋 Bye {name}! Run  ./start.sh  anytime to come back.\n")
    return 0


def main() -> int:
    from user_friendly_errors import wrap_main
    return wrap_main(run, "running easy mode")


if __name__ == "__main__":
    sys.exit(main())
