"""Easy mode — guided wizard for non-technical users."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent


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
    candidates = [DIR / ".env", Path.cwd() / ".env", Path.home() / ".env"]
    for p in candidates:
        if p.is_file():
            return p
    return None


def run() -> int:
    _banner()

    # Welcome
    name = _ask("What's your name? (or press Enter to skip):", default="friend")
    print(f"\n  👋 Hi {name}! Let's check your API keys.\n")
    print("  This tool reads your .env file and checks if your API keys")
    print("  still work. It's safe — your keys never leave your computer")
    print("  (except to verify with the real service).\n")

    # Experience level
    print("  How comfortable are you with command-line tools?\n")
    level = _ask("Pick one:", ["Beginner — I'm new to this", "Intermediate — I know the basics", "Advanced — I'm comfortable"])
    is_beginner = "Beginner" in level
    print()

    # Find .env
    env_path = _find_env()
    if env_path:
        print(f"  ✅ Found your .env file: {env_path}")
        use_it = _ask("Use this file? (y/n):", default="y")
        if use_it.lower() not in ("y", "yes"):
            env_path = None

    if not env_path:
        print("\n  📄 Where is your .env file?")
        print("     (This is the file that contains your API keys)")
        if is_beginner:
            print("     It's usually in your project folder, named exactly '.env'\n")
        while True:
            raw = _ask("Path to .env file (or 'q' to quit):")
            if raw.lower() in ("q", "quit"):
                print("\n  👋 No problem! Come back anytime.\n")
                return 0
            p = Path(raw).expanduser()
            if p.is_file():
                env_path = p
                break
            print(f"    Couldn't find a file at: {raw}")
            print("    Make sure you typed the full path.\n")

    # What to do
    print(f"\n  Great! We'll check the keys in: {env_path}\n")
    print("  What would you like to do?\n")
    action = _ask("Pick one:", [
        "Check my keys — see which ones work and which don't",
        "Preview only — show what would be checked (no network calls)",
        "Open help — learn more about this tool",
    ])

    if "help" in action.lower():
        from help_system import interactive
        interactive()
        return 0

    dry = "Preview" in action
    print()

    # Run
    if is_beginner:
        print("  ⏳ Contacting services to verify your keys...")
        print("     This usually takes 10-30 seconds.\n")
    else:
        print("  ⏳ Running audit...\n")

    cmd = [sys.executable, "-m", "credential_auditor", "--env", str(env_path), "--timeout", "30"]
    if dry:
        cmd.append("--dry-run")

    result = subprocess.run(cmd, cwd=str(DIR))

    print()
    if result.returncode == 0:
        print("  🎉 All your keys are valid! Everything looks good.")
    elif result.returncode == 1:
        print("  ⚠️  Some keys have issues — check the results above.")
        if is_beginner:
            print("     Keys marked 'auth_failed' need to be replaced.")
            print("     Log into that service's website and create a new key.")
    else:
        print("  😕 Something went wrong. Check the messages above.")
        print("     For help, run: python help_system.py")

    # Next steps
    print(f"\n  What next, {name}?\n")
    nxt = _ask("Pick one:", [
        "Run again",
        "Open help topics",
        "Try the simple menu interface",
        "Quit",
    ])
    if "again" in nxt.lower():
        return run()
    if "help" in nxt.lower():
        from help_system import interactive
        interactive()
    if "simple" in nxt.lower():
        from simple_cli import run as simple_run
        return simple_run()

    print(f"\n  👋 Bye {name}! Run  ./start.sh --easy  anytime to come back.\n")
    return 0


def main() -> int:
    from user_friendly_errors import wrap_main
    return wrap_main(run, "running easy mode")


if __name__ == "__main__":
    sys.exit(main())
