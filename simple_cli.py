"""Simple CLI — numbered menu interface, no flags to remember."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _menu(title: str, options: list[str]) -> int:
    """Show a numbered menu, return 0-based index or -1 for quit."""
    print(f"\n  {title}\n")
    for i, opt in enumerate(options, 1):
        print(f"    {i}. {opt}")
    print(f"    q. Back / Quit\n")
    while True:
        raw = input("  Your choice: ").strip().lower()
        if raw in ("q", "quit", "exit", "back"):
            return -1
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        print(f"    Please enter 1-{len(options)} or 'q'.")


def _find_env() -> Path | None:
    for p in [DIR / ".env", Path.cwd() / ".env"]:
        if p.is_file():
            return p
    return None


def _run_audit(env_path: Path, extra_args: list[str] | None = None) -> int:
    cmd = [sys.executable, "-m", "credential_auditor", "--env", str(env_path), "--timeout", "30"]
    if extra_args:
        cmd.extend(extra_args)
    print()
    return subprocess.run(cmd, cwd=str(DIR)).returncode


def _pick_env() -> Path | None:
    """Let user pick or enter .env path."""
    found = _find_env()
    if found:
        print(f"\n  Found .env file: {found}")
        use = input("  Use this file? (y/n, default y): ").strip().lower() or "y"
        if use in ("y", "yes"):
            return found
    raw = input("\n  Enter path to your .env file: ").strip()
    p = Path(raw).expanduser()
    if p.is_file():
        return p
    print(f"  ❌ File not found: {raw}")
    return None


def run() -> int:
    while True:
        _clear()
        print()
        print("  ╔══════════════════════════════════════════════╗")
        print("  ║       🔐 Check Please — Simple Menu         ║")
        print("  ╚══════════════════════════════════════════════╝")

        choice = _menu("What would you like to do?", [
            "🔍 Check my API keys — see which ones work",
            "👀 Preview — show what would be checked (no network calls)",
            "📋 List supported services (16 providers)",
            "🧪 Run self-test — verify the tool works correctly",
            "💾 Save report to file",
            "📚 Help — learn about API keys, security, and more",
            "🚀 Quick start guide — first-time tutorial",
        ])

        if choice == -1:
            print("\n  👋 Goodbye! Run  ./start.sh --simple  to come back.\n")
            return 0

        if choice == 0:  # Check keys
            env = _pick_env()
            if env:
                rc = _run_audit(env)
                if rc == 0:
                    print("\n  🎉 All keys are valid!")
                elif rc == 1:
                    print("\n  ⚠️  Some keys have issues — see results above.")
                else:
                    print("\n  😕 Something went wrong — check messages above.")
            input("\n  Press Enter to continue...")

        elif choice == 1:  # Preview
            env = _pick_env()
            if env:
                _run_audit(env, ["--dry-run"])
            input("\n  Press Enter to continue...")

        elif choice == 2:  # List providers
            subprocess.run([sys.executable, "-m", "credential_auditor", "--list-providers"], cwd=str(DIR))
            input("\n  Press Enter to continue...")

        elif choice == 3:  # Self-test
            print("\n  Running self-test...\n")
            rc = subprocess.run([sys.executable, "-m", "credential_auditor", "--self-test"], cwd=str(DIR)).returncode
            if rc == 0:
                print("\n  ✅ All tests passed! The tool is working correctly.")
            else:
                print("\n  ❌ Some tests failed. Try deleting .venv and running ./start.sh again.")
            input("\n  Press Enter to continue...")

        elif choice == 4:  # Save report
            env = _pick_env()
            if env:
                out = input("  Save report as (default: report.json): ").strip() or "report.json"
                _run_audit(env, ["--output", out, "--force-insecure-output"])
                if Path(out).exists():
                    print(f"\n  ✅ Report saved to: {out}")
                else:
                    print(f"\n  ❌ Could not save report.")
            input("\n  Press Enter to continue...")

        elif choice == 5:  # Help
            from help_system import interactive
            interactive()

        elif choice == 6:  # Quick start
            from quick_start_guide import run as qs_run
            qs_run()

    return 0


def main() -> int:
    from user_friendly_errors import wrap_main
    return wrap_main(run, "running simple menu")


if __name__ == "__main__":
    sys.exit(main())
