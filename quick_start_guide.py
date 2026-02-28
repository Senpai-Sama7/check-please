"""Quick start guide — 4-step first-run tutorial for absolute beginners."""

from __future__ import annotations

import os
import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _pause(msg: str = "Press Enter to continue..."):
    input(f"\n  {msg}")


def _step(num: int, total: int, title: str):
    _clear()
    print()
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  🚀 Quick Start — Step {num} of {total}: {title:<16}│")
    print(f"  └─────────────────────────────────────────────┘")
    bar = "█" * num + "░" * (total - num)
    print(f"  Progress: [{bar}] {num}/{total}")
    print()


def run() -> int:
    _clear()
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║       🚀 Check Please — Quick Start         ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    print("  Welcome! This 4-step guide will get you up and running.")
    print("  It takes about 2 minutes. You can quit anytime with Ctrl+C.\n")
    name = input("  What's your name? (or press Enter to skip): ").strip() or "friend"
    print(f"\n  Nice to meet you, {name}! Let's get started.\n")
    _pause()

    # Step 1: What is this tool?
    _step(1, 4, "What Is This?")
    print("  Check Please is a tool that checks your API keys.\n")
    print("  What's an API key?")
    print("    It's like a password that lets your programs talk to")
    print("    online services like OpenAI, GitHub, Stripe, etc.\n")
    print("  What does this tool do?")
    print("    1. Reads your .env file (where keys are stored)")
    print("    2. Contacts each service to check if the key works")
    print("    3. Shows you which keys are valid and which aren't\n")
    print("  Your keys are safe — they never leave your computer")
    print("  except to verify with the real service.\n")
    _pause()

    # Step 2: Find your .env file
    _step(2, 4, "Your .env File")
    env_path = DIR / ".env"
    if env_path.is_file():
        count = sum(1 for l in env_path.read_text().splitlines() if "=" in l and not l.strip().startswith("#"))
        print(f"  ✅ Found your .env file with ~{count} entries!")
        print(f"     Location: {env_path}\n")
    else:
        print("  📄 You'll need a .env file with your API keys.")
        print("     It's a text file that looks like this:\n")
        print("       OPENAI_API_KEY=sk-abc123...")
        print("       GITHUB_TOKEN=ghp_xyz789...\n")
        print("     Create one in this folder, then run this guide again.\n")
        _pause("Press Enter to exit...")
        return 0
    _pause()

    # Step 3: Choose your interface
    _step(3, 4, "Pick Your Style")
    print("  How would you like to use Check Please?\n")
    print("    1. 🌟 Easy Mode — Guided, step-by-step (recommended)")
    print("    2. 💻 Simple Menu — Text menus, no commands to remember")
    print("    3. 🌐 Web Browser — Visual interface in your browser")
    print("    4. 📺 Terminal UI — Rich visual interface in terminal")
    print("    5. ⚡ Command Line — Full power, flags and options\n")
    choice = input("  Pick a number (1-5, default 1): ").strip() or "1"
    modes = {"1": "easy", "2": "simple", "3": "web", "4": "tui", "5": "cli"}
    mode = modes.get(choice, "easy")
    labels = {"easy": "Easy Mode", "simple": "Simple Menu", "web": "Web Browser", "tui": "Terminal UI", "cli": "Command Line"}
    print(f"\n  Great choice! You picked: {labels[mode]}\n")
    _pause()

    # Step 4: Launch
    _step(4, 4, "Ready to Go!")
    print(f"  You're all set, {name}! Here's how to start:\n")
    cmds = {
        "easy": "./start.sh --easy",
        "simple": "./start.sh --simple",
        "web": "./start.sh --web",
        "tui": "./start.sh --tui",
        "cli": "./start.sh",
    }
    print(f"    👉  {cmds[mode]}\n")
    print("  Other useful commands:")
    print("    ./start.sh --help       — See all options")
    print("    python help_system.py   — Read help topics")
    print("    ./start.sh --easy       — Guided mode anytime\n")

    launch = input(f"  Launch {labels[mode]} now? (y/n, default y): ").strip().lower() or "y"
    if launch in ("y", "yes"):
        print()
        if mode == "easy":
            from easy_mode import run as easy_run
            return easy_run()
        elif mode == "simple":
            from simple_cli import run as simple_run
            return simple_run()
        elif mode == "web":
            from simple_web import run as web_run
            return web_run()
        else:
            import subprocess
            return subprocess.run(cmds[mode].split(), cwd=str(DIR)).returncode

    print(f"\n  👋 See you later, {name}! Run the command above when you're ready.\n")
    return 0


def main() -> int:
    from user_friendly_errors import wrap_main
    return wrap_main(run, "running quick start guide")


if __name__ == "__main__":
    sys.exit(main())
