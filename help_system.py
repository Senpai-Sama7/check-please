"""Plain-language help system — 8 topics for non-technical users."""

TOPICS = {
    "getting-started": {
        "title": "🚀 Getting Started",
        "body": (
            "Welcome to Check Please — a tool that checks whether your API keys still work.\n\n"
            "What does it do?\n"
            "  It reads a file called .env (where your keys are stored), contacts each\n"
            "  service (like OpenAI, GitHub, Stripe, etc.), and tells you which keys\n"
            "  are still valid and which ones have expired or been revoked.\n\n"
            "How to run it:\n"
            "  • Easy mode (recommended):   ./start.sh --easy\n"
            "  • Simple menu:               ./start.sh --simple\n"
            "  • Web browser:               ./start.sh --web\n"
            "  • Full pipeline:             ./start.sh\n"
            "  • Terminal UI:               ./start.sh --tui\n\n"
            "What you need:\n"
            "  1. Python 3.10 or newer (the tool checks this for you)\n"
            "  2. A .env file with your API keys\n"
            "  3. An internet connection (to contact the services)\n"
        ),
    },
    "api-keys": {
        "title": "🔑 What Are API Keys?",
        "body": (
            "An API key is like a password that lets a program talk to an online service.\n\n"
            "For example:\n"
            "  • An OpenAI key lets your code use ChatGPT\n"
            "  • A GitHub key lets your code access repositories\n"
            "  • A Stripe key lets your code process payments\n\n"
            "Where do they come from?\n"
            "  You create them on each service's website, usually under 'Settings' or\n"
            "  'API' or 'Developer' sections.\n\n"
            "Why check them?\n"
            "  Keys can stop working if you rotated them, hit a usage limit, had your\n"
            "  account suspended, or accidentally leaked them.\n"
            "  This tool checks all of them at once.\n"
        ),
    },
    "env-file": {
        "title": "📄 The .env File",
        "body": (
            "A .env file is a simple text file that stores your API keys, one per line.\n\n"
            "It looks like this:\n"
            "  OPENAI_API_KEY=sk-abc123...\n"
            "  GITHUB_TOKEN=ghp_xyz789...\n"
            "  STRIPE_SECRET_KEY=sk_live_...\n\n"
            "Rules:\n"
            "  • One key per line, format: NAME=VALUE\n"
            "  • Lines starting with # are comments (ignored)\n"
            "  • Keep this file private — never share it or commit it to git\n\n"
            "Where should it be?\n"
            "  Put your .env file in the same folder as this tool.\n"
        ),
    },
    "security": {
        "title": "🛡️ Security & Privacy",
        "body": (
            "Your keys are safe. Here's how:\n\n"
            "  ✓ Keys never leave your computer (except to verify with the real service)\n"
            "  ✓ No keys are stored in logs — only fingerprints like 'sk-a...z (48)'\n"
            "  ✓ No data is sent to us or any third party\n"
            "  ✓ The tool warns you if your .env file permissions are too open\n"
            "  ✓ Output files are checked for unsafe permissions before writing\n\n"
            "Best practice: run  chmod 600 .env  so only you can read your key file.\n"
        ),
    },
    "results": {
        "title": "📊 Understanding Your Results",
        "body": (
            "After a scan, each key gets one of these statuses:\n\n"
            "  ✅ valid              — Key works! The service accepted it.\n"
            "  ❌ auth_failed        — Key was rejected (expired or revoked).\n"
            "  ⚠️  quota_exhausted    — Key works but you've used up your allowance.\n"
            "  ⚠️  suspended_account  — Your account is suspended.\n"
            "  ⚠️  insufficient_scope — Key lacks needed permissions.\n"
            "  🔶 invalid_format     — Key doesn't match the expected pattern.\n"
            "  🌐 network_error      — Couldn't reach the service.\n\n"
            "What to do:\n"
            "  • auth_failed → Log into that service and create a new key\n"
            "  • quota_exhausted → Add credits or wait for your limit to reset\n"
            "  • network_error → Check your internet and try again\n"
        ),
    },
    "troubleshooting": {
        "title": "🔧 Troubleshooting",
        "body": (
            "Common problems and solutions:\n\n"
            "'Python not found' or 'Python 3.10+ required'\n"
            "  → Install Python from https://python.org/downloads\n\n"
            "'.env not found'\n"
            "  → Make sure your .env file is in the same folder as start.sh\n"
            "  → Or specify: ./start.sh --env /path/to/.env\n\n"
            "'Permission denied'\n"
            "  → Run: chmod +x start.sh\n\n"
            "'Network error' on all keys\n"
            "  → Check your internet connection\n"
            "  → Some corporate networks block API calls\n\n"
            "'Module not found' errors\n"
            "  → Delete the .venv folder and run ./start.sh again\n\n"
            "Everything says 'auth_failed'\n"
            "  → Your keys may genuinely be expired\n"
            "  → Double-check you copied the full key\n"
        ),
    },
    "best-practices": {
        "title": "✨ Best Practices",
        "body": (
            "Tips for keeping your API keys safe and organized:\n\n"
            "  1. Run this tool regularly — catch dead keys early\n"
            "  2. Keep .env permissions tight — run: chmod 600 .env\n"
            "  3. Never commit .env to git — add it to .gitignore\n"
            "  4. Rotate keys periodically — replace old keys with new ones\n"
            "  5. Use one key per project — don't share keys across projects\n"
            "  6. Delete keys you don't use — fewer keys = smaller risk\n"
            "  7. Use .env.organized — it groups keys by service\n"
            "  8. Save reports — use --output report.json to track over time\n"
        ),
    },
    "glossary": {
        "title": "📖 Glossary",
        "body": (
            "Terms explained simply:\n\n"
            "  API         — A way for programs to talk to online services\n"
            "  API key     — A password that identifies your program to a service\n"
            "  .env file   — A text file that stores your API keys\n"
            "  Provider    — A service like OpenAI, GitHub, Stripe, etc.\n"
            "  Validation  — Checking if a key still works\n"
            "  Fingerprint — A safe preview of a key (e.g., 'sk-a...z (48)')\n"
            "  Redaction   — Hiding sensitive parts of a key in output\n"
            "  Cache       — Saved results to avoid re-checking unchanged keys\n"
            "  Audit       — The process of checking all your keys\n"
            "  TUI         — Terminal User Interface (visual text-based screen)\n"
            "  Rotate      — Replace an old key with a new one\n"
        ),
    },
}


def show_topic(name: str) -> None:
    t = TOPICS.get(name)
    if not t:
        print(f"  Unknown topic. Available: {', '.join(TOPICS)}")
        return
    print(f"\n{'═' * 60}")
    print(f"  {t['title']}")
    print(f"{'═' * 60}")
    print(t["body"])


def show_index() -> None:
    print(f"\n{'═' * 60}")
    print("  📚 Help Topics")
    print(f"{'═' * 60}\n")
    for i, t in enumerate(TOPICS.values(), 1):
        print(f"  {i}. {t['title']}")
    print(f"\n  Type a number to read a topic, or 'q' to go back.\n")


def interactive() -> None:
    keys = list(TOPICS)
    while True:
        show_index()
        choice = input("  Your choice: ").strip().lower()
        if choice in ("q", "quit", "exit", "back", ""):
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                show_topic(keys[idx])
                input("\n  Press Enter to continue...")
            else:
                print("  Please pick a number from the list.")
        except ValueError:
            if choice in TOPICS:
                show_topic(choice)
                input("\n  Press Enter to continue...")
            else:
                print("  Please pick a number from the list.")


if __name__ == "__main__":
    interactive()
