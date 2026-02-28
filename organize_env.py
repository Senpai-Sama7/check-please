#!/usr/bin/env python3
"""Reorganize a messy .env file into clean, categorized, properly formatted sections.

Handles:
- Inconsistent quoting, spacing, comment styles
- Duplicate keys (keeps all, marks with #N suffix)
- Freeform text/instructions mixed with env vars
- Section headers in various formats (---, #, ----, etc.)
- Numbered alternates (#2=, #3=, #4 KEY=)
- Keys with missing or malformed names
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

# ── Provider categorization by key prefix / name patterns ──────────────────

CATEGORIES: dict[str, list[re.Pattern]] = {
    "AI & LLM Providers": [
        re.compile(r"(OPENAI|ANTHROPIC|CLAUDE|GEMINI|MISTRAL|GROQ|DEEPSEEK|KIMI|CEREBRAS|NVIDIA|TOGETHER|LITELLM|OLLAMA|VENICE|ZEN)", re.I),
        re.compile(r"(OPEN_ROUTER|CLINE|KILO_CODE|QODO|JULES|ALIBABA)", re.I),
    ],
    "GitHub & Dev Tools": [
        re.compile(r"(GITHUB|GH_TOKEN|FIGMA|SENTRY|CODACY|SONAR|LANGSMITH|LANGFUSE|APIFY|COMPOSIO|AMPLITUDE|RUBE|CONTEXT7|PYPI|WARP|OPEN_CLAW)", re.I),
    ],
    "Cloud Providers (AWS, GCP, DigitalOcean, Vercel, Cloudflare, Neon)": [
        re.compile(r"(AWS|AMAZON|NOVA_ACT|DIGITAL_OCEAN|VERCEL|CLOUDFLARE|NEON|NGROK|TAILSCALE)", re.I),
    ],
    "Database & Storage": [
        re.compile(r"(DATABASE_URL|POSTGRES|PGHOST|PGUSER|PGDATABASE|PGPASSWORD|REDIS|NEO4J|WEAVIATE|PINECONE|SUPABASE|ISN_DB)", re.I),
    ],
    "Financial APIs": [
        re.compile(r"(POLYGON|FINNHUB|NEWS_API|ALPHAVANTAGE|ALPHA_VANTAGE|STRIPE|PUBLISHABLE_KEY|PRIVATE_KEY|RESTRICTED.KEY|BALLDONTLIE)", re.I),
    ],
    "Communication & Social": [
        re.compile(r"(TWILIO|SLACK|TWITTER|TELEGRAM|EMAIL|SMTP|SENDER_EMAIL|RECIPIENT_EMAIL|NOTIFICATION_EMAIL|RETELL|META_ACCESS)", re.I),
    ],
    "Auth & Security": [
        re.compile(r"(JWT|API_AUTH_TOKEN|MCP_ENCRYPT|BEARER_TOKEN|SHARED_KEY|STACK_SECRET|STACK_PUBLISHABLE|STACK_PROJECT|PAYLOAD_SECRET|SEED_ADMIN)", re.I),
    ],
    "Search & Data": [
        re.compile(r"(BRAVE|SHODAN|RAPID|WORLD_NEWS|ZAPIER|NOTION|WEB3FORM|JARVIS)", re.I),
    ],
    "HuggingFace": [
        re.compile(r"(HF_|HUGGING)", re.I),
    ],
    "Application Config": [
        re.compile(r"(PORT|NODE_ENV|LOG_LEVEL|MCP_PATH|Q_TRUST|BASE_URL|KAFKA|REGION|CLUSTER|TEXT_MODEL|ALLOW_TEST|SITE_DOMAIN|ADMIN_DOMAIN|CMS_PORT|FRONTEND_PORT|OLLAMA_BASE_URL|NEXT_PUBLIC_OLLAMA|OPEN_API_PROMPT|OPEN_API_VECTOR)", re.I),
    ],
}


def categorize(key: str) -> str:
    for cat, patterns in CATEGORIES.items():
        for p in patterns:
            if p.search(key):
                return cat
    return "Uncategorized"


def parse_env_line(line: str) -> tuple[str | None, str | None]:
    """Extract (KEY, VALUE) from a line, or (None, None) if not a valid assignment."""
    # Standard: KEY=VALUE or KEY="VALUE" or export KEY=VALUE
    # Also handles keys with hyphens, slashes, spaces
    m = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_./\- ]*?)\s*=\s*(.*)', line)
    if m:
        key = m.group(1).strip()
        val = m.group(2).strip()
        # Strip surrounding quotes if balanced
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        # Normalize key: replace spaces/hyphens with underscores
        key = re.sub(r'[\s\-/]+', '_', key)
        return key, val
    return None, None


def parse_numbered_alt(line: str) -> tuple[str | None, str | None, str | None]:
    """Parse lines like '#2 OPENAI_API_KEY=...' or '#2=sk-proj-...'"""
    # Pattern: #N KEY=VALUE
    m = re.match(r'^#(\d+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
    if m:
        return m.group(2), m.group(3).strip().strip('"').strip("'"), m.group(1)
    # Pattern: #N=VALUE (unnamed alternate, try to infer from value prefix)
    m = re.match(r'^#(\d+)\s*=\s*(.*)', line)
    if m:
        return None, m.group(2).strip().strip('"').strip("'"), m.group(1)
    return None, None, None


def infer_key_name(value: str) -> str:
    """Guess a key name from the value prefix."""
    prefixes = {
        "sk-proj-": "OPENAI_API_KEY",
        "sk-ant-": "ANTHROPIC_API_KEY",
        "sk-kimi-": "KIMI_API_KEY",
        "ghp_": "GITHUB_TOKEN",
        "gsk_": "GROQ_API_KEY",
        "hf_": "HF_TOKEN",
        "AIza": "GOOGLE_API_KEY",
        "sk-or-": "OPEN_ROUTER_API_KEY",
        "xox": "SLACK_TOKEN",
        "SG.": "SENDGRID_API_KEY",
        "sk_live_": "STRIPE_SECRET_KEY",
        "pk_live_": "STRIPE_PUBLISHABLE_KEY",
        "rk_live_": "STRIPE_RESTRICTED_KEY",
        "sk_test_": "STRIPE_SECRET_KEY_TEST",
        "nvapi-": "NVIDIA_API_KEY",
        "wk-": "WARP_API_KEY",
        "sk-lf-": "LANGFUSE_SECRET_KEY",
        "pk-lf-": "LANGFUSE_PUBLIC_KEY",
    }
    for prefix, name in prefixes.items():
        if value.startswith(prefix):
            return name
    return "UNKNOWN_KEY"


def organize_env(input_path: Path, output_path: Path) -> None:
    lines = input_path.read_text().splitlines()

    entries: list[tuple[str, str, str]] = []  # (category, key, value)
    seen_keys: defaultdict[str, int] = defaultdict(int)
    skipped: list[str] = []

    for raw in lines:
        line = raw.strip()

        # Skip empty, pure comments/headers, freeform text
        if not line:
            continue
        if re.match(r'^-{2,}.*-{2,}$', line):  # --- SECTION ---
            continue
        if re.match(r'^#{1,4}\s*[A-Z]', line) and '=' not in line:
            continue
        if line.startswith('#') and '=' not in line:
            continue

        # Try recovering commented-out KEY=VALUE lines (e.g. "# KIMI-CLI_API_KEY=sk-...")
        if line.startswith('#') and '=' in line:
            stripped = re.sub(r'^#\s*', '', line)
            # Skip if it looks like instructions/code, not a key
            if not re.match(r'[A-Za-z_][A-Za-z0-9_\s\-/]*=\S', stripped):
                continue
            # Skip diff-format lines ("+ 5: ISN_DB_HOST=...")
            if stripped.startswith('+'):
                continue
            key, val = parse_env_line(stripped)
            if key and val:
                seen_keys[key] += 1
                display_key = key if seen_keys[key] == 1 else f"{key}_ALT{seen_keys[key]}"
                cat = categorize(key)
                entries.append((cat, display_key, val))
                continue

        # Try numbered alternate (#2=..., #3 KEY=...)
        alt_key, alt_val, alt_num = parse_numbered_alt(line)
        if alt_val is not None:
            if alt_key is None:
                alt_key = infer_key_name(alt_val)
            seen_keys[alt_key] += 1
            suffix = f"_ALT{alt_num or seen_keys[alt_key]}"
            cat = categorize(alt_key)
            entries.append((cat, f"{alt_key}{suffix}", alt_val))
            continue

        # Try diff-format lines: "+     5: KEY=VALUE"
        m = re.match(r'^#?\s*\+\s*\d+:\s*(.+)', line)
        if m:
            key, val = parse_env_line(m.group(1).strip())
            if key and val:
                seen_keys[key] += 1
                display_key = key if seen_keys[key] == 1 else f"{key}_ALT{seen_keys[key]}"
                entries.append((categorize(key), display_key, val))
                continue

        # Try standard KEY=VALUE
        key, val = parse_env_line(line)
        if key and val is not None:
            # Skip code artifacts (lowercase Python vars, JSON fragments, etc.)
            if re.match(r'^[a-z]', key) and key not in ("pypi_api_token",):
                # But recover if value looks like a known credential prefix
                if not any(val.startswith(p) for p in ("sk-proj-", "sk-ant-", "sk-or-", "sk-kimi-", "gsk_", "hf_", "nvapi-", "AIza")):
                    skipped.append(line)
                    continue
            # Skip empty values
            if not val:
                continue
            # Fix mangled Langfuse keys (nested quotes from code snippets)
            if key == "public_key" and val.startswith('"pk-lf-'):
                key, val = "LANGFUSE_PUBLIC_KEY", val.strip('"').rstrip('",')
            elif key == "secret_key" and val.startswith('"sk-lf-'):
                key, val = "LANGFUSE_SECRET_KEY", val.strip('"').rstrip('",')
            # Rename gRPC_EndPoint to proper env var name
            elif key == "gRPC_EndPoint":
                key = "WEAVIATE_GRPC_ENDPOINT"
            seen_keys[key] += 1
            display_key = key if seen_keys[key] == 1 else f"{key}_ALT{seen_keys[key]}"
            cat = categorize(key)
            entries.append((cat, display_key, val))
            continue

        # Lines that look like they contain secrets but aren't parseable — skip
        if any(c in line for c in ['=', 'key', 'token', 'secret']) and not line.startswith(('#', '-', '"', '`')):
            skipped.append(line)

    # ── Deduplicate: remove entries with identical values to an earlier key ──
    seen_vals: dict[str, str] = {}
    deduped: list[tuple[str, str, str]] = []
    for cat, key, val in entries:
        base = re.sub(r'_ALT\d+$', '', key)
        val_id = f"{base}:{val}"
        if val_id in seen_vals:
            continue
        seen_vals[val_id] = key
        deduped.append((cat, key, val))
    entries = deduped

    # ── Build output ──────────────────────────────────────────────────────

    grouped: defaultdict[str, list[tuple[str, str]]] = defaultdict(list)
    for cat, key, val in entries:
        grouped[cat].append((key, val))

    # Determine quoting: quote if value contains spaces, special chars, or is empty
    def quote(v: str) -> str:
        if not v or re.search(r'[\s#;$`\\]', v) or v != v.strip():
            return f'"{v}"'
        return f'"{v}"'  # Always quote for consistency

    out_lines: list[str] = []
    cat_order = [c for c in CATEGORIES if c in grouped] + (["Uncategorized"] if "Uncategorized" in grouped else [])

    for i, cat in enumerate(cat_order):
        if i > 0:
            out_lines.append("")
        out_lines.append(f"# {'═' * 60}")
        out_lines.append(f"# {cat}")
        out_lines.append(f"# {'═' * 60}")
        out_lines.append("")
        for key, val in sorted(grouped[cat], key=lambda x: x[0]):
            out_lines.append(f"{key}={quote(val)}")

    if skipped:
        out_lines.append("")
        out_lines.append(f"# {'═' * 60}")
        out_lines.append("# UNPARSEABLE LINES (review manually)")
        out_lines.append(f"# {'═' * 60}")
        for s in skipped:
            out_lines.append(f"# {s}")

    out_lines.append("")  # trailing newline
    output_path.write_text("\n".join(out_lines))
    print(f"✓ Organized {len(entries)} entries into {len(cat_order)} categories → {output_path}")
    if skipped:
        print(f"⚠ {len(skipped)} unparseable lines appended as comments")


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".env")
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_name(".env.organized")
    if not src.exists():
        print(f"Error: {src} not found")
        sys.exit(1)
    organize_env(src, dst)
