# check_please — Credential Audit Pipeline

## Location
`/home/donovan/Documents/.cred/check_please/`

## What It Does
Single command (`./start.sh`) that:
1. Sets up Python venv + deps
2. Parses messy 616-line `.env` → clean `.env.organized` (244 entries, 11 categories)
3. Runs self-test suite (7/7 invariants)
4. Audits credentials against live APIs (13 providers, 25 keys)
5. Auto-prunes dead keys (auth_failed/invalid_format)
6. Auto-deduplicates identical values
7. Saves JSON report to `audit_report.json`

## Providers (13)
anthropic, cerebras, deepseek, github, google, groq, huggingface, mistral, nvidia, openai, openrouter, stripe, together, twilio

## Key Files
- `start.sh` — entry point, 9-step pipeline
- `organize_env.py` — parses messy .env, categorizes, dedupes, outputs clean file
- `credential_auditor/` — async audit package (httpx + rich)
  - `providers/` — one file per provider, auto-discovered
  - `self_test.py` — 7 invariant checks
  - `orchestrator.py` — async gather with error isolation
- `.env` — original messy file (untouched)
- `.env.organized` — clean output (auto-regenerated each run)
- `audit_report.json` — latest audit results

## Last Run Results (2026-02-27)
20 valid, 5 pruned (Gemini ALT2, HF personal token, OpenAI ALT3/ALT4, Twilio auth token)

## Adding a Provider
Create `credential_auditor/providers/<name>_p.py` with a class extending `Provider`. Set `name`, `env_patterns`, `key_format`, and implement `async validate()`. Auto-discovered on next run.
