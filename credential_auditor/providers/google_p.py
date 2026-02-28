"""Google Gemini/AI provider — GET /v1beta/models with API key as query param."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class GoogleProvider(Provider):
    name: ClassVar[str] = "google"
    env_patterns: ClassVar[list[re.Pattern]] = [
        re.compile(r"^(GOOGLE_API_KEY|GEMINI_API_KEY)(_ALT\d+)?$"),
    ]
    key_format: ClassVar[re.Pattern] = re.compile(r"^AIza[A-Za-z0-9_-]{35,60}$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": key},
        )
        if resp.status_code == 200:
            data = resp.json()
            model_count = len(data.get("models", []))
            return "valid", f"{model_count} models accessible", None, None, None, None
        if resp.status_code == 400:
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 403:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            msg = body.get("error", {}).get("message", "Forbidden")
            if "disabled" in msg.lower() or "not enabled" in msg.lower():
                return "suspended_account", None, None, None, None, msg
            return "insufficient_scope", None, None, None, None, msg
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Quota exceeded"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
