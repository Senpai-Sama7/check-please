"""OpenAI provider — GET /v1/models with Bearer token."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider, _extract_rate_limit, _safe_json


class OpenAIProvider(Provider):
    name: ClassVar[str] = "openai"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^OPENAI_API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^sk-[A-Za-z0-9_-]{20,}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        rl = _extract_rate_limit(resp)
        if resp.status_code == 200:
            data = _safe_json(resp)
            model_count = len(data.get("data", []))
            return "valid", f"{model_count} models accessible", None, rl, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, rl, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, rl, None, "Rate limit or quota exceeded"
        if resp.status_code == 403:
            body = _safe_json(resp)
            code = body.get("error", {}).get("code", "")
            if "account" in code or "deactivated" in code:
                return "suspended_account", None, None, rl, None, code
            return "insufficient_scope", None, None, rl, None, code or "Forbidden"
        return "network_error", None, None, rl, None, f"HTTP {resp.status_code}"
