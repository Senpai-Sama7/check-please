"""DeepSeek provider — GET /models with Bearer token (OpenAI-compatible)."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider, _safe_json


class DeepSeekProvider(Provider):
    name: ClassVar[str] = "deepseek"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^DEEPSEEK_API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^sk-[a-f0-9]{32,}$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.deepseek.com/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 200:
            count = len(_safe_json(resp).get("data", []))
            return "valid", f"{count} models accessible", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limit exceeded"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
