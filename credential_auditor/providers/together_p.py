"""Together AI provider — GET /v1/models with Bearer token (OpenAI-compatible)."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class TogetherProvider(Provider):
    name: ClassVar[str] = "together"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^TOGETHER_(AI_)?API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^[a-f0-9]{64}$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.together.xyz/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 200:
            count = len(resp.json())  # Together returns a list, not {data:[]}
            return "valid", f"{count} models accessible", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limit exceeded"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
