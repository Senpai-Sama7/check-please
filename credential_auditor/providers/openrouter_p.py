"""OpenRouter provider — GET /api/v1/models with Bearer token."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class OpenRouterProvider(Provider):
    name: ClassVar[str] = "openrouter"
    env_patterns: ClassVar[list[re.Pattern]] = [
        re.compile(r"^OPEN_ROUTER_(API_KEY|MANAGEMENT_KEY)(_ALT\d+)?$"),
    ]
    key_format: ClassVar[re.Pattern] = re.compile(r"^sk-or-v1-[a-f0-9]{64}$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://openrouter.ai/api/v1/auth/key",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            label = data.get("label", "unnamed")
            limit = data.get("limit")
            usage = data.get("usage")
            detail = f"label:{label}"
            if limit is not None:
                detail += f" limit:${limit/100:.2f}" if limit else " unlimited"
            if usage is not None:
                detail += f" used:${usage/100:.2f}"
            return "valid", detail, None, None, None, None
        if resp.status_code in (401, 403):
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limit exceeded"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
