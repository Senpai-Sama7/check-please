"""Anthropic provider — GET /v1/models with x-api-key header."""

from __future__ import annotations

import re
import time
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class AnthropicProvider(Provider):
    name: ClassVar[str] = "anthropic"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^ANTHROPIC_API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        )
        rl = self._parse_rate_limit(resp)
        if resp.status_code == 200:
            data = resp.json()
            model_count = len(data.get("data", []))
            return "valid", f"{model_count} models accessible", None, rl, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, rl, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, rl, None, "Rate limit exceeded"
        if resp.status_code == 403:
            return "insufficient_scope", None, None, rl, None, "Forbidden"
        return "network_error", None, None, rl, None, f"HTTP {resp.status_code}"

    @staticmethod
    def _parse_rate_limit(resp: httpx.Response) -> Optional[RateLimitInfo]:
        try:
            limit = int(resp.headers.get("anthropic-ratelimit-requests-limit", 0))
            remaining = int(resp.headers.get("anthropic-ratelimit-requests-remaining", 0))
            reset_s = int(resp.headers.get("anthropic-ratelimit-requests-reset", 0))
            if limit == 0 and remaining == 0:
                return None
            return RateLimitInfo(limit=limit, remaining=remaining, reset_ts=int(time.time()) + reset_s)
        except (TypeError, ValueError):
            return None
