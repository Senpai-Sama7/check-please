"""SendGrid provider — GET /v3/user/profile with Bearer token."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class SendGridProvider(Provider):
    name: ClassVar[str] = "sendgrid"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^SENDGRID_API_KEY(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            scopes = data.get("scopes", [])
            return "valid", None, scopes or None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 403:
            return "insufficient_scope", None, None, None, None, "Forbidden"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limited"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
