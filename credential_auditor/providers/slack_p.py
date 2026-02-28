"""Slack provider — POST auth.test with Bearer token."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class SlackProvider(Provider):
    name: ClassVar[str] = "slack"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^SLACK_(BOT_TOKEN|TOKEN|API_TOKEN)(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^xox[bpas]-[A-Za-z0-9-]{10,}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "unknown")
            return "quota_exhausted", None, None, None, None, f"Rate limited, retry after {retry}s"
        if resp.status_code != 200:
            return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
        data = resp.json()
        if not data.get("ok"):
            err = data.get("error", "unknown_error")
            if err in ("invalid_auth", "not_authed", "token_revoked"):
                return "auth_failed", None, None, None, None, err
            if err == "account_inactive":
                return "suspended_account", None, None, None, None, err
            if err == "missing_scope":
                return "insufficient_scope", None, None, None, None, err
            return "auth_failed", None, None, None, None, err
        user = data.get("user", "unknown")
        team = data.get("team", "unknown")
        return "valid", f"{user}@{team}", None, None, None, None
