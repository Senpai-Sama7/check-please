"""Twilio provider — GET /2010-04-01/Accounts/{SID}.json with basic auth."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider, _safe_json


class TwilioProvider(Provider):
    name: ClassVar[str] = "twilio"
    env_patterns: ClassVar[list[re.Pattern]] = [re.compile(r"^TWILIO_AUTH_TOKEN(_ALT\d+)?$")]
    key_format: ClassVar[re.Pattern] = re.compile(r"^[a-f0-9]{32}$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        # Need the account SID from env — stored during matching
        import os
        sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
        if not sid:
            return "network_error", None, None, None, None, "TWILIO_ACCOUNT_SID not set"
        # SEC: Validate SID format to prevent SSRF via path traversal
        if not re.match(r"^AC[a-f0-9]{32}$", sid):
            return "network_error", None, None, None, None, "Invalid TWILIO_ACCOUNT_SID format"
        resp = await client.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
            auth=(sid, key),
        )
        if resp.status_code == 200:
            data = _safe_json(resp)
            name = data.get("friendly_name", "unknown")
            status = data.get("status", "unknown")
            if status == "suspended":
                return "suspended_account", None, None, None, None, f"Account suspended: {name}"
            return "valid", f"{name} ({status})", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid credentials"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limited"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
