"""Stripe provider — GET /v1/account with Basic auth (key as username)."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class StripeProvider(Provider):
    name: ClassVar[str] = "stripe"
    env_patterns: ClassVar[list[re.Pattern]] = [
        re.compile(r"^(STRIPE_(SECRET_KEY|API_KEY|RESTRICTED_KEY)|PRIVATE_KEY)(_ALT\d+)?$"),
    ]
    key_format: ClassVar[re.Pattern] = re.compile(r"^(sk|rk)_(test|live)_[A-Za-z0-9]{10,}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get("https://api.stripe.com/v1/account", auth=(key, ""))
        if resp.status_code == 200:
            data = resp.json()
            acct_id = data.get("id", "unknown")
            charges = "enabled" if data.get("charges_enabled") else "disabled"
            return "valid", f"{acct_id} (charges: {charges})", None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid API key"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limited"
        if resp.status_code == 403:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            err = body.get("error", {})
            if err.get("code") == "account_invalid":
                return "suspended_account", None, None, None, None, "Account suspended"
            return "insufficient_scope", None, None, None, None, err.get("message", "Forbidden")
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
