"""HuggingFace provider — GET /api/whoami-v2 with Bearer token."""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider


class HuggingFaceProvider(Provider):
    name: ClassVar[str] = "huggingface"
    env_patterns: ClassVar[list[re.Pattern]] = [
        re.compile(r"^(HUGGINGFACE_TOKEN|HF_TOKEN|HF_API_KEY|HF_PERSONAL_AUTHENTICATION_TOKEN|HUGGING_FACE_API_KEY)(_ALT\d+)?$"),
    ]
    key_format: ClassVar[re.Pattern] = re.compile(r"^hf_[A-Za-z0-9]{20,}(_ALT\d+)?$")

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://huggingface.co/api/whoami-v2",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("name", "unknown")
            orgs = [o.get("name", "") for o in data.get("orgs", [])]
            acct = f"{username}" + (f" (orgs: {', '.join(orgs)})" if orgs else "")
            fgrained = data.get("auth", {}).get("accessToken", {})
            scopes = fgrained.get("role", None)
            return "valid", acct, [scopes] if scopes else None, None, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, None, None, "Invalid token"
        if resp.status_code == 403:
            return "insufficient_scope", None, None, None, None, "Forbidden"
        if resp.status_code == 429:
            return "quota_exhausted", None, None, None, None, "Rate limited"
        return "network_error", None, None, None, None, f"HTTP {resp.status_code}"
