"""GitHub provider — GET /user with Bearer token.

Status discrimination from Kimi's analysis:
- 200 = valid
- 401 = auth_failed
- 403 + x-ratelimit-remaining=0 = quota_exhausted
- 403 otherwise = insufficient_scope
"""

from __future__ import annotations

import re
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import RateLimitInfo, Status
from credential_auditor.providers import Provider, _extract_rate_limit, _safe_json


class GitHubProvider(Provider):
    name: ClassVar[str] = "github"
    env_patterns: ClassVar[list[re.Pattern]] = [
        re.compile(r"^GITHUB_(TOKEN|API_KEY|PAT)(_ALT\d+)?$"),
        re.compile(r"^GH_TOKEN(_ALT\d+)?$"),
    ]
    key_format: ClassVar[re.Pattern] = re.compile(
        r"^(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|v[0-9]\.[0-9a-f]{40})$"
    )

    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str],
    ]:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {key}", "Accept": "application/vnd.github+json"},
        )
        rl = _extract_rate_limit(resp)
        if resp.status_code == 200:
            data = _safe_json(resp)
            login = data.get("login", "unknown")
            scopes = [s.strip() for s in resp.headers.get("x-oauth-scopes", "").split(",") if s.strip()]
            return "valid", f"user:{login}", scopes or None, rl, None, None
        if resp.status_code == 401:
            return "auth_failed", None, None, rl, None, "Bad credentials"
        if resp.status_code == 403:
            remaining = resp.headers.get("x-ratelimit-remaining", "1")
            if remaining == "0":
                return "quota_exhausted", None, None, rl, None, "Rate limit exceeded"
            return "insufficient_scope", None, None, rl, None, "Forbidden — missing scopes"
        return "network_error", None, None, rl, None, f"HTTP {resp.status_code}"
