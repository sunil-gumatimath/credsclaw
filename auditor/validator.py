"""Standalone validation functions for discovered API keys.

Each function takes a (key, timeout) and returns True/False/None.
Supports an optional ``session`` parameter to reuse a single aiohttp.ClientSession
across multiple validation calls for efficiency.
"""

import logging
import ssl as _ssl
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


def create_validator_session(
    no_ssl_verify: bool = False, timeout: int = 10
) -> aiohttp.ClientSession:
    """Create a ClientSession with optional SSL verification bypass."""
    connector_kwargs: dict = {}
    if no_ssl_verify:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        connector_kwargs["ssl"] = ctx
    t = aiohttp.ClientTimeout(total=timeout)
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(**connector_kwargs), timeout=t
    )


async def validate_openai_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_anthropic_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_google_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    # No reliable lightweight validation endpoint for Google AI keys.
    # Preserved as a stub for future implementation.
    return None


async def validate_github_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Accept": "application/vnd.github+json",
                },
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_slack_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                data = await response.json()
                return data.get("ok") is True
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_huggingface_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_cloudflare_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                data = await response.json()
                return data.get("success") is True
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_replicate_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.replicate.com/v1/account",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_groq_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.groq.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_openrouter_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://openrouter.ai/api/v1/auth/key",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_together_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.together.xyz/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_mistral_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    try:
        async def _do(s: aiohttp.ClientSession) -> Optional[bool]:
            async with s.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_aws_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    # AWS keys require both Access Key ID AND Secret Access Key.
    # Preserved as a stub for future implementation.
    return None


async def validate_azure_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[bool]:
    # Azure connection strings require SDK-based validation.
    # Preserved as a stub for future implementation.
    return None


# ---------------------------------------------------------------------------
# Validation registry  (provider_display_name -> callable)
#
# Only providers with actual API validation endpoints are registered.
# Stubs (Google, AWS, Twilio, Azure) are excluded to avoid unnecessary
# session creation in batch_validate_keys().
# ---------------------------------------------------------------------------
VALIDATION_MAP = {
    "OpenAI": validate_openai_key,
    "Anthropic": validate_anthropic_key,
    "GitHub": validate_github_key,
    "Slack": validate_slack_key,
    "HuggingFace": validate_huggingface_key,
    "Cloudflare": validate_cloudflare_key,
    "Replicate": validate_replicate_key,
    "Groq": validate_groq_key,
    "OpenRouter": validate_openrouter_key,
    "Together AI": validate_together_key,
    "Mistral AI": validate_mistral_key,
}
