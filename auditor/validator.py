"""Standalone validation functions for discovered API keys.

Each function takes a (key, timeout) and returns True/False/None.
"""

import logging
import ssl as _ssl
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


def _create_validator_session(
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
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_anthropic_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_google_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    # No reliable lightweight validation endpoint for Google AI keys
    return None


async def validate_stripe_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.stripe.com/v1/account",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_github_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
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
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_slack_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                data = await response.json()
                return data.get("ok") is True
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_sendgrid_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.sendgrid.com/v3/user/profile",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_huggingface_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_cloudflare_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                data = await response.json()
                return data.get("success") is True
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_supabase_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    try:
        async with _create_validator_session(no_ssl_verify, timeout) as session:
            async with session.get(
                "https://api.supabase.com/v1/projects",
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def validate_aws_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    # AWS keys require both Access Key ID AND Secret Access Key.
    return None


async def validate_twilio_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    # Twilio keys require both Account SID/API Key AND Auth Token/Secret.
    return None


async def validate_azure_key(
    key: str, timeout: int = 10, no_ssl_verify: bool = False
) -> Optional[bool]:
    # Azure connection strings require SDK-based validation.
    return None


# ---------------------------------------------------------------------------
# Validation registry  (provider_display_name -> callable)
# ---------------------------------------------------------------------------
VALIDATION_MAP = {
    "OpenAI": validate_openai_key,
    "Anthropic": validate_anthropic_key,
    "Google": validate_google_key,
    "Stripe": validate_stripe_key,
    "GitHub": validate_github_key,
    "Slack": validate_slack_key,
    "SendGrid": validate_sendgrid_key,
    "HuggingFace": validate_huggingface_key,
    "Cloudflare": validate_cloudflare_key,
    "Supabase": validate_supabase_key,
    "AWS": validate_aws_key,
    "Twilio": validate_twilio_key,
    "Azure": validate_azure_key,
}
