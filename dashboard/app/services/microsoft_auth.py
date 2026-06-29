from __future__ import annotations

import base64
import hashlib
from typing import Any, cast
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import Request

from ..models import IntegrationSettings
from ..security import random_token
from ..web import settings
from .common import clean_optional, is_valid_email_address
from .local_ad_auth import split_display_name


def microsoft_authority_url(
    integration_settings: IntegrationSettings | None,
) -> str | None:
    if not integration_settings or not integration_settings.microsoft_tenant_id:
        return None
    if integration_settings.microsoft_authority:
        return integration_settings.microsoft_authority.rstrip("/")
    return (
        "https://login.microsoftonline.com/"
        + integration_settings.microsoft_tenant_id.strip()
    )


def microsoft_access_scope(
    integration_settings: IntegrationSettings | None,
) -> str | None:
    if not integration_settings or not integration_settings.microsoft_audience:
        return None
    audience = integration_settings.microsoft_audience.strip()
    audience = audience.removeprefix("api://")
    audience = audience.removesuffix("/access_as_user")
    if not audience:
        return None
    return f"api://{audience}/access_as_user"


def microsoft_redirect_uri(request: Request) -> str:
    public_base = settings.public_url.rstrip("/")
    callback_path = str(request.url_for("microsoft_callback").path)
    return public_base + callback_path


def microsoft_pkce_verifier() -> str:
    return random_token(64)


def microsoft_pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def microsoft_login_authorize_url(
    integration_settings: IntegrationSettings,
    request: Request,
    state: str,
    verifier: str,
    login_hint: str | None = None,
) -> str:
    authority_url = microsoft_authority_url(integration_settings)
    scope = microsoft_access_scope(integration_settings)
    if not authority_url or not scope:
        raise RuntimeError("Microsoft sign-in is not configured")
    query_params = {
        "client_id": integration_settings.microsoft_client_id or "",
        "response_type": "code",
        "redirect_uri": microsoft_redirect_uri(request),
        "response_mode": "query",
        "scope": f"openid profile email {scope}",
        "state": state,
        "code_challenge": microsoft_pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    normalized_login_hint = clean_optional(login_hint)
    if normalized_login_hint:
        query_params["login_hint"] = normalized_login_hint
    query = urlencode(query_params)
    return authority_url.rstrip("/") + "/oauth2/v2.0/authorize?" + query


def exchange_microsoft_authorization_code(
    integration_settings: IntegrationSettings,
    request: Request,
    code: str,
    verifier: str,
    client_secret: str | None,
) -> dict[str, Any]:
    authority_url = microsoft_authority_url(integration_settings)
    scope = microsoft_access_scope(integration_settings)
    if not authority_url or not scope:
        raise RuntimeError("Microsoft sign-in is not configured")
    token_url = authority_url.rstrip("/") + "/oauth2/v2.0/token"
    with httpx.Client(timeout=20) as client:
        response = client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": integration_settings.microsoft_client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": microsoft_redirect_uri(request),
                "code_verifier": verifier,
                "scope": f"openid profile email {scope}",
            },
        )
        response.raise_for_status()
        payload = cast(dict[str, Any], response.json())
    if not payload.get("access_token"):
        raise RuntimeError("Microsoft sign-in did not return an access token")
    return payload


def microsoft_group_matches(groups: list[str], *candidates: str | None) -> bool:
    normalized_groups = {group.strip().lower() for group in groups if group.strip()}
    for candidate in candidates:
        normalized = (candidate or "").strip().lower()
        if normalized and normalized in normalized_groups:
            return True
    return False


def microsoft_role_from_groups(
    integration_settings: IntegrationSettings,
    groups: list[str],
    existing_role: str | None,
) -> tuple[str, bool]:
    admin_mapped = bool(
        integration_settings.microsoft_admin_group_name
        or integration_settings.microsoft_admin_group_id
    )
    user_mapped = bool(
        integration_settings.microsoft_user_group_name
        or integration_settings.microsoft_user_group_id
    )
    if microsoft_group_matches(
        groups,
        integration_settings.microsoft_admin_group_name,
        integration_settings.microsoft_admin_group_id,
    ):
        return "administrator", True
    if microsoft_group_matches(
        groups,
        integration_settings.microsoft_user_group_name,
        integration_settings.microsoft_user_group_id,
    ):
        return "user", True
    if admin_mapped or user_mapped:
        return existing_role or "user", False
    return existing_role or "user", True


def validate_microsoft_access_token(
    integration_settings: IntegrationSettings, token: str
) -> dict[str, Any]:
    authority_url = microsoft_authority_url(integration_settings)
    if not authority_url or not integration_settings.microsoft_tenant_id:
        raise RuntimeError("Microsoft sign-in is not configured")
    jwks_client = jwt.PyJWKClient(authority_url.rstrip("/") + "/discovery/v2.0/keys")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = cast(
        dict[str, Any],
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        ),
    )
    tenant_id = integration_settings.microsoft_tenant_id.strip()
    expected_issuers = {
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/",
        authority_url.rstrip("/") + "/v2.0",
    }
    if str(claims.get("iss", "")) not in expected_issuers:
        raise RuntimeError("Microsoft token has an invalid issuer")
    audience = (integration_settings.microsoft_audience or "").strip()
    normalized_audience = audience.removeprefix("api://").removesuffix(
        "/access_as_user"
    )
    token_aud = claims.get("aud")
    allowed_audiences = {normalized_audience, f"api://{normalized_audience}"}
    if str(token_aud) not in allowed_audiences:
        raise RuntimeError("Microsoft token has an invalid audience")
    claim_names = claims.get("_claim_names")
    if isinstance(claim_names, dict) and "groups" in claim_names:
        raise RuntimeError(
            "Microsoft token uses group overage claims. Configure the app registration to emit groups for the API token or reduce group memberships before login."
        )
    return claims


def microsoft_user_identity(
    claims: dict[str, Any],
) -> tuple[str, str | None, str | None, list[str]]:
    email = clean_optional(
        str(
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("upn")
            or ""
        )
    )
    if not email or not is_valid_email_address(email):
        raise RuntimeError("Microsoft token does not contain a usable email address")
    first_name, last_name = split_display_name(cast(str | None, claims.get("name")))
    groups = [str(group) for group in cast(list[Any], claims.get("groups") or [])]
    return email, first_name, last_name, groups
