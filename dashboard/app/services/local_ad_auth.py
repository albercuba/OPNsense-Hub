from __future__ import annotations

from urllib.parse import urlparse

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from ..models import IntegrationSettings
from .common import clean_optional, is_valid_email_address


def split_display_name(name: str | None) -> tuple[str | None, str | None]:
    normalized = clean_optional(name)
    if not normalized:
        return None, None
    parts = normalized.split(None, 1)
    if len(parts) == 1:
        return parts[0], None
    return parts[0], parts[1]


def base_dn_domain(base_dn: str | None) -> str | None:
    if not base_dn:
        return None
    labels = []
    for part in base_dn.split(","):
        key, _sep, value = part.strip().partition("=")
        if key.lower() == "dc" and value.strip():
            labels.append(value.strip())
    if not labels:
        return None
    return ".".join(labels)


def ldap_server_from_host(host_value: str) -> Server:
    parsed = urlparse(host_value if "://" in host_value else f"ldaps://{host_value}")
    use_ssl = parsed.scheme.lower() == "ldaps"
    host = parsed.hostname or host_value
    port = parsed.port or (636 if use_ssl else 389)
    tls = Tls(validate=0) if use_ssl else None
    return Server(host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)


def local_ad_bind_candidates(identifier: str, base_dn: str | None) -> list[str]:
    candidates: list[str] = []
    stripped = identifier.strip()
    if stripped:
        candidates.append(stripped)
    if stripped and "@" not in stripped and "\\" not in stripped:
        domain = base_dn_domain(base_dn)
        if domain:
            candidates.append(f"{stripped}@{domain}")
    seen = set()
    ordered = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def authenticate_local_ad_user(
    integration_settings: IntegrationSettings, identifier: str, password: str
) -> tuple[str, str | None, str | None]:
    ad_host = integration_settings.ad_host
    ad_base_dn = integration_settings.ad_base_dn
    if not ad_host or not ad_base_dn:
        raise RuntimeError("Local AD sign-in is not configured")
    server = ldap_server_from_host(ad_host)
    login_value = identifier.strip()
    if not login_value or not password:
        raise RuntimeError("Username and password are required")
    last_error = RuntimeError("Local AD sign-in failed")
    for bind_user in local_ad_bind_candidates(login_value, ad_base_dn):
        try:
            with Connection(
                server, user=bind_user, password=password, auto_bind=True
            ) as conn:
                escaped_identifier = escape_filter_chars(login_value)
                localpart = escape_filter_chars(login_value.split("@", 1)[0])
                search_filter = (
                    "(|"
                    f"(mail={escaped_identifier})"
                    f"(userPrincipalName={escaped_identifier})"
                    f"(sAMAccountName={localpart})"
                    f"(cn={escaped_identifier})"
                    ")"
                )
                conn.search(
                    ad_base_dn,
                    search_filter,
                    attributes=[
                        "mail",
                        "userPrincipalName",
                        "givenName",
                        "sn",
                        "displayName",
                    ],
                    size_limit=1,
                )
                entry = conn.entries[0] if conn.entries else None
                email = None
                first_name = None
                last_name = None
                if entry is not None:
                    entry_data = entry.entry_attributes_as_dict
                    email = clean_optional(
                        (entry_data.get("mail") or [None])[0]
                        or (entry_data.get("userPrincipalName") or [None])[0]
                    )
                    first_name = clean_optional(
                        (entry_data.get("givenName") or [None])[0]
                    )
                    last_name = clean_optional((entry_data.get("sn") or [None])[0])
                    if not first_name and not last_name:
                        first_name, last_name = split_display_name(
                            (entry_data.get("displayName") or [None])[0]
                        )
                if not email:
                    candidate_email = (
                        bind_user if is_valid_email_address(bind_user) else login_value
                    )
                    if not is_valid_email_address(candidate_email):
                        raise RuntimeError(
                            "Local AD sign-in succeeded, but no usable email address was found for this account"
                        )
                    email = candidate_email
                return email, first_name, last_name
        except LDAPException as exc:
            last_error = RuntimeError(f"Local AD authentication failed: {exc}")
    raise last_error
