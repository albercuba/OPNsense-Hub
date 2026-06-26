from __future__ import annotations

from .models import IntegrationSettings


def smtp_email_configured(integration_settings: IntegrationSettings | None) -> bool:
    if not integration_settings or not integration_settings.smtp_enabled:
        return False
    return bool(
        integration_settings.smtp_host
        and integration_settings.smtp_port
        and integration_settings.smtp_from
    )


def graph_email_configured(integration_settings: IntegrationSettings | None) -> bool:
    if not integration_settings or not integration_settings.graph_enabled:
        return False
    return bool(
        integration_settings.graph_tenant_id
        and integration_settings.graph_client_id
        and integration_settings.graph_client_secret
        and integration_settings.graph_sender
    )


def email_settings_configured(integration_settings: IntegrationSettings | None) -> bool:
    return smtp_email_configured(integration_settings) or graph_email_configured(
        integration_settings
    )
