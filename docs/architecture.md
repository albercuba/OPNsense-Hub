# OPNsense Hub architecture

OPNsense Hub is split into two separately deployable parts:

1. `os-opnsensehub` OPNsense plugin
2. `opnsense-hub` Dockerized dashboard/control-plane

The platform focuses on secure enrollment, remote firewall access, company grouping, audit logging, and WireGuard peer lifecycle management.

## High-level flow

```mermaid
sequenceDiagram
    participant Admin as Dashboard admin
    participant Hub as Dashboard origin
    participant Proxy as Proxy origin
    participant Plugin as OPNsense plugin
    participant WG as WireGuard tunnel
    participant FW as OPNsense GUI

    Admin->>Hub: Create company
    Admin->>Hub: Generate short-lived OTP
    Plugin->>Plugin: Generate WireGuard keypair locally
    Plugin->>Hub: POST /api/v1/enroll with OTP + public key + metadata
    Hub->>Hub: Validate hashed OTP, validate WG overlay config, allocate /32 IP
    Hub->>WG: Add peer public key with firewall tunnel /32 only
    Hub-->>Plugin: Device token + WireGuard client config
    Plugin->>Plugin: Validate returned /32 values before saving state
    Plugin->>Plugin: Store token/private key locally, render WG config
    Plugin->>WG: Start client tunnel
    Plugin->>Hub: Heartbeat with device token
    Admin->>Hub: Log in and receive revocable session token
    Admin->>Hub: POST /devices/{id}/proxy/open with CSRF token
    Hub->>Hub: Check session, RBAC, and audit access
    Hub-->>Admin: Handoff page with short-lived one-time grant
    Admin->>Proxy: POST /proxy/bootstrap with grant
    Proxy->>Proxy: Consume grant and set host-only device-scoped cookie
    Admin->>Proxy: Open /proxy/devices/{id}/
    Proxy->>FW: Reverse proxy through tunnel
```

## Dashboard/control-plane

- FastAPI serves both REST API and server-rendered UI.
- PostgreSQL stores users, companies, enrollment codes, devices, sessions, events, and audit logs.
- Dashboard auth uses random server-side session tokens stored hashed with expiration and revocation.
- Device token bearer auth protects post-enrollment device endpoints.
- WireGuard server setup is bootstrapped by the app container on startup.
- Startup validates `HUB_WG_CIDR` and `HUB_WG_ADDRESS`, generates/persists the Hub server key, renders `wg0.conf`, brings up `wg0`, and restores non-revoked peers from the database.
- WireGuard peers are managed by a small validated wrapper around `wg set`.
- Peer routes are `/32` only: one unique firewall tunnel IP per device. Customer LAN subnets are never routed, so overlapping company LANs do not conflict.
- By default the Hub disables IPv4/IPv6 forwarding and installs an idempotent firewall rule that drops forwarded `wg0 -> wg0` traffic to preserve peer isolation.
- `PUBLIC_URL` is the dashboard/control-plane origin and `PROXY_PUBLIC_URL` is a required, distinct proxy origin. Both require DNS and TLS in production.
- Opening a firewall starts with a CSRF-protected POST on the dashboard origin. After session and company-scoped RBAC checks, the Hub renders a standalone handoff that automatically POSTs a short-lived, single-use grant to `/proxy/bootstrap` on the proxy origin.
- The bootstrap consumes the grant and establishes a host-only proxy cookie whose path is scoped to `/proxy/devices/{device_id}`. The cookie authorizes only that device proxy path and is not shared with the dashboard origin.
- Reverse proxying is implemented in FastAPI and proxies requests from `/proxy/devices/{device_id}/*` to `https://{device_tunnel_ip}:443`.
- Edge routing enforces the origin split: the dashboard host denies `/proxy/*`, while the proxy host exposes only `/proxy/bootstrap` and `/proxy/devices/*`; dashboard, authentication, settings, and API routes return `404` on the proxy origin.
- A lightweight background scheduler marks active, non-revoked devices for a firmware status check once per day at `23:00` in the Hub process timezone.
- The Hub only stores and displays reported firmware status; it does not probe or install firewall updates itself.
- Branding uploads are stored in a persistent directory and served back through `/branding/logo`, with uploaded assets taking precedence over any configured fallback logo URL.

For local development without kernel WireGuard access, set `WG_DRY_RUN=true`. For real tunnels, the app container runs with `NET_ADMIN` and `/dev/net/tun` so it can configure `wg0` itself.

## OPNsense plugin

The plugin is scaffolded using standard OPNsense MVC/configd layout:

- PHP MVC controllers only save settings and invoke configd actions.
- Privileged operations live in Python scripts under `src/opnsense/scripts/OPNsense/OPNsenseHub`.
- The plugin generates the WireGuard private key locally; the private key is never sent to Hub.
- The plugin validates Hub-returned `interface_address` and `allowed_ips` before writing config, reusing saved state, or starting the WireGuard client.
- The plugin checks the Hub heartbeat response for pending firmware-check requests, runs the firmware probe locally on the firewall, and reports normalized status back to the Hub.
- Enrollment code is cleared after successful enrollment.
- Device token is stored locally with restrictive file permissions by the backend script.

Some OPNsense service paths and WireGuard startup commands are marked `verify against current OPNsense plugin conventions` because exact integration can vary by OPNsense and WireGuard plugin version.

## Security boundaries

- OTPs are hashed at rest and single-use.
- Dashboard session tokens and device tokens are generated randomly and stored hashed in the Hub database.
- Device revocation removes the WireGuard peer and marks the device revoked.
- Dashboard users are authorized at company scope through `company_users`.
- The Hub never stores OPNsense administrator passwords.
- Firewall access is authorized on the dashboard origin, handed off through a one-time POST grant, reverse-proxied on the dedicated proxy origin through WireGuard, and audit logged.
- Firmware status reporting is local-first: the firewall plugin performs the check, the Hub stores the result, and no update is installed automatically.
- The dashboard does not create firewall policies, restore config, reboot firewalls, or reconfigure OPNsense beyond the plugin’s own local WireGuard client setup.
- The Hub is not a site-to-site router. It only reaches each firewall web UI through that firewall's unique WireGuard tunnel `/32`.
- Firewalls must never be able to reach each other or route customer LANs through the Hub overlay.
