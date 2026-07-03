# Security notes and production hardening checklist

## Current protections

- OTP enrollment codes are generated randomly, short-lived, single-use, and stored only as PBKDF2 hashes.
- Dashboard login now uses random server-side session tokens stored only as HMAC-SHA256 hashes in PostgreSQL with expiration and revocation support.
- Device tokens are random, shown only to the enrolling plugin, and stored hashed in PostgreSQL.
- WireGuard private keys are generated locally on OPNsense and never sent to Hub.
- Hub validates `HUB_WG_CIDR` and `HUB_WG_ADDRESS` at startup before allocating or restoring peers.
- Hub only installs `/32` WireGuard `AllowedIPs` for each firewall tunnel IP and never routes customer LAN subnets.
- Startup validation now fails closed on unsafe forwarding/isolation combinations, such as enabling IP forwarding while moving network control outside the app or disabling inline isolation rule management.
- When inline isolation is enabled, startup explicitly verifies that the `wg0 -> wg0` drop rule exists after installation.
- The OPNsense plugin validates Hub-returned `interface_address` and `allowed_ips` before writing config, reusing saved state, or starting the tunnel.
- Hub disables IPv4 and IPv6 forwarding by default unless `HUB_ENABLE_IP_FORWARDING=true`.
- When enabled, Hub startup installs an idempotent `wg0 -> wg0` forward-drop isolation rule using nftables or iptables so one firewall cannot talk to another through the Hub.
- Dashboard RBAC checks happen before device detail, revoke, and proxy access.
- Proxy access and revocation are audit logged.
- Revocation invalidates the stored device token hash and removes the WireGuard peer.
- The Hub never stores OPNsense web UI credentials.

## Isolation invariant

Every enrolled firewall gets a unique WireGuard tunnel IPv4 address. The only route installed on the Hub for a firewall peer is that firewall tunnel `/32`, and the only route installed on the firewall for the Hub peer is the Hub tunnel `/32`.

This is intentional:

- firewalls must not be able to reach each other
- the Hub may reach each firewall WebGUI through its unique tunnel IP
- customer LANs must never be routed through the management overlay
- overlapping customer LANs remain safe because they are never advertised as WireGuard `AllowedIPs`

The `wg0 -> wg0` forward-drop rule is a defense-in-depth control that prevents firewall-to-firewall forwarding on the Hub even if OS forwarding or other host routing changes are introduced later. The runtime now hard-fails if unsafe forwarding/isolation settings are combined, and the `/32`-only peer-route invariant is covered by unit tests so customer LAN CIDRs are not added to peer routes by accident.

## Redacted/sensitive fields

Never log or display these values:

- OTP enrollment codes after initial display.
- Device tokens.
- Dashboard session tokens.
- WireGuard private keys.
- OPNsense administrator passwords or session cookies.
- Any firewall GUI credentials proxied through the Hub.

## Production hardening checklist

- `security: enforce HTTPS and secure cookies` — set `APP_ENV=production`, `SESSION_SECURE=true`, and deploy behind HTTPS.
- `security: replace default secrets` — set a long random `SECRET_KEY`, admin password, and database password.
- `security: replace the default admin address` — set `INITIAL_ADMIN_EMAIL` to a real admin mailbox.
- `security: verify firewall TLS` — set `PROXY_VERIFY_TLS=true` in production unless you explicitly accept the risk with `ALLOW_INSECURE_PROXY_TLS_IN_PRODUCTION=true`.
- `security: restrict incoming hostnames` — set `ALLOWED_HOSTS` to the real Hub hostname(s) used by browsers and reverse proxies.
- `security: trust only known reverse proxies` — set `TRUSTED_PROXY_CIDRS` to the proxy IPs/subnets that are allowed to supply `X-Forwarded-For`.
- `security: use a production rate-limit backend` — prefer `RATE_LIMIT_BACKEND=redis` with `RATE_LIMIT_REDIS_URL` configured, or enforce rate limits at the edge when using `RATE_LIMIT_BACKEND=edge`.
- `security: keep MFA throttling enabled` — tune `RATE_LIMIT_MFA_ATTEMPTS` and `RATE_LIMIT_MFA_WINDOW_SECONDS` conservatively for internet-facing deployments.
- `security: bound proxy and restore payload sizes` — review `MAX_PROXY_REQUEST_BYTES`, `MAX_PROXY_RESPONSE_BYTES`, `MAX_BACKUP_RESTORE_BYTES`, `MAX_BACKUP_RESTORE_ENTRIES`, `MAX_BACKUP_RESTORE_TOTAL_UNCOMPRESSED_BYTES`, and `MAX_BACKUP_RESTORE_FILE_BYTES` for your deployment.
- `security: minimize web-app privilege` — use `NETWORK_CONTROL_MODE=external` when WireGuard bootstrap and runtime firewall management are handled by a sidecar or host service.
- `security: keep browser hardening headers enabled` — leave `SECURITY_HEADERS_ENABLED=true` and only relax `CONTENT_SECURITY_POLICY`, `REFERRER_POLICY`, or `PERMISSIONS_POLICY` intentionally.
- `security: keep management-only routing` — continue rejecting customer LAN routes in WireGuard `AllowedIPs` to avoid cross-company routing and overlapping subnet conflicts.
- `security: keep IP forwarding disabled` — leave `HUB_ENABLE_IP_FORWARDING=false` unless you intentionally manage peer routing outside the app.
- `security: keep Hub firewall isolation enabled` — leave `HUB_MANAGE_FIREWALL_RULES=true` so startup installs the `wg0 -> wg0` forward-drop rule.
- `security: pin firewall certificates` — replace trust bypasses with certificate pinning or an internal CA when possible.
- `security: isolate WireGuard management` — for higher-assurance deployments, consider moving WireGuard bootstrap and peer updates into a minimal privileged sidecar or host service.
- `security: rate limit login and enrollment` — add IP/user rate limits to auth and enrollment endpoints.
- `security: add CSRF protection` — server-rendered forms should get CSRF tokens before production use.
- `security: encrypt database backups` — configs, token hashes, metadata, uploaded branding assets, and audit data are sensitive.
- `security: monitor audit logs` — alert on repeated failed enrollment, unexpected proxy opens, and revocations.
