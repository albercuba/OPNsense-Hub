# Security notes and production hardening checklist

## Current protections

- OTP enrollment codes are generated randomly, short-lived, single-use, stored only as PBKDF2 hashes, and atomically claimed during enrollment.
- Dashboard login now uses random server-side session tokens stored only as HMAC-SHA256 hashes in PostgreSQL with expiration and revocation support.
- Pending local MFA logins carry a signed nonce bound to a server-side pending-login row; failed authenticator-code attempts are counted in the database and the pending login is invalidated after `RATE_LIMIT_MFA_ATTEMPTS` failures.
- Device tokens are random, shown only to the enrolling plugin, and stored hashed in PostgreSQL.
- WireGuard private keys are generated locally on OPNsense and never sent to Hub.
- Hub validates `HUB_WG_CIDR` and `HUB_WG_ADDRESS` at startup before allocating or restoring peers.
- In the default Compose deployment, the public FastAPI web container runs as unprivileged UID `10001` with all capabilities dropped and no `/dev/net/tun` or `/etc/wireguard` mount; its direct `8083` publication is bound only to `127.0.0.1` so Caddy remains the public HTTP(S) entry point. Only the `opnsense-hub-wireguard` sidecar runs as root with `NET_ADMIN`, `/dev/net/tun`, UDP `51820`, and the WireGuard server key volume.
- Hub only installs `/32` WireGuard `AllowedIPs` for each firewall tunnel IP and never routes customer LAN subnets.
- Production startup fails closed whenever inline tunnel isolation is disabled or network control is external without `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true`, an explicit operator attestation that the external policy was independently verified.
- Inline startup installs and verifies a complete nftables or iptables/ip6tables policy: established return traffic is allowed, new tunnel input is limited to `HUB_WG_CIDR -> HUB_WG_ADDRESS:HUB_CONTROL_PLANE_PORT/TCP`, all other tunnel input is dropped, and all forwarding originating from `wg0` is dropped regardless of output interface.
- The OPNsense plugin validates Hub-returned `interface_address` and `allowed_ips` before writing config, reusing saved state, or starting the tunnel.
- Hub disables IPv4 and IPv6 forwarding by default unless `HUB_ENABLE_IP_FORWARDING=true`. Even when kernel forwarding is enabled, the managed tunnel policy continues to default-drop forwarding from `wg0`.
- Rate-limit keys use the direct peer IP unless that peer is inside `TRUSTED_PROXY_CIDRS`; only then is `X-Forwarded-For` parsed to find the last untrusted client hop. Production startup rejects process-local memory rate limiting in favor of Redis or verified edge enforcement, while development memory buckets are globally pruned and capped by `RATE_LIMIT_MEMORY_MAX_BUCKETS`.
- Dashboard session, CSRF, company-scoped RBAC, device target validation, and revocation checks happen before a connector token is issued.
- Connector tokens are random, short-lived, device-scoped, bound to the issuing dashboard session, stored only as hashes, returned in `no-store` pages, and sent to WSS only in an `Authorization: Bearer` header.
- The connector accepts the token only from a hidden prompt, standard input, or `OPNSENSE_HUB_CONNECTOR_TOKEN`; no CLI token option or token-bearing URL exists.
- Connector access accepts binary frames only and forwards opaque TLS bytes to the firewall WebGUI over the validated WireGuard `/32`. The Hub does not terminate firewall TLS or receive WebGUI credentials/session cookies.
- Connector and optional relay opens are rate limited and audit logged. Device revocation immediately closes tracked local connector/relay access, while active connector streams periodically recheck shared database authorization for cross-worker session revocation, RBAC removal, user deletion, and device revocation.
- Revocation invalidates the stored device token hash and removes the WireGuard peer.
- The OPNsense plugin removes its local tunnel/state only after an explicit revocation response from the primary heartbeat endpoint, currently `410 Gone`; ordinary `401`/`404` failures from heartbeat, firmware reporting, backup upload, version skew, or reverse-proxy errors are recorded as errors without destructive cleanup.
- Complete OPNsense configurations are encrypted and authenticated on the firewall before upload. The Hub stores only opaque `opnsense-config-encrypted-v1` envelopes and never receives the backup master/recovery key.
- The Hub never stores OPNsense web UI credentials.

## Isolation invariant

Every enrolled firewall gets a unique WireGuard public key and tunnel IPv4 address. Enrollment reserves the device row and consumes the OTP in the database before WireGuard runtime changes. If post-commit peer installation fails, the Hub compensates by removing the reserved device row and releasing the OTP for retry. The only route installed on the Hub for a firewall peer is that firewall tunnel `/32`, and the only route installed on the firewall for the Hub peer is the Hub tunnel `/32`.

This is intentional:

- firewalls must not be able to reach each other
- the Hub may reach each firewall WebGUI through its unique tunnel IP
- customer LANs must never be routed through the management overlay
- overlapping customer LANs remain safe because they are never advertised as WireGuard `AllowedIPs`

The forwarding boundary is enforced in the WireGuard sidecar and is interface-origin based, not peer-destination based: every packet entering through `wg0` and reaching the forwarding hook is dropped. This blocks `wg0 -> wg0`, `wg0 -> eth0`, the Docker bridge, and any later routed interface even if kernel forwarding is enabled. The input boundary separately permits established return traffic needed by Hub-initiated WebGUI connections and only one new inbound service tuple: source within `HUB_WG_CIDR`, destination equal to the `HUB_WG_ADDRESS`, TCP destination port `HUB_CONTROL_PLANE_PORT`. New ICMP, UDP, alternate-address, alternate-port, and IPv6 input from peers is dropped.

`NETWORK_CONTROL_MODE=external` and `HUB_MANAGE_FIREWALL_RULES=false` are production-safe only when an equivalent host/sidecar policy has actually been verified and `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true` records that operator attestation. The assertion does not verify policy automatically. The `/32`-only peer-route invariant remains defense in depth and is covered by unit tests so customer LAN CIDRs are not added accidentally.

## Default connector boundary

The default access path has no separate browser proxy origin, `/proxy/bootstrap`, proxy authorization cookie, or L7 reverse proxy to OPNsense.

1. The browser sends a CSRF-protected `POST /devices/{device_id}/proxy/open` to `PUBLIC_URL` using the normal dashboard session.
2. The Hub enforces company RBAC, validates the device's WireGuard target, creates a short-lived device-scoped token bound to the issuing dashboard session, stores only its hash, and returns the token and connector instructions with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
3. The local connector listens on loopback by default. Each local browser TCP connection opens an authenticated `wss://<PUBLIC_URL host>/api/v1/connector/devices/{device_id}` connection with the token in the bearer header.
4. The Hub validates token/device/user/dashboard-session/revocation state and connection limits, opens TCP to the firewall's WireGuard `/32` and `OPNSENSE_GUI_PORT`, rechecks authorization before WSS acceptance and periodically during the stream, and copies opaque binary bytes. OPNsense—not the Hub—terminates browser TLS.

The browser must trust the certificate presented by that OPNsense WebGUI. If its certificate and redirects use a firewall hostname, map that hostname to loopback on the connector host and use connector `--browser-host`; do not disable certificate validation as a convenience. Keep the listener on loopback. A non-loopback listener requires the explicit `--allow-non-loopback` override plus separate workstation firewall controls, and any local process able to reach the listener can use the active connector.

Caddy handles dashboard HTTP(S), including the WSS upgrade, only. The raw relay described below bypasses Caddy.

## Firewall configuration backup boundary

The plugin—not the Hub—reads `/conf/config.xml`. Plugin `0.2` encrypts it locally with AES-256-CBC and authenticates a canonical envelope with an independent HMAC-SHA256 key. Both keys are domain-separated derivations of a random 32-byte master key at `/var/db/opnsensehub/backup_master.key`. OpenSSL receives the derived high-entropy passphrase through standard input, never through process arguments, URLs, logs, or the Hub API.

The Hub enforces these limits:

- backup requests are sent only to plugins advertising `opnsense-config-encrypted-v1`
- an upload is accepted only while a backup request is pending
- legacy `content` fields, unexpected envelope fields, unsupported algorithms, wrong device IDs, invalid base64, non-OpenSSL salt headers, invalid block lengths, and oversized ciphertext are rejected
- retention ordering uses Hub receipt time, preventing a device-supplied future timestamp from pinning a backup
- PostgreSQL stores only `backup_format` and canonical `encrypted_payload`; downloads are opaque `.opnenc` files with `Cache-Control: no-store`
- Hub export format version `2` rejects archives that could restore legacy plaintext firewall backups
- Hub restore requires every expected table in `data.json`, verifies manifest row counts, validates row fields and foreign-key references, and flushes all restored rows in an isolated staging database before deleting existing Hub rows. Restore stages filesystem updates first, commits the database replacement before touching live files, atomically replaces the staged logo/WireGuard key, and then runs idempotent post-commit WireGuard reconciliation.

The Hub cannot verify the HMAC because it intentionally lacks the key. Verification happens before local decryption with `hmac.compare_digest()` on OPNsense. A stolen device token can still submit structurally valid garbage for a pending request, so device-token protection and backup monitoring remain important.

The root-only backup key is deliberately independent from WireGuard and is not deleted during normal disconnect/revocation cleanup. Export it to separate encrypted offline storage using `backup_crypto.py export-key`; never place that recovery file in Hub storage, Hub exports, or the same failure domain as the Hub database. Without this key, backups cannot be recovered after loss of the firewall's `/var/db` state. Import the key before generating backups on replacement hardware to avoid creating a new recovery lineage.

Migration `0012_encrypted_device_backups` deletes existing plaintext rows because converting them at the Hub would require giving the Hub the encryption key. Database deletion does not erase old PostgreSQL snapshots, WAL, filesystem remnants, or prior Hub exports; operators must expire those copies according to their threat model.

## Optional public L4 relay boundary

The raw public relay is disabled by default. It must remain disabled unless both `PUBLIC_L4_RELAY_ENABLED=true` and `PUBLIC_L4_RELAY_MTLS_REQUIRED=true` are set and the deployment has independently verified all of these controls:

- every participating OPNsense WebGUI requires and validates an approved browser client certificate; password-only access is not an adequate relay control
- each WebGUI presents a trusted certificate whose SAN matches its exact generated hostname `d-{device UUID without dashes}.<PROXY_PUBLIC_URL hostname>`
- wildcard DNS under the `PROXY_PUBLIC_URL` hostname resolves generated device names to the correct Hub node
- inbound TCP `55000-55099` is restricted to the Hub and traverses no HTTP proxy or TLS terminator
- the network path preserves the browser's source IP; the relay does not consume PROXY protocol and rejects a TCP peer whose source differs from the IP authorized by the dashboard POST

Use `deploy/docker-compose.l4.yml` to publish TCP `55000-55099`. These raw ports bypass Caddy so browser-to-OPNsense TLS remains end to end. A relay is short-lived, bound to one device and one observed source IP, limited by idle/connection controls, and closed on expiry or revocation.

This relay is single-node/single-process only because listeners and allocations are held in API-process memory. The CSRF/RBAC POST and raw relay connection must reach the same API instance. Source-IP pinning is only defense in depth: users behind the same NAT share a public source IP and are not isolated from each other by this check. Enforced WebGUI client-certificate authentication and exact certificate hostname validation remain mandatory.

## Redacted/sensitive fields

Never log or display these values:

- OTP enrollment codes after initial display.
- Device tokens.
- Dashboard session tokens.
- WireGuard private keys.
- Connector tokens and optional relay allocation details.
- OPNsense administrator passwords, WebGUI session cookies, client-certificate private keys, decrypted WebGUI traffic, plaintext `config.xml`, or firewall backup recovery keys.

## Production hardening checklist

- `security: enforce dashboard HTTPS and secure cookies` — set `APP_ENV=production`, `SESSION_SECURE=true`, and deploy `PUBLIC_URL` behind HTTPS/WSS. `PROXY_PUBLIC_URL` is a distinct base hostname for optional relay DNS, not an L7 origin.
- `security: replace default secrets` — set a long random `SECRET_KEY`, admin password, and database password.
- `security: replace the default admin address` — set `INITIAL_ADMIN_EMAIL` to a real admin mailbox.
- `security: keep the connector local` — bind the user connector to loopback, prefer its hidden prompt, and never place a token in a CLI argument, URL, literal shell command, or shell history. Use a protected secret file/file descriptor for managed automation; process environments may be inspectable.
- `security: validate local firewall TLS` — make the browser trust the OPNsense WebGUI certificate and use a loopback hostname mapping plus `--browser-host` when its SAN does not match `localhost` or `127.0.0.1`.
- `security: restrict incoming hostnames` — set `ALLOWED_HOSTS` to the actual dashboard and configured relay-base hostnames.
- `security: keep the raw relay off by default` — leave `PUBLIC_L4_RELAY_ENABLED=false` unless the documented mTLS, exact hostname, wildcard DNS, source-IP, port, and single-node requirements are all met.
- `security: attest and enforce relay mTLS` — setting `PUBLIC_L4_RELAY_MTLS_REQUIRED=true` is only an operator assertion; verify each OPNsense WebGUI actually rejects clients without a trusted certificate.
- `security: bypass Caddy only for raw relay ports` — Caddy serves dashboard HTTPS/WSS; if enabled, publish TCP `55000-55099` directly with `deploy/docker-compose.l4.yml` and preserve source IP.
- `security: trust only known reverse proxies` — set `TRUSTED_PROXY_CIDRS` to the dashboard proxies allowed to supply `X-Forwarded-For`; relay source-IP authorization depends on this value.
- `security: use a production rate-limit backend` — prefer `RATE_LIMIT_BACKEND=redis` with `RATE_LIMIT_REDIS_URL` configured, or enforce rate limits at the edge when using `RATE_LIMIT_BACKEND=edge`.
- `security: keep MFA throttling enabled` — tune `RATE_LIMIT_MFA_ATTEMPTS` and `RATE_LIMIT_MFA_WINDOW_SECONDS` conservatively for internet-facing deployments.
- `security: bound connector, relay, and restore resources` — review `CONNECTOR_SESSION_TTL_MINUTES`, `CONNECTOR_MAX_CONNECTIONS`, `CONNECTOR_CONNECTION_MAX_SECONDS`, `CONNECTOR_AUTHORIZATION_RECHECK_SECONDS`, device-access launch rate limits, all `PUBLIC_L4_RELAY_*` limits, and backup/restore size limits for your deployment.
- `security: minimize web-app privilege` — use `NETWORK_CONTROL_MODE=external` only when a sidecar or host service owns WireGuard and an equivalent full tunnel input/forward policy has been independently verified; then set `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true`.
- `security: keep browser hardening headers enabled` — leave `SECURITY_HEADERS_ENABLED=true` and only relax `CONTENT_SECURITY_POLICY`, `REFERRER_POLICY`, or `PERMISSIONS_POLICY` intentionally.
- `security: keep management-only routing` — continue rejecting customer LAN routes in WireGuard `AllowedIPs` to avoid cross-company routing and overlapping subnet conflicts.
- `security: keep IP forwarding disabled` — leave `HUB_ENABLE_IP_FORWARDING=false` unless other application routing requires it; enabling it never permits forwarding from `wg0`.
- `security: keep Hub firewall isolation enabled` — use `NETWORK_CONTROL_MODE=inline`, `HUB_MANAGE_FIREWALL_RULES=true`, `HUB_CONTROL_PLANE_PORT=8083`, and `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=false` for the bundled deployment.
- `security: manage firewall certificates` — use an internal/public CA or explicit trust so local connector hostnames and exact optional relay hostnames validate without trust bypasses.
- `security: isolate WireGuard management` — for higher-assurance deployments, consider moving WireGuard bootstrap and peer updates into a minimal privileged sidecar or host service.
- `security: keep login and enrollment rate limits enabled` — tune the existing IP/user limits conservatively and use a shared production backend.
- `security: preserve CSRF enforcement` — keep signed-cookie/form-token validation on all browser-facing state-changing routes, including connector and relay opens.
- `security: export firewall recovery keys offline` — export each firewall's root-only backup key, verify its key fingerprint, keep it encrypted and separate from Hub storage, and test recovery on disposable hardware.
- `security: remove historical plaintext copies` — after migration `0012`, securely expire old Hub exports, PostgreSQL backups/snapshots, WAL, and storage images that may contain legacy `config.xml` rows.
- `security: encrypt database backups` — firewall configuration envelopes are opaque, but token hashes, Hub secrets, metadata, uploaded branding assets, audit data, and the Hub WireGuard key remain sensitive.
- `security: monitor audit logs` — alert on repeated failed enrollment, unexpected `device.connector.open` or `device.relay.open` events, and revocations.
