# OPNsense Hub

OPNsense Hub enrolls OPNsense firewalls into a central dashboard with a short-lived OTP, establishes a WireGuard tunnel, and provides end-to-end encrypted WebGUI access through a local connector.

> Important: the Hub dashboard/control plane does not modify firewall configuration, restore backups, reboot firewalls, or store OPNsense admin passwords. The only firewall-side configuration change is performed by the OPNsense plugin on that firewall to create its own WireGuard client tunnel.

OPNsense Hub is an independent project. It is not affiliated with, endorsed by, or sponsored by Deciso B.V. or the OPNsense project unless explicitly stated by those parties.

## Architecture

See `docs/architecture.md`.

## Screenshots

### Dashboard

![OPNsense Hub dashboard](docs/screenshots/2026-07-02%2012_06_48-WhatsApp.png)

### Firewall settings

![OPNsense Hub firewall settings](docs/screenshots/2026-07-02%2012_07_44-Greenshot.png)

### Account security

![OPNsense Hub account security](docs/screenshots/2026-07-02%2012_08_18-WhatsApp.png)

## License and notices

This project is licensed under the BSD 2-Clause License. See `LICENSE`.

Third-party dependency, container image, font, icon, and trademark notices are tracked in:

- `THIRD_PARTY_NOTICES.md`
- `docs/licensing.md`
- `docs/release-compliance-checklist.md`

## Repository layout

```text
connector/                Local opaque-TCP-to-WSS connector and tests
dashboard/
  app/                    FastAPI dashboard/API
  migrations/             SQL schema
  tests/                  Unit tests
  Dockerfile
  requirements.txt
net-mgmt/os-opnsensehub/  OPNsense plugin scaffold
docs/                     Architecture, security, licensing, compliance, test plan
deploy/                   Dashboard proxy and optional L4 relay Compose examples
docker-compose.yml
.env.example
```

## Features

- Dashboard login with seeded initial admin.
- Local TOTP multi-factor authentication for dashboard accounts, including MFA-protected login and admin-managed user MFA setup.
- Random server-side dashboard session tokens stored hashed with expiration and revocation.
- Company/group creation.
- Company-scoped RBAC model in the database.
- Short-lived single-use OTP enrollment codes stored hashed.
- Device enrollment endpoint using WireGuard public key.
- Device tokens stored hashed; heartbeat uses bearer token auth.
- Automatic Hub WireGuard server bootstrap and peer restore on container startup.
- `/32`-only WireGuard routes for firewall web UI access; customer LAN subnets are never routed.
- Startup validation for Hub WireGuard CIDR/address, disabled IP forwarding by default, and verified default-deny tunnel input/forwarding rules or an explicitly attested external equivalent.
- WireGuard peer add/remove wrapper with public-key/IP validation.
- Firewall revoke flow invalidates device token and removes WireGuard peer.
- Audit logs for login, company creation, enrollment, revoke, connector access, and optional relay access, with throttled `device.view` entries to reduce browsing noise.
- Default local connector that carries opaque browser TLS bytes over an authenticated, device-scoped WSS connection; the Hub never terminates firewall TLS or receives WebGUI credentials.
- Optional, disabled-by-default public raw L4 relay for deployments where each OPNsense WebGUI enforces client certificates.
- Server-rendered dashboard with an Ephemeral-Link-inspired style.
- Side-menu settings area for adding companies, managing users, branding, email settings, Microsoft 365, and Local AD configuration.
- Branding logo upload with persistent storage and login/app-shell rendering.
- Admin backup/restore settings for exporting a portable Hub configuration archive and restoring it into another Hub container.
- Configurable database-backed retention management for audit logs and device events, with batched cleanup and local archive export from the Hub UI.
- Complete OPNsense configuration backups encrypted and authenticated on the firewall before upload; the Hub stores and downloads only opaque ciphertext and never receives the recovery key.
- Daily firmware update-status checks requested by Hub and executed locally by the OPNsense plugin at 23:00 Hub time.
- Colored firmware status icons in the firewalls table for unknown, up to date, updates available, upgrade available, and check failed states.
- OPNsense plugin scaffold with MVC, configd actions, and backend scripts.

## Run locally

```sh
cp .env.example .env
docker compose up --build
```

Open:

```text
http://localhost:8083
```

Default login comes from `.env`:

```text
INITIAL_ADMIN_EMAIL=admin@example.com
INITIAL_ADMIN_PASSWORD=change-me
```

`.env.example` now includes the full set of supported runtime variables, including retention, archive, rate-limit, health-check, migration, branding, and WireGuard-related settings.

By default, the Compose stack separates the public web process from privileged WireGuard operations. `opnsense-hub-api` runs as an unprivileged UID with all Linux capabilities dropped and no WireGuard key volume. It delegates server-key, interface, peer, and runtime-peer operations to the authenticated internal `opnsense-hub-wireguard` sidecar. Only that sidecar runs with `NET_ADMIN`, `/dev/net/tun`, UDP `51820`, and the `opnsense_hub_wg` volume. The sidecar generates and persists the Hub server private key, renders `/etc/wireguard/wg0.conf`, brings up `wg0`, restores enrolled peers supplied by the web process, disables IP forwarding inside its container, and installs a verified default-deny tunnel policy. That policy drops all forwarding originating from `wg0`, permits only established return traffic and new TCP connections to the exact Hub WireGuard address/control-plane port, and drops every other packet entering from `wg0`.

Branding uploads are stored in the `opnsense_hub_branding` Docker volume and served from `/branding/logo`.

## Exact dashboard commands

```sh
cd /path/to/OPNsense-Hub
cp .env.example .env
docker compose config
docker compose up --build
```

## Local Python setup

For local dashboard work outside Docker, install the dashboard dependencies from the repository root so runtime and migration tooling stay aligned:

```sh
python -m pip install -r dashboard/requirements.txt
```

This installs FastAPI, SQLAlchemy, Alembic, pytest, and the other dependencies used by the dashboard and startup migration path.

## Docker Compose deployment

These steps deploy the Hub with the included Compose stack, PostgreSQL, persistent WireGuard state, persistent branding uploads, and optional Caddy TLS reverse proxy.

1. Prepare the host:

   - Install Docker Engine with the Compose plugin.
   - Ensure `/dev/net/tun` exists and the host allows the WireGuard sidecar container to use `NET_ADMIN`.
   - Open inbound TCP `80`/`443` for the dashboard and authenticated connector WSS endpoint, and UDP `51820` for the WireGuard sidecar.
   - Point the dashboard DNS name, for example `hub.example.com`, at the Docker host and provision a valid TLS certificate.
   - Do not open TCP `55000-55099` for the default connector design. Those ports are only for the optional public L4 relay described below.

2. Create and edit the environment file:

   ```sh
   cp .env.example .env
   ```

   Set production values before starting the stack:

   ```text
   APP_ENV=production
   PUBLIC_URL=https://hub.example.com
   PROXY_PUBLIC_URL=https://relay.example.com
   ALLOWED_HOSTS=hub.example.com,relay.example.com
   TRUSTED_PROXY_CIDRS=<reverse-proxy-ip-or-cidr>
   RATE_LIMIT_BACKEND=redis
   RATE_LIMIT_REDIS_URL=redis://opnsense-hub-redis:6379/0
   NETWORK_CONTROL_MODE=inline
   HUB_MANAGE_FIREWALL_RULES=true
   HUB_ENABLE_IP_FORWARDING=false
   HUB_CONTROL_PLANE_PORT=8083
   HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=false
   HUB_WG_ENDPOINT=hub.example.com:51820
   WG_AGENT_TOKEN=<long-random-sidecar-token>
   SECRET_KEY=<long-random-secret>
   SECRET_ENCRYPTION_KEY=<separate-long-random-secret>
   INITIAL_ADMIN_EMAIL=<admin-email>
   INITIAL_ADMIN_PASSWORD=<temporary-strong-password>
   SESSION_SECURE=true
   WG_DRY_RUN=false
   PUBLIC_L4_RELAY_ENABLED=false
   PUBLIC_L4_RELAY_MTLS_REQUIRED=false
   ```

   `PROXY_PUBLIC_URL` is retained as the base hostname used to construct optional raw relay names; it is not an L7 proxy origin and serves no `/proxy/*` routes. Production validation currently requires it to be a valid HTTPS URL on a hostname distinct from `PUBLIC_URL`, even while the relay is disabled. Wildcard DNS and relay ports are unnecessary until the relay is explicitly enabled.

   `docker-compose.yml` sets `WG_AGENT_URL=http://opnsense-hub-wireguard:8084` for the web container and `WG_AGENT_MODE=true` for the sidecar. Set `WG_AGENT_TOKEN` to the same long random value for both services through `.env`; production startup rejects the development placeholder.

   If you change the PostgreSQL username, password, database, Redis service name, WireGuard sidecar name, or service hostnames, keep `DATABASE_URL`, `RATE_LIMIT_REDIS_URL`, and `WG_AGENT_URL` aligned with `docker-compose.yml`.

3. Configure the bundled Caddy profile when required:

   - Edit `deploy/Caddyfile` and replace `hub.example.com` and the email address.
   - Keep the upstream as `opnsense-hub-api:8083` when using the default Compose service; do not route public traffic to `opnsense-hub-wireguard:8084`.
   - Caddy handles dashboard HTTP(S), including the WSS upgrade on `/api/v1/connector/devices/{id}`. It does not terminate or proxy the optional raw L4 relay.

   Connector settings added in `dashboard/app/config.py`:

   - `CONNECTOR_SESSION_TTL_MINUTES` — lifetime of the short-lived, device-scoped connector token; default `15`.
   - `CONNECTOR_LOCAL_PORT` — local port shown in connector instructions; default `8443`.
   - `CONNECTOR_MAX_CONNECTIONS` — concurrent WSS streams allowed per connector session; default `16`.
   - `CONNECTOR_UPSTREAM_CONNECT_TIMEOUT_SECONDS` — Hub timeout while connecting to the firewall WebGUI through WireGuard; default `15`.
   - `CONNECTOR_CONNECTION_MAX_SECONDS` — maximum lifetime of each connector WSS stream; default `900`.
   - `CONNECTOR_AUTHORIZATION_RECHECK_SECONDS` — interval for rechecking the issuing dashboard session, user/company access, device revocation, and connector expiry during an active stream; default `5`.
   - `RATE_LIMIT_DEVICE_ACCESS_ATTEMPTS` and `RATE_LIMIT_DEVICE_ACCESS_WINDOW_SECONDS` — per-user connector/relay launch limit; defaults `20` launches per `300` seconds.

   Optional relay settings added in `dashboard/app/config.py`:

   - `PUBLIC_L4_RELAY_ENABLED` — enables relay allocation; default `false`.
   - `PUBLIC_L4_RELAY_MTLS_REQUIRED` — deployment attestation that every exposed OPNsense WebGUI requires and validates client certificates; default `false` and required to enable the relay.
   - `PUBLIC_L4_RELAY_BIND_HOST` — raw TCP listener bind address; default `0.0.0.0`.
   - `PUBLIC_L4_RELAY_PORT_MIN` and `PUBLIC_L4_RELAY_PORT_MAX` — allocation range; defaults `55000` and `55099`.
   - `PUBLIC_L4_RELAY_TTL_SECONDS` — hard relay lifetime; default `600`.
   - `PUBLIC_L4_RELAY_IDLE_TIMEOUT_SECONDS` — inactivity timeout per raw connection; default `120`.
   - `PUBLIC_L4_RELAY_MAX_CONNECTIONS` — concurrent connections allowed per allocated relay; default `16`.

   Other production-focused variables include `ALLOWED_HOSTS`, `TRUSTED_PROXY_CIDRS`, `RATE_LIMIT_BACKEND`, `RATE_LIMIT_REDIS_URL`, `RATE_LIMIT_MFA_ATTEMPTS`, `RATE_LIMIT_MFA_WINDOW_SECONDS`, `NETWORK_CONTROL_MODE`, `WG_AGENT_URL`, `WG_AGENT_TOKEN`, `WG_AGENT_MODE`, browser security-header controls, and backup/restore size limits.

4. Validate and start the default stack:

   ```sh
   docker compose config
   docker compose up -d --build
   ```

   Or start it with the bundled Caddy reverse proxy:

   ```sh
   docker compose --profile reverse-proxy up -d --build
   ```

5. Check service status and logs:

   ```sh
   docker compose ps
   docker compose logs -f opnsense-hub-api
   ```

6. Back up the persistent Docker volumes:

   - `opnsense_hub_db` for PostgreSQL data.
   - `opnsense_hub_wg` for the Hub WireGuard server key and config; this is mounted only into the WireGuard sidecar.
   - `opnsense_hub_branding` for uploaded branding assets; this is mounted into the unprivileged web container.
   - `opnsense_hub_caddy` when using the bundled Caddy profile.

   Losing the WireGuard volume changes the Hub server key and requires re-enrollment or careful key rotation for existing firewalls.

7. Upgrade an existing deployment:

   ```sh
   git pull
   docker compose config
   docker compose up -d --build
   ```

   Fresh databases run migrations automatically on startup. Existing databases should keep `RUN_DB_MIGRATIONS_ON_STARTUP=true` unless migrations are managed manually. Migration `0011_connector_access_sessions` extends access-session storage for short-lived connector tokens.

After the stack is running, open `PUBLIC_URL`, sign in with the initial admin credentials, change the temporary password, create a company, generate an enrollment OTP, and enroll the OPNsense firewall through `Services > OPNsense Hub`.

### Connector install and usage

Install the connector on the administrator's workstation with Python 3.11 or newer:

```sh
cd connector
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

In the dashboard, click `Open OPNsense UI` for the firewall. The CSRF/RBAC-protected POST displays a device UUID, a short-lived connector token, and a command like:

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef
```

The interactive command prompts for the token without echoing it and is the recommended path. For managed automation, provide exactly one token line on standard input from a short-lived, permission-restricted secret file or secret-manager file descriptor:

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef \
  < /run/secrets/opnsense-hub-connector-token
```

The connector also supports `OPNSENSE_HUB_CONNECTOR_TOKEN`, but process environments may be inspectable on some systems. The token is never accepted as a CLI argument or URL value. Do not place a literal token in shell commands or shell history.

The connector listens on `127.0.0.1:8443` by default and prints the local HTTPS URL. OPNsense terminates that TLS connection, so browser trust, hostname checks, redirects, and client-certificate behavior come from the target firewall's WebGUI certificate. If the certificate expects `firewall.example.test`, map it to loopback locally, for example `127.0.0.1 firewall.example.test`, and run with `--browser-host firewall.example.test`. `--browser-host` changes the printed URL only; it does not change DNS or the listener address. A non-loopback `--listen` value is rejected unless `--allow-non-loopback` is also supplied. Use that override only when exposing the unauthenticated local TCP listener is deliberate and protected by the workstation firewall. Any local process or user that can connect to the listener can use the active connector token to reach the selected firewall.

### Optional public L4 relay

The public relay is disabled by default and is not required for normal connector access. Enable it only when every participating firewall has all of the following controls in place:

- the OPNsense WebGUI requires and validates a trusted browser client certificate, with no password-only fallback on the relay listener
- the WebGUI presents a certificate valid for the exact generated per-device hostname `d-{device-uuid-without-dashes}.<PROXY_PUBLIC_URL hostname>`
- wildcard DNS for `*.<PROXY_PUBLIC_URL hostname>` resolves to the Hub node
- TCP `55000-55099` is allowed end to end without an HTTP proxy, TLS terminator, or source-NAT device that hides the browser's source IP

Then set both required gates:

```text
PUBLIC_L4_RELAY_ENABLED=true
PUBLIC_L4_RELAY_MTLS_REQUIRED=true
```

Open TCP `55000-55099` on the host firewall/security group and start Compose with the relay port override:

```sh
docker compose -f docker-compose.yml -f deploy/docker-compose.l4.yml config
docker compose -f docker-compose.yml -f deploy/docker-compose.l4.yml --profile reverse-proxy up -d --build
```

The relay allocates a short-lived random port, accepts only the source IP observed on the authorized dashboard POST, and forwards raw TLS bytes directly to that device's WebGUI over WireGuard. Caddy is not in this path. Any L4 load balancer must preserve the original source IP; PROXY protocol is not consumed by the relay.

Relay state and port allocation are process-local, so this design is single-node/single-process only: the dashboard authorization request and TCP relay ports must reach the same Hub API instance. Source-IP filtering also cannot distinguish users behind the same NAT; another user sharing that public IP could reach the temporary port, which is why exact per-device WebGUI certificates and enforced client-certificate authentication are mandatory.

## WireGuard production notes

OPNsense Hub is a management overlay for opening each firewall's own web UI. It is not a site-to-site VPN router and does not route customer LANs.

The `opnsense-hub-api` container configures WireGuard automatically when `WG_DRY_RUN=false` and `NETWORK_CONTROL_MODE=inline`:

1. Validates `HUB_WG_CIDR` and `HUB_WG_ADDRESS` before allocating peers.
2. Generates `/etc/wireguard/server.key` if it does not exist.
3. Derives the Hub server public key from that private key.
4. Renders `/etc/wireguard/wg0.conf` using `HUB_WG_ADDRESS` and `HUB_WG_LISTEN_PORT`.
5. Runs `wg-quick up /etc/wireguard/wg0.conf` when `wg0` is not already running.
6. Restores all non-revoked device peers from the database on startup.
7. Adds each newly enrolled firewall as a `/32` peer.
8. Disables IPv4/IPv6 forwarding unless `HUB_ENABLE_IP_FORWARDING=true`.
9. Installs and verifies a complete nftables or iptables/ip6tables tunnel policy when `HUB_MANAGE_FIREWALL_RULES=true`:
   - accept established/related return traffic entering `wg0`, preserving Hub-initiated WebGUI, health-check, connector, and relay connections
   - accept new IPv4 TCP connections only from `HUB_WG_CIDR` to the exact `HUB_WG_ADDRESS` and `HUB_CONTROL_PLANE_PORT`
   - drop every other IPv4/IPv6 packet entering from `wg0`
   - drop every forwarded packet whose input interface is `wg0`, regardless of output interface

`HUB_CONTROL_PLANE_PORT` must be the TCP port bound by the control-plane process inside the WireGuard network namespace; the bundled API container uses `8083`. Keep `NETWORK_CONTROL_MODE=inline`, `HUB_MANAGE_FIREWALL_RULES=true`, and `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=false` for the bundled deployment.

When a sidecar or host firewall owns networking, set `NETWORK_CONTROL_MODE=external` or disable `HUB_MANAGE_FIREWALL_RULES` only after independently verifying an equivalent policy, then set `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true` as an operator attestation. Production startup fails without that attestation. The external policy must allow established return traffic, allow new tunnel input only to the exact Hub address/control-plane TCP port, default-drop all other tunnel input, and default-drop all forwarding originating from the WireGuard interface. `HUB_ENABLE_IP_FORWARDING=true` does not relax these requirements.

AllowedIPs are intentionally narrow:

- Hub side peer route: `firewall_tunnel_ip/32`
- Firewall side peer route: `hub_tunnel_ip/32`

Do not add customer LAN networks such as `192.168.1.0/24` to WireGuard `AllowedIPs`. Many companies can use the same LAN subnet without conflict because the Hub only connects to each firewall's unique tunnel IP.

The server private key is persisted in the `opnsense_hub_wg` Docker volume. Back up this volume securely; losing it requires re-enrolling devices or carefully rotating WireGuard keys.

Set `HUB_WG_ENDPOINT` to the public UDP endpoint that OPNsense firewalls can reach, for example `hub.example.com:51820`, and ensure UDP `51820` is allowed through the host firewall/security group and forwarded to the Hub app host/container.

Required inbound ports for a typical deployment:

- TCP `443` to the dashboard reverse proxy for browser access, enrollment APIs, and authenticated connector WSS traffic. If running the development Compose file directly, TCP `8083` reaches the FastAPI app instead.
- UDP `51820` to the Hub WireGuard listener for enrolled firewalls.
- No public WebGUI relay ports for the default connector path. TCP `55000-55099` is required only when the optional L4 relay is enabled.

`Open OPNsense UI` sends a CSRF-protected POST to the dashboard. After session and company-scope RBAC authorization, the Hub creates a short-lived, device-scoped connector token, stores only its hash, and displays connector instructions in a `no-store` response. The user runs the local connector, which listens on loopback and opens an authenticated WSS connection to `/api/v1/connector/devices/{device_id}` for each accepted local TCP connection. The Hub connects to `OPNSENSE_GUI_PORT` (default TCP `443`) at that firewall's WireGuard `/32` and copies opaque binary bytes in both directions. Browser-to-firewall TLS remains end to end, so the Hub never receives the OPNsense administrator password, session cookie, or plaintext WebGUI traffic.

The firewall WebGUI does not need to be exposed to the internet. The Hub container must have a working WireGuard interface and be able to reach the firewall tunnel IP over `wg0`.

On connect, the OPNsense plugin provisions the firewall side for Hub access:

- Validates that the returned WireGuard `interface_address` is IPv4 `/32` and that `allowed_ips` contains exactly one Hub tunnel IPv4 `/32`.
- Creates and starts the runtime WireGuard interface `wgopnhub`.
- Assigns/enables it in OPNsense as `OPNHUB` when not already assigned.
- Adds one narrow pass rule allowing the Hub tunnel IP, for example `100.96.0.1/32`, to reach `This Firewall` on the configured WebGUI port.
- If WebGUI listen interfaces are explicitly restricted, adds the assigned `OPNHUB` interface to that list.

It does not add customer LAN routes or broad allow rules. The Hub drops all forwarding originating from `wg0`, so an enrolled firewall cannot reach another peer, the container's Docker network, `eth0`, or another routed network. Tunnel input is limited to established return traffic and the exact control-plane destination.

## Firmware update status checks

Firmware checks are request/report only:

- The Hub scheduler marks active, non-revoked firewalls for a firmware check once per day at `23:00` Hub/container local time.
- The Hub does not run firmware probes and does not install updates.
- The OPNsense plugin performs the local check on the firewall with native firmware commands and reports normalized status back on heartbeat.
- The plugin installs a per-minute local heartbeat cron entry on connect so firmware requests, manual backup requests, and status updates are processed automatically.
- If a firewall already completed the scheduled check for that local day, the Hub does not request it again automatically.

Firmware status colors in the firewalls table:

- `unknown` = gray
- `none` = green
- `update` = blue
- `upgrade` = orange
- `error` = red

For UI-only development without WireGuard privileges, set `WG_DRY_RUN=true`.

## Encrypted OPNsense configuration backups

Plugin version `0.2` encrypts `/conf/config.xml` locally before upload. The format uses AES-256-CBC with PBKDF2-HMAC-SHA256 plus an independent HMAC-SHA256 encrypt-then-MAC key. Encryption and authentication keys are derived separately from a random 32-byte master key stored only on the firewall at `/var/db/opnsensehub/backup_master.key` with root-only permissions. The key, plaintext XML, and decrypted configuration are never sent to the Hub.

The plugin advertises `opnsense-config-encrypted-v1` in its heartbeat. The Hub requests a backup only from a plugin advertising that format and accepts uploads only while a backup request is pending. Legacy `content` uploads and unknown or malformed envelopes are rejected. Retention ordering uses Hub receipt time rather than a device-supplied timestamp.

The Hub stores a canonical encrypted envelope, serves downloads as `.opnenc`, and cannot validate the envelope HMAC or decrypt it because it does not possess the firewall key. Integrity is verified locally when the file is decrypted. Hub exports contain only these opaque envelopes, although the rest of a Hub export still contains sensitive Hub data and should normally use passphrase protection.

Back up the recovery key separately before relying on off-device backups:

```sh
/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/backup_crypto.py \
  export-key /root/firewall-backup-recovery-key.json
```

Move that root-only file to encrypted offline storage, then remove the temporary copy from the firewall. Never upload it to OPNsense Hub or store it beside Hub database backups. The non-secret key fingerprint can be displayed with:

```sh
/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/backup_crypto.py key-info
```

On a replacement firewall, import the recovery key before generating new backups, then decrypt a downloaded backup to a new root-only file:

```sh
/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/backup_crypto.py \
  import-key /root/firewall-backup-recovery-key.json
/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/backup_crypto.py \
  decrypt /root/firewall-backup.opnenc /root/config.xml.recovered
```

The utility refuses to overwrite an existing key or output file. Review and restore the recovered XML using supported OPNsense recovery procedures; the Hub does not push or restore firewall configurations.

Migration `0012_encrypted_device_backups` intentionally deletes all existing plaintext firewall backup rows, resets backup timestamps, replaces the plaintext column with `encrypted_payload`, and requests encrypted replacements from capable plugins. Export any legacy backup you must retain before upgrading, then securely expire old Hub exports, PostgreSQL backups/snapshots, and WAL archives that may still contain plaintext `config.xml` data. Plugin `0.1` remains able to heartbeat but will not receive backup requests from the updated Hub; upgrade each firewall to plugin `0.2` to resume backups.

## Production defaults

Set `APP_ENV=production` to enable strict startup validation. In production the app refuses to start when any of these remain insecure:

- `SECRET_KEY=change-me` or a too-short secret
- `INITIAL_ADMIN_EMAIL=admin@example.com`
- `INITIAL_ADMIN_PASSWORD=change-me` or a weak password
- `SESSION_SECURE=false`
- `PUBLIC_URL` is localhost, plain HTTP, or otherwise not an HTTPS user-facing URL
- `PROXY_PUBLIC_URL`, which supplies the optional relay base hostname, is not HTTPS, is invalid, or is not distinct from `PUBLIC_URL`
- connector limits are invalid, or the public relay is enabled without `PUBLIC_L4_RELAY_MTLS_REQUIRED=true` and valid relay limits
- `HUB_CONTROL_PLANE_PORT` is invalid, or inline tunnel policy management is disabled/external without `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true`
- the retained `PROXY_VERIFY_TLS` setting is `false` without `ALLOW_INSECURE_PROXY_TLS_IN_PRODUCTION=true`; the default connector still leaves firewall TLS validation to the user's browser

In development the same conditions remain usable but are logged as warnings.

## Branding uploads

The Branding settings page accepts uploaded PNG, JPEG, or WebP logos up to `BRANDING_LOGO_MAX_BYTES` and stores them under `BRANDING_UPLOAD_DIR`. Uploaded branding takes precedence over `branding_logo_url`, appears on the login page and dashboard shell, and can be removed with the Branding settings form.

## CSRF protection

Browser-facing POST routes use CSRF protection with a signed cookie plus matching form token. This applies to login, settings, user/company management, branding, device actions (including connector token creation at `POST /devices/{device_id}/proxy/open` and optional relay allocation at `POST /devices/{device_id}/relay/open`), and backup export/restore. The connector then authenticates its WSS upgrade with the short-lived bearer token; it does not use the dashboard session or CSRF cookie. Device bearer-token API routes such as enrollment, heartbeat, and backup upload remain exempt.

## Rate limiting

Rate limiting is in-process and works in local Docker without Redis. Configure limits with environment variables such as:

- `RATE_LIMIT_LOGIN_ATTEMPTS`
- `RATE_LIMIT_LOGIN_WINDOW_SECONDS`
- `RATE_LIMIT_LOCAL_AD_LOGIN_ATTEMPTS`
- `RATE_LIMIT_LOCAL_AD_LOGIN_WINDOW_SECONDS`
- `RATE_LIMIT_MICROSOFT_LOGIN_ATTEMPTS`
- `RATE_LIMIT_MICROSOFT_LOGIN_WINDOW_SECONDS`
- `RATE_LIMIT_ENROLLMENT_ATTEMPTS`
- `RATE_LIMIT_ENROLLMENT_WINDOW_SECONDS`
- `RATE_LIMIT_ENROLLMENT_CODE_ATTEMPTS`
- `RATE_LIMIT_ENROLLMENT_CODE_WINDOW_SECONDS`
- `RATE_LIMIT_DEVICE_HEARTBEAT_ATTEMPTS`
- `RATE_LIMIT_DEVICE_HEARTBEAT_WINDOW_SECONDS`
- `RATE_LIMIT_DEVICE_BACKUP_ATTEMPTS`
- `RATE_LIMIT_DEVICE_BACKUP_WINDOW_SECONDS`
- `RATE_LIMIT_BACKUP_RESTORE_ATTEMPTS`
- `RATE_LIMIT_BACKUP_RESTORE_WINDOW_SECONDS`

## Log retention and local archives

Hub keeps `audit_logs` and `device_events` as separate database tables and manages them separately:

- audit logs are accountability and access-history records
- device events are operational troubleshooting history reported by the Hub and firewalls
- retention cleanup never deletes stored firewall backups
- local archive export downloads files through the Hub UI only
- no offsite archive target such as S3, Azure Blob, SFTP, or email export is supported by this feature

Default retention environment variables:

- `LOG_RETENTION_ENABLED=true`
- `LOG_RETENTION_RUN_ON_STARTUP=true`
- `AUDIT_LOG_RETENTION_DAYS=365`
- `DEVICE_EVENT_RETENTION_DAYS=90`
- `AUDIT_LOG_MIN_RETENTION_DAYS=30`
- `DEVICE_EVENT_MIN_RETENTION_DAYS=7`
- `LOG_RETENTION_SWEEP_INTERVAL_HOURS=24`
- `LOG_RETENTION_DELETE_BATCH_SIZE=5000`
- `AUDIT_DEVICE_VIEW_THROTTLE_MINUTES=15`

Behavior:

- when retention is enabled, startup and scheduled sweeps remove old `audit_logs` and `device_events` in separate batched deletes
- in production, the app rejects unsafe retention values below the configured minimums or invalid batch/sweep values
- in development, unsafe retention days are clamped to the configured minimums for cleanup behavior while startup still logs clear warnings
- opening the same firewall page repeatedly only writes one `device.view` audit row per user/device within the throttle window, while higher-value actions such as `device.proxy.open` are still logged every time

Under `Settings > Retention`, administrators can:

- review current retention configuration from environment variables
- see current database counts, oldest rows, and rows older than the active retention cutoffs
- run cleanup immediately
- export a local log archive up to a selected cutoff timestamp

Log archive details:

- archives are downloaded locally from the Hub UI
- the ZIP layout uses `manifest.json`, `audit_logs.csv`, and `device_events.csv`
- you can export audit logs only, device events only, or both
- optional passphrase protection reuses the Hub backup encryption format
- archives may contain sensitive metadata such as IP addresses, user agents, user IDs, device IDs, and operational event history

## Secret encryption

Sensitive integration secrets are encrypted at the application layer before being stored. Set `SECRET_ENCRYPTION_KEY` to a dedicated value in production. If omitted, Hub derives an encryption key from `SECRET_KEY` for backward compatibility.

## Database migrations

Hub supports explicit Alembic migrations. The dashboard container installs Alembic through `dashboard/requirements.txt`, and local Python environments should do the same before running migration commands:

```sh
python -m pip install -r dashboard/requirements.txt
PYTHONPATH=dashboard python -m alembic -c dashboard/alembic.ini upgrade head
```

Use the same `PYTHONPATH=dashboard` prefix for local test commands so the `app` package resolves consistently.

On startup, fresh databases upgrade to `head`. Existing databases without `alembic_version` are bootstrapped, stamped, and then upgraded through `head` when `ALLOW_LEGACY_SCHEMA_BOOTSTRAP=true`. Migration `0011_connector_access_sessions` permits hashed, expiring connector authorization records. Migration `0012_encrypted_device_backups` removes legacy plaintext firewall backups and enforces the firewall-encrypted envelope schema.

## Hub backup and restore

Under `Settings > Backup`, administrators can:

- click `Backup configuration` to download a `.zip` archive, or provide a passphrase to download an encrypted `.opnhub` archive
- click `Restore configuration` to upload a previously exported archive, plus the passphrase when restoring an encrypted backup

The backup archive is application-level and portable across supported database backends. Unencrypted restore remains supported for backward compatibility, but encrypted export is strongly recommended. The archive includes:

- Hub database content needed to restore users, companies, memberships, enrollment codes, devices, opaque firewall-encrypted backup envelopes, device events, audit logs, and integration settings
- uploaded branding logo, if present
- the Hub WireGuard server private key, if present at `WG_SERVER_PRIVATE_KEY_PATH`

Hub archive format version `2` requires firewall backups to use the encrypted envelope fields. Legacy Hub archives containing plaintext `device_backups[].content` are rejected so restore cannot reintroduce readable `config.xml` data.

Restore behavior:

- replaces the current persisted Hub configuration with the uploaded archive
- clears all active dashboard sessions and redirects back to the login page
- restores the uploaded branding asset and Hub WireGuard private key from the archive when included

Deployment environment variables such as `DATABASE_URL`, `PUBLIC_URL`, `PROXY_PUBLIC_URL`, connector/relay settings, `SECRET_KEY`, and other container/runtime settings are not changed by the restore operation and still need to be configured on the target container.

Hub export uses the same active limits as restore and refuses to build an archive that those settings cannot restore. Encrypted firewall envelopes are base64-encoded and do not compress significantly, so deployments retaining many large firewall backups may need to raise these values together:

- `MAX_BACKUP_RESTORE_BYTES` — maximum uploaded or generated archive size; default `20000000`
- `MAX_BACKUP_RESTORE_ENTRIES` — maximum ZIP member count; default `16`
- `MAX_BACKUP_RESTORE_TOTAL_UNCOMPRESSED_BYTES` — aggregate extracted size; default `25000000`
- `MAX_BACKUP_RESTORE_FILE_BYTES` — maximum size of one member such as `data.json`; default `20000000`

Export performs an aggregate database-size preflight before loading encrypted firewall payloads and returns an actionable error when the retained ciphertext cannot fit within these limits.

## OPNsense plugin build/install commands

These commands assume an OPNsense ports/plugins build environment. Verify against current OPNsense plugin conventions for your target OPNsense release.

```sh
cd /usr/plugins/net-mgmt/os-opnsensehub
make package
pkg install /usr/obj/usr/plugins/net-mgmt/os-opnsensehub/*.pkg
service configd restart
```

For quick development copy testing on a lab firewall:

```sh
scp -r net-mgmt/os-opnsensehub/src/opnsense/* root@firewall:/usr/local/opnsense/
ssh root@firewall 'chmod +x /usr/local/opnsense/scripts/OPNsense/OPNsenseHub/*.py && service configd restart'
```

After copying updated plugin files, reconnect the plugin once so it re-installs the per-minute heartbeat cron entry used for firmware requests, manual backup requests, and status updates:

```sh
ssh root@firewall 'configctl opnsensehub connect'
ssh root@firewall 'crontab -l | grep "OPNsense Hub heartbeat"'
```

Then open:

```text
Services > OPNsense Hub
```

## Enrollment steps

1. Log in to Hub.
2. Create a company.
3. Open the company and click `Generate enrollment OTP`.
4. In OPNsense, go to `Services > OPNsense Hub`.
5. Enter the HTTPS Hub URL and OTP.
6. Click `Connect`. The plugin saves the current form values before starting enrollment.
7. The firewall should appear in the company firewalls table.

If enrollment fails, the OPNsense dialog should show an actionable `status: error` message, such as an invalid/expired OTP, HTTPS URL validation failure, unsafe `AllowedIPs`, missing WireGuard command, or Hub API HTTP status. For lab debugging, run these commands on the firewall and check the returned JSON plus configd logs:

```sh
configctl opnsensehub connect
/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/connect.py
tail -f /var/log/configd/latest.log
```

## REST endpoints

Auth:
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

Companies:
- `GET /api/v1/companies`
- `POST /api/v1/companies`
- `GET /api/v1/companies/{company_id}`

Enrollment:
- `POST /api/v1/companies/{company_id}/enrollment-codes`
- `POST /api/v1/enroll`

Devices:
- `GET /api/v1/companies/{company_id}/devices`
- `GET /api/v1/devices/{device_id}`
- `POST /api/v1/devices/{device_id}/heartbeat`
- `POST /api/v1/devices/{device_id}/revoke`

Firewall access:
- Dashboard: `POST /devices/{device_id}/proxy/open` — CSRF/RBAC-authorized connector token creation and instructions
- Dashboard WSS: `/api/v1/connector/devices/{device_id}` — bearer-authenticated opaque binary stream to the selected firewall
- Dashboard: `POST /devices/{device_id}/relay/open` — optional CSRF/RBAC-authorized raw L4 relay allocation; returns `404` while disabled

Legacy `/proxy/bootstrap` and `/proxy/devices/*` routes are not part of this design and return `404`.

## Validation

```sh
cd dashboard
python -m pytest
python -m compileall app
cd ..
docker compose config
docker compose build
```

## Known limitations

- Connector access requires the user to install and run the local Python connector. Browser trust and hostname behavior still depend on the certificate presented by the target OPNsense WebGUI.
- Connector connection counts and immediate socket cleanup are process-local. The shipped deployment uses one Uvicorn process; active streams also poll shared database authorization so session revocation, RBAC removal, and device revocation are enforced across workers within `CONNECTOR_AUTHORIZATION_RECHECK_SECONDS`. Multi-process deployments need shared accounting if a global connection cap is required.
- The optional public L4 relay is single-node/single-process and source-IP filtering cannot distinguish users behind the same NAT.
- OPNsense plugin service integration may require adjustment for the exact installed WireGuard plugin/version.

