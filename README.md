# OPNsense Hub

OPNsense Hub enrolls OPNsense firewalls into a central dashboard with a short-lived OTP, establishes a WireGuard tunnel, and opens the firewall UI through a protected reverse proxy path.

> Important: the Hub dashboard/control plane does not modify firewall configuration, restore backups, reboot firewalls, or store OPNsense admin passwords. The only firewall-side configuration change is performed by the OPNsense plugin on that firewall to create its own WireGuard client tunnel.

OPNsense Hub is an independent project. It is not affiliated with, endorsed by, or sponsored by Deciso B.V. or the OPNsense project unless explicitly stated by those parties.

## Architecture

See `docs/architecture.md`.

## License and notices

This project is licensed under the BSD 2-Clause License. See `LICENSE`.

Third-party dependency, container image, font, icon, and trademark notices are tracked in:

- `THIRD_PARTY_NOTICES.md`
- `docs/licensing.md`
- `docs/release-compliance-checklist.md`

## Repository layout

```text
dashboard/
  app/                    FastAPI dashboard/API
  migrations/             SQL schema
  tests/                  Unit tests
  Dockerfile
  requirements.txt
net-mgmt/os-opnsensehub/  OPNsense plugin scaffold
docs/                     Architecture, security, licensing, compliance, test plan
deploy/                   Reverse proxy examples
docker-compose.yml
.env.example
```

## Features

- Dashboard login with seeded initial admin.
- Random server-side dashboard session tokens stored hashed with expiration and revocation.
- Company/group creation.
- Company-scoped RBAC model in the database.
- Short-lived single-use OTP enrollment codes stored hashed.
- Device enrollment endpoint using WireGuard public key.
- Device tokens stored hashed; heartbeat uses bearer token auth.
- Automatic Hub WireGuard server bootstrap and peer restore on container startup.
- `/32`-only WireGuard routes for firewall web UI access; customer LAN subnets are never routed.
- Startup validation for Hub WireGuard CIDR/address, disabled IP forwarding by default, and optional automatic Hub firewall isolation rules.
- WireGuard peer add/remove wrapper with public-key/IP validation.
- Firewall revoke flow invalidates device token and removes WireGuard peer.
- Audit logs for login, company creation, enrollment, revoke, and proxy access.
- Server-rendered dashboard with an Ephemeral-Link-inspired style.
- Side-menu settings area for adding companies, managing users, branding, email settings, Microsoft 365, and Local AD configuration.
- Branding logo upload with persistent storage and login/app-shell rendering.
- Admin backup/restore settings for exporting a portable Hub configuration archive and restoring it into another Hub container.
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

By default, the app container automatically configures the Hub WireGuard server interface on startup. It generates and persists the Hub server private key under the `opnsense_hub_wg` Docker volume, renders `/etc/wireguard/wg0.conf`, brings up `wg0`, exposes UDP `51820`, restores enrolled peers from the database, disables IP forwarding inside the container, and installs an idempotent `wg0 -> wg0` forward-drop rule unless you explicitly opt out.

Branding uploads are stored in the `opnsense_hub_branding` Docker volume and served from `/branding/logo`.

## Exact dashboard commands

```sh
cd /Projects/OPNsense-Hub
cp .env.example .env
docker compose config
docker compose up --build
```

## WireGuard production notes

OPNsense Hub is a management overlay for opening each firewall's own web UI. It is not a site-to-site VPN router and does not route customer LANs.

The `opnsense-hub-api` container configures WireGuard automatically when `WG_DRY_RUN=false`:

1. Validates `HUB_WG_CIDR` and `HUB_WG_ADDRESS` before allocating peers.
2. Generates `/etc/wireguard/server.key` if it does not exist.
3. Derives the Hub server public key from that private key.
4. Renders `/etc/wireguard/wg0.conf` using `HUB_WG_ADDRESS` and `HUB_WG_LISTEN_PORT`.
5. Runs `wg-quick up /etc/wireguard/wg0.conf` when `wg0` is not already running.
6. Restores all non-revoked device peers from the database on startup.
7. Adds each newly enrolled firewall as a `/32` peer.
8. Disables IPv4/IPv6 forwarding unless `HUB_ENABLE_IP_FORWARDING=true`.
9. Installs an idempotent isolation rule that drops forwarded `wg0 -> wg0` traffic when `HUB_MANAGE_FIREWALL_RULES=true`.

AllowedIPs are intentionally narrow:

- Hub side peer route: `firewall_tunnel_ip/32`
- Firewall side peer route: `hub_tunnel_ip/32`

Do not add customer LAN networks such as `192.168.1.0/24` to WireGuard `AllowedIPs`. Many companies can use the same LAN subnet without conflict because the Hub only connects to each firewall's unique tunnel IP.

The server private key is persisted in the `opnsense_hub_wg` Docker volume. Back up this volume securely; losing it requires re-enrolling devices or carefully rotating WireGuard keys.

Set `HUB_WG_ENDPOINT` to the public UDP endpoint that OPNsense firewalls can reach, for example `hub.example.com:51820`, and ensure UDP `51820` is allowed through the host firewall/security group and forwarded to the Hub app host/container.

Required inbound ports for a typical deployment:

- TCP `443` to the Hub reverse proxy for browser access and firewall enrollment API calls. If running the development compose file directly, TCP `8083` reaches the FastAPI app instead.
- UDP `51820` to the Hub WireGuard listener for enrolled firewalls.

`Open OPNsense UI` uses the WireGuard tunnel from the Hub to the firewall tunnel IP, then proxies to the firewall GUI on `OPNSENSE_GUI_PORT` which defaults to TCP `443`. You do not need to expose the firewall GUI to the internet, but the Hub container must have a working WireGuard interface and be able to reach the firewall tunnel IP over `wg0`.

On connect, the OPNsense plugin provisions the firewall side for Hub access:

- Validates that the returned WireGuard `interface_address` is IPv4 `/32` and that `allowed_ips` contains exactly one Hub tunnel IPv4 `/32`.
- Creates and starts the runtime WireGuard interface `wgopnhub`.
- Assigns/enables it in OPNsense as `OPNHUB` when not already assigned.
- Adds one narrow pass rule allowing the Hub tunnel IP, for example `100.96.0.1/32`, to reach `This Firewall` on the configured WebGUI port.
- If WebGUI listen interfaces are explicitly restricted, adds the assigned `OPNHUB` interface to that list.

It does not add customer LAN routes or broad allow rules, and the Hub host drops forwarded `wg0 -> wg0` traffic so enrolled firewalls cannot talk to one another through the overlay.

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

## Production defaults

Set `APP_ENV=production` to enable strict startup validation. In production the app refuses to start when any of these remain insecure:

- `SECRET_KEY=change-me` or a too-short secret
- `INITIAL_ADMIN_EMAIL=admin@example.com`
- `INITIAL_ADMIN_PASSWORD=change-me` or a weak password
- `SESSION_SECURE=false`
- `PUBLIC_URL` is localhost, plain HTTP, or otherwise not an HTTPS user-facing URL
- `PROXY_VERIFY_TLS=false` unless `ALLOW_INSECURE_PROXY_TLS_IN_PRODUCTION=true`

In development the same conditions remain usable but are logged as warnings.

## Branding uploads

The Branding settings page accepts uploaded PNG, JPEG, or WebP logos up to `BRANDING_LOGO_MAX_BYTES` and stores them under `BRANDING_UPLOAD_DIR`. Uploaded branding takes precedence over `branding_logo_url`, appears on the login page and dashboard shell, and can be removed with the Branding settings form.

## CSRF protection

Browser-facing POST routes use CSRF protection with a signed cookie plus matching form token. This applies to login, settings, user/company management, branding, device actions, and backup export/restore. Device bearer-token API routes such as enrollment, heartbeat, and backup upload remain exempt.

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

## Secret encryption

Sensitive integration secrets are encrypted at the application layer before being stored. Set `SECRET_ENCRYPTION_KEY` to a dedicated value in production. If omitted, Hub derives an encryption key from `SECRET_KEY` for backward compatibility.

## Database migrations

Hub now supports explicit Alembic migrations. Existing deployments can still start through the legacy compatibility bootstrap path, but production should prefer running migrations explicitly:

```sh
cd dashboard
python -m alembic upgrade head
```

On startup, fresh databases upgrade to `head`. Existing databases without `alembic_version` can still be bootstrapped and stamped when `ALLOW_LEGACY_SCHEMA_BOOTSTRAP=true`.

## Hub backup and restore

Under `Settings > Backup`, administrators can:

- click `Backup configuration` to download a `.zip` archive, or provide a passphrase to download an encrypted `.opnhub` archive
- click `Restore configuration` to upload a previously exported archive, plus the passphrase when restoring an encrypted backup

The backup archive is application-level and portable across supported database backends. Unencrypted restore remains supported for backward compatibility, but encrypted export is strongly recommended. The archive includes:

- Hub database content needed to restore users, companies, memberships, enrollment codes, devices, stored firewall backups, device events, audit logs, and integration settings
- uploaded branding logo, if present
- the Hub WireGuard server private key, if present at `WG_SERVER_PRIVATE_KEY_PATH`

Restore behavior:

- replaces the current persisted Hub configuration with the uploaded archive
- clears all active dashboard sessions and redirects back to the login page
- restores the uploaded branding asset and Hub WireGuard private key from the archive when included

Deployment environment variables such as `DATABASE_URL`, `PUBLIC_URL`, `SECRET_KEY`, and other container/runtime settings are not changed by the restore operation and still need to be configured on the target container.

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

Proxy:
- `GET/POST/PUT/PATCH/DELETE /proxy/devices/{device_id}/{path:path}`

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

- The FastAPI proxy is intentionally simple. For production, consider Caddy/Nginx with a signed internal auth check or a hardened streaming proxy.
- OPNsense plugin service integration may require adjustment for the exact installed WireGuard plugin/version.
- MFA fields exist, but MFA is not implemented yet.
- Email and Microsoft Graph client secrets entered in the settings UI are not shown back in forms and are never logged, but they are currently stored in the database without application-level encryption. Use restrictive database access and backups until encrypted-at-rest integration secrets are implemented.
