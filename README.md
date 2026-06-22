# OPNsense Hub

OPNsense Hub is an MVP for enrolling OPNsense firewalls into a central dashboard with a short-lived OTP, establishing a WireGuard tunnel, and opening the firewall UI through a read-only reverse proxy path.

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

## MVP features

- Dashboard login with seeded initial admin.
- Company/group creation.
- Company-scoped RBAC model in the database.
- Short-lived single-use OTP enrollment codes stored hashed.
- Device enrollment endpoint using WireGuard public key.
- Device tokens stored hashed; heartbeat uses bearer token auth.
- Automatic Hub WireGuard server bootstrap and peer restore on container startup.
- `/32`-only WireGuard routes for firewall web UI access; customer LAN subnets are never routed.
- WireGuard peer add/remove wrapper with public-key/IP validation.
- Firewall revoke flow invalidates device token and removes WireGuard peer.
- Audit logs for login, company creation, enrollment, revoke, and proxy access.
- Server-rendered dashboard with an Ephemeral-Link-inspired style.
- Side-menu settings area for adding companies, managing users, branding, email settings, Microsoft 365, and Local AD configuration.
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

By default, the app container automatically configures the Hub WireGuard server interface on startup. It generates and persists the Hub server private key under the `opnsense_hub_wg` Docker volume, renders `/etc/wireguard/wg0.conf`, brings up `wg0`, exposes UDP `51820`, and restores enrolled peers from the database.

## Exact dashboard commands

```sh
cd /home/alberto/Projects/OPNsense-Hub
cp .env.example .env
docker compose config
docker compose up --build
```

## WireGuard production notes

OPNsense Hub is a management overlay for opening each firewall's own web UI. It is not a site-to-site VPN router and does not route customer LANs.

The `opnsense-hub-api` container configures WireGuard automatically when `WG_DRY_RUN=false`:

1. Generates `/etc/wireguard/server.key` if it does not exist.
2. Derives the Hub server public key from that private key.
3. Renders `/etc/wireguard/wg0.conf` using `HUB_WG_ADDRESS` and `HUB_WG_LISTEN_PORT`.
4. Runs `wg-quick up /etc/wireguard/wg0.conf` when `wg0` is not already running.
5. Restores all non-revoked device peers from the database on startup.
6. Adds each newly enrolled firewall as a `/32` peer.

AllowedIPs are intentionally narrow:

- Hub side peer route: `firewall_tunnel_ip/32`
- Firewall side peer route: `hub_tunnel_ip/32`

Do not add customer LAN networks such as `192.168.1.0/24` to WireGuard `AllowedIPs`. Many companies can use the same LAN subnet without conflict because the Hub only connects to each firewall's unique tunnel IP.

The server private key is persisted in the `opnsense_hub_wg` Docker volume. Back up this volume securely; losing it requires re-enrolling devices or carefully rotating WireGuard keys.

Set `HUB_WG_ENDPOINT` to the public UDP endpoint that OPNsense firewalls can reach, for example `hub.example.com:51820`, and ensure UDP `51820` is allowed through the host firewall/security group.

For UI-only development without WireGuard privileges, set `WG_DRY_RUN=true`.

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

If enrollment fails, the OPNsense dialog should show an actionable `status: error` message, such as an invalid/expired OTP, HTTPS URL validation failure, missing WireGuard command, or Hub API HTTP status. For lab debugging, run these commands on the firewall and check the returned JSON plus configd logs:

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

## Known MVP limitations

- The FastAPI proxy is intentionally simple. For production, consider Caddy/Nginx with a signed internal auth check or a hardened streaming proxy.
- OPNsense plugin service integration may require adjustment for the exact installed WireGuard plugin/version.
- MFA fields exist, but MFA is not implemented yet.
- Email and Microsoft Graph client secrets entered in the settings UI are not shown back in forms and are never logged, but they are currently stored in the database without application-level encryption. Use restrictive database access and backups until encrypted-at-rest integration secrets are implemented.
