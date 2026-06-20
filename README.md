# OPNsense Hub

OPNsense Hub is an MVP for enrolling OPNsense firewalls into a central dashboard with a short-lived OTP, establishing a WireGuard tunnel, and opening the firewall UI through a read-only reverse proxy path.

> Important: the Hub dashboard/control plane does not modify firewall configuration, restore backups, reboot firewalls, or store OPNsense admin passwords. The only firewall-side configuration change is performed by the OPNsense plugin on that firewall to create its own WireGuard client tunnel.

## Architecture

See `docs/architecture.md`.

## Repository layout

```text
dashboard/
  app/                    FastAPI dashboard/API
  migrations/             SQL schema
  tests/                  Unit tests
  Dockerfile
  requirements.txt
net-mgmt/os-opnsensehub/  OPNsense plugin scaffold
docs/                     Architecture, security, test plan
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
- WireGuard peer add/remove wrapper with public-key/IP validation.
- Firewall revoke flow invalidates device token and removes WireGuard peer.
- Audit logs for login, company creation, enrollment, revoke, and proxy access.
- Server-rendered dashboard with an Ephemeral-Link-inspired style.
- OPNsense plugin scaffold with MVC, configd actions, and backend scripts.

## Run locally

```sh
cp .env.example .env
docker compose up --build
```

Open:

```text
http://localhost:8082
```

Default login comes from `.env`:

```text
INITIAL_ADMIN_EMAIL=admin@example.com
INITIAL_ADMIN_PASSWORD=change-me
```

For local development, `WG_DRY_RUN=true` means enrollment succeeds without requiring a real WireGuard interface. For production, configure a real WireGuard server key/interface and set `WG_DRY_RUN=false`.

## Exact dashboard commands

```sh
cd /home/alberto/Projects/OPNsense-Hub
cp .env.example .env
docker compose config
docker compose up --build
```

## WireGuard production notes

1. Generate a server private/public key pair on the Hub host.
2. Put the public key in `WG_SERVER_PUBLIC_KEY`.
3. Configure `HUB_WG_ENDPOINT` to the public UDP endpoint, for example `hub.example.com:51820`.
4. Ensure UDP `51820` reaches the WireGuard interface.
5. Set `WG_DRY_RUN=false` only after the container can run `wg set` against the configured interface.

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
6. Click `Connect`.
7. The firewall should appear in the company firewalls table.

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
- User management UI is not included in this MVP, though schema supports company users and roles.
