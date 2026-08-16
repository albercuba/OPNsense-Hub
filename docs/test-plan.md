# Test plan

## Automated tests

Run:

```sh
cd dashboard
python -m pytest
python -m compileall app
```

Current coverage:

- Secret hashing and verification.
- OTP format generation.
- WireGuard public key validation against command injection-shaped values.
- `/32`-only WireGuard peer route generation.
- RBAC role ordering.

## Manual tests

1. Start stack with `docker compose up --build`.
2. Log in with the seeded admin user.
3. Create a company.
4. Generate an enrollment OTP and verify it is only shown once.
5. Simulate enrollment with `curl` using a valid WireGuard-shaped public key.
6. Verify a second enrollment using the same OTP fails.
7. Verify the enrolled device appears in the company firewall table.
8. Send heartbeat using the returned device token.
9. Revoke the device and verify later heartbeats fail.
10. Click Open and verify the dashboard sends `POST /devices/{device_id}/proxy/open` with a valid CSRF token into a new tab.
11. Verify the standalone handoff page automatically submits the grant with `POST` to `PROXY_PUBLIC_URL`; disable JavaScript and verify the visible manual submit button works.
12. Verify `/proxy/bootstrap` accepts the grant only once, redirects to the selected `/proxy/devices/{device_id}/` path, and creates a host-only cookie scoped to that exact device path.
13. Verify the cookie cannot authorize another device path and that the dashboard session cookie is not sent to the proxy origin.
14. Verify a proxy-open audit log entry is created, even if the tunnel target is unreachable.

## Plugin lab tests

On a disposable OPNsense VM:

1. Copy plugin files into `/usr/local/opnsense`.
2. Run `service configd restart`.
3. Open `Services > OPNsense Hub`.
4. Enter Hub HTTPS URL and OTP.
5. Click Connect.
6. Confirm `/var/db/opnsensehub/state.json` exists with restrictive permissions.
7. Confirm `/usr/local/etc/wireguard/opnsensehub.conf` exists with restrictive permissions.
8. Confirm the WireGuard private key is never visible in Hub logs or Hub database.
9. Run heartbeat configd action.
10. Test Disconnect stops only the local tunnel and does not delete enrollment state.

## Production readiness tests

- Verify Docker images build from a clean checkout.
- Verify database backup and restore.
- Verify startup creates `/etc/wireguard/server.key`, renders `/etc/wireguard/wg0.conf`, and brings up `wg0` when `WG_DRY_RUN=false`.
- Verify every peer in `wg show` uses only `100.96.x.y/32` AllowedIPs and no customer LAN subnet.
- Verify revocation removes the peer from `wg show`.
- Verify company RBAC prevents cross-company proxy access and unauthorized users cannot obtain a handoff grant.
- Verify expired, replayed, malformed, and wrong-device proxy grants fail closed.
- Verify `PUBLIC_URL` and `PROXY_PUBLIC_URL` are distinct HTTPS origins with valid DNS and TLS.
- Verify the dashboard host returns `404` for `/proxy/bootstrap` and `/proxy/devices/*`.
- Verify the proxy host serves only `/proxy/bootstrap` and `/proxy/devices/*`, and returns `404` for `/`, dashboard, login, settings, and API routes.
- Verify the proxy authorization cookie has no `Domain` attribute and has `Path=/proxy/devices/{device_id}`.
- Verify logs do not contain OTPs, device tokens, proxy grants, dashboard/proxy cookies, or private keys.
