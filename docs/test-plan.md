# Test plan

## Automated tests

Run the access-path tests first, then broader validation:

```sh
PYTHONPATH=dashboard python -m pytest dashboard/tests/test_proxy_origin.py dashboard/tests/test_tcp_relay.py dashboard/tests/test_security.py
python -m unittest discover -s connector -p 'test_*.py' -v
python -m unittest discover -s net-mgmt/os-opnsensehub/tests -p 'test_*.py' -v
PYTHONPATH=dashboard python -m pytest dashboard/tests
python -m compileall dashboard/app connector
```

Validate both Compose modes:

```sh
docker compose config
docker compose -f docker-compose.yml -f deploy/docker-compose.l4.yml config
```

Relevant automated coverage must prove:

- CSRF and company-scoped RBAC are required before connector token creation.
- Connector tokens are hashed at rest, short-lived, device-scoped, bound to the issuing dashboard session, and rejected when missing, malformed, expired, for another device/company, or revoked.
- The connector WSS route requires bearer authentication, accepts binary frames only, forwards exact opaque bytes, enforces connection/time limits, and closes access on revocation/shutdown.
- `/proxy/bootstrap` and `/proxy/devices/*` return `404`; no proxy cookie is created or required.
- Connector CLI validation accepts the token only from a hidden prompt, stdin, or `OPNSENSE_HUB_CONNECTOR_TOKEN`, never a command argument or URL.
- The connector defaults to loopback, requires `--allow-non-loopback` for broader listeners, validates device/URL/listener arguments, forwards exact bytes, handles idle timeout, and shuts down cleanly.
- The raw relay forwards exact bytes, constructs an exact per-device hostname, rejects a nonmatching source IP before upstream connect, enforces connection caps, expires hard, applies idle timeout, atomically replaces per-device allocations, cleans up after handoff failures, and releases ports.
- Startup validation refuses production external/disabled tunnel isolation without `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true`, rejects an invalid control-plane port, and permits enabled kernel forwarding only while the managed or verified-external default-drop policy remains active.
- nftables and iptables/ip6tables tests prove established return traffic is allowed, new tunnel input is restricted to `HUB_WG_CIDR -> HUB_WG_ADDRESS:HUB_CONTROL_PLANE_PORT/TCP`, all other IPv4/IPv6 tunnel input is dropped, and every forwarded packet originating from `wg0` is dropped regardless of output interface.
- Startup validation rejects invalid connector/relay limits and refuses `PUBLIC_L4_RELAY_ENABLED=true` unless `PUBLIC_L4_RELAY_MTLS_REQUIRED=true`.
- Firewall backup tests use the actual OpenSSL command to prove encryption/decryption, key separation and root-only permissions, MAC tamper rejection, wrong-key rejection, recovery-key export/import, and absence of XML plaintext from the upload request.
- Hub tests prove capability gating, pending-request enforcement, strict encrypted-envelope validation, server-time retention, plaintext upload rejection, opaque no-store download, and Hub export/restore without a `content` field.
- Existing security coverage continues to prove secret hashing, OTP format, WireGuard key validation, `/32`-only routes, and RBAC ordering.

## Default connector manual tests

1. Start the normal stack with `docker compose up --build`; do not apply `deploy/docker-compose.l4.yml` and confirm TCP `55000-55099` is not published.
2. Log in, create a company, generate an enrollment OTP, enroll a disposable OPNsense firewall, and verify OTP replay fails.
3. Verify the firewall receives only its unique WireGuard `/32`, heartbeats work, and the WebGUI is reachable from the Hub only at `OPNSENSE_GUI_PORT` through the tunnel.
4. Click Open and verify the browser sends a CSRF-protected `POST /devices/{device_id}/proxy/open` on `PUBLIC_URL`.
5. Verify the response has `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, contains a short-lived connector token/instructions, creates no proxy authorization cookie, and contains no `/proxy/bootstrap` handoff.
6. Verify a `device.connector.open` audit event is written even if the subsequent firewall TCP connection cannot be established.
7. Install the connector in a virtual environment:

   ```sh
   cd connector
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   ```

8. Run `opnsense_hub_connector.py --hub-url <PUBLIC_URL> --device <UUID>` and enter the token at the hidden prompt. Confirm the listener defaults to `127.0.0.1:8443`.
9. Repeat once with one token line from a permission-restricted secret file on stdin and once with `OPNSENSE_HUB_CONNECTOR_TOKEN`. Confirm `--help` exposes no connector-token argument, literal tokens are absent from shell history/process arguments, and putting a token in the Hub URL is rejected.
10. Open the connector's local HTTPS URL and verify the complete OPNsense login/session flow works while packet/log inspection at the Hub shows only TLS ciphertext, not credentials, cookies, paths, or response bodies.
11. Verify the browser reports the OPNsense WebGUI certificate. If its SAN expects a firewall hostname, map that hostname to `127.0.0.1`, run with `--browser-host <certificate-hostname>`, and confirm hostname validation and OPNsense redirects work without disabling certificate checks.
12. Verify a token cannot connect to another device, a cross-company user cannot obtain a token, an expired token cannot start a new WSS stream, and device revocation closes active access. Revoke the issuing dashboard session and remove company membership while a stream is active; verify the stream closes within `CONNECTOR_AUTHORIZATION_RECHECK_SECONDS`.
13. Exercise concurrent browser connections and verify `CONNECTOR_MAX_CONNECTIONS`, `CONNECTOR_CONNECTION_MAX_SECONDS`, and token expiry terminate or reject access as configured.
14. Confirm direct requests to `/proxy/bootstrap` and `/proxy/devices/{device_id}/` return `404` and no separate proxy origin is serving dashboard or firewall traffic.

## Optional public L4 relay tests

Run these tests only in a disposable environment whose OPNsense WebGUI is already configured to require a trusted browser client certificate.

1. Confirm `POST /devices/{device_id}/relay/open` returns `404` while `PUBLIC_L4_RELAY_ENABLED=false`.
2. Set `PUBLIC_L4_RELAY_ENABLED=true` while leaving `PUBLIC_L4_RELAY_MTLS_REQUIRED=false`; verify startup fails closed.
3. Configure the test WebGUI to reject clients without an approved certificate and to present a trusted certificate valid for the exact generated name `d-{device UUID without dashes}.<PROXY_PUBLIC_URL hostname>`.
4. Configure wildcard DNS for `*.<PROXY_PUBLIC_URL hostname>` to the single Hub node. Verify resolution of the exact generated device hostname.
5. Set both relay gates to `true`, open TCP `55000-55099`, and start with the override:

   ```sh
   docker compose -f docker-compose.yml -f deploy/docker-compose.l4.yml --profile reverse-proxy up -d --build
   ```

6. Verify Caddy serves only dashboard HTTPS/WSS and does not listen on or terminate TLS for TCP `55000-55099`; the raw relay must reach the API container directly.
7. Submit the CSRF/RBAC-protected relay-open POST and verify a `device.relay.open` audit event, a random port in `55000-55099`, the exact per-device hostname, and the configured hard expiry.
8. Connect from the authorized source IP with the approved browser client certificate and verify OPNsense terminates TLS and serves the WebGUI. Verify the Hub cannot decrypt the stream.
9. Connect without a client certificate, with an unapproved certificate, or with a hostname mismatch and verify OPNsense/browser rejects access.
10. Connect from a different source IP and verify the relay closes before opening the upstream firewall connection. Repeat through any L4 load balancer and verify it preserves the original source IP; do not enable PROXY protocol because the relay does not parse it.
11. Verify idle timeout, maximum concurrent connections, hard TTL, explicit replacement of a prior device relay, device revocation, and Hub shutdown all close listeners/connections and release ports.
12. Document the same-NAT risk by confirming source-IP filtering cannot distinguish two clients sharing one public egress IP; client-certificate enforcement must still reject the unauthorized client.
13. Verify a second Hub API replica cannot share allocations or accept a relay created by the first. Keep the relay deployment single-node/single-process and ensure dashboard POSTs and raw ports reach the same instance.

## WireGuard isolation tests

Run these tests in a disposable Linux/Compose environment with real network namespaces:

1. Start the bundled deployment with `NETWORK_CONTROL_MODE=inline`, `HUB_MANAGE_FIREWALL_RULES=true`, `HUB_ENABLE_IP_FORWARDING=false`, and `HUB_CONTROL_PLANE_PORT=8083`.
2. Confirm startup reports successful policy verification. Inspect `nft list table inet opnsense_hub` or the `OPNHUB_INPUT`/`OPNHUB_FORWARD` iptables chains.
3. From an enrolled firewall tunnel address, confirm a new TCP connection to the exact Hub WireGuard address and port `8083` is permitted.
4. Confirm new connections from `wg0` to another local port, another Hub/container address, ICMP, UDP, and IPv6 are dropped.
5. Initiate WebGUI TCP traffic from Hub to a firewall and confirm established return packets entering `wg0` remain permitted.
6. Temporarily enable kernel forwarding and confirm packets originating from `wg0` cannot reach another peer, `eth0`, the Docker bridge, or an external routed address.
7. Remove or alter one required rule and verify production startup fails policy verification.
8. Set `NETWORK_CONTROL_MODE=external` or `HUB_MANAGE_FIREWALL_RULES=false` without external-policy attestation and verify production startup fails. Set `HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true` only after independently reproducing steps 3-6 against the external policy.

## Plugin lab tests

On a disposable OPNsense VM:

1. Copy plugin files into `/usr/local/opnsense`.
2. Run `service configd restart`.
3. Open `Services > OPNsense Hub`.
4. Enter Hub HTTPS URL and OTP, then click Connect.
5. Confirm `/var/db/opnsensehub/state.json`, `/var/db/opnsensehub/backup_master.key`, and `/usr/local/etc/wireguard/opnsensehub.conf` exist with restrictive permissions after the first encrypted backup.
6. Confirm the WireGuard private key, firewall backup master key, plaintext `config.xml`, and decrypted configuration are never visible in Hub requests, logs, database rows, downloads, or Hub exports.
7. Run the heartbeat configd action and confirm plugin `0.2` advertises `opnsense-config-encrypted-v1`; confirm an older/non-advertising heartbeat receives `backup_requested=false`.
8. Export the backup recovery key to offline storage, compare its key fingerprint with `key-info`, import it into a disposable replacement environment, and decrypt a downloaded `.opnenc` backup. Verify tampering and a wrong key fail before plaintext is written.
9. Verify Disconnect stops only the local tunnel and does not delete enrollment state or the independent backup master key.
10. If testing the optional relay, verify the WebGUI's exact hostname certificate and mandatory client-certificate policy directly on OPNsense before exposing relay ports.

## Migration and production readiness tests

- Upgrade a database at revision `0010_device_proxy_sessions` to `0011_connector_access_sessions`; verify the phase constraint accepts `connector` records, `dashboard_session_id` references `sessions(id)` with cascade deletion, and existing access-session rows remain intact.
- Downgrade only in a disposable database; verify connector rows are removed before the old phase constraint is restored.
- Upgrade both a revision-`0011` database containing plaintext `device_backups.content` and a fresh database to `0012_encrypted_device_backups`. Verify plaintext rows are deleted, backup timestamps are reset, the encrypted columns/constraint exist, and enabled capable devices upload replacements.
- Verify an unversioned legacy database is stamped and then upgraded through `head` in the same startup rather than starting against the legacy plaintext column.
- Verify downgrade deletes ciphertext rather than exposing it as XML, and verify old Hub archive format/version or a version-2 archive containing `device_backups[].content` is rejected.
- Verify startup migration reaches Alembic `head`, then test application backup and restore without expecting environment variables or firewall recovery keys to be restored.
- Verify Docker images build from a clean checkout.
- Verify startup creates `/etc/wireguard/server.key`, renders `/etc/wireguard/wg0.conf`, and brings up `wg0` when `WG_DRY_RUN=false`.
- Verify every peer in `wg show` uses only `100.96.x.y/32` AllowedIPs and no customer LAN subnet; revocation must remove the peer.
- Verify the installed tunnel policy default-drops all forwarding from `wg0`, restricts new tunnel input to the exact control-plane address/port, permits established Hub-initiated return traffic, and fails production startup when inline enforcement or verified external enforcement is absent.
- Verify production HTTPS/WSS works at `PUBLIC_URL`, Caddy forwards WSS upgrades, and connector tokens never appear in URLs, access logs, referrers, or shell command history.
- Verify `PROXY_PUBLIC_URL` is used only as the optional relay DNS base and that no L7 `/proxy/*` service or proxy cookie remains.
- Verify logs do not contain OTPs, device tokens, connector tokens, dashboard cookies, OPNsense credentials/session cookies, client-certificate private keys, plaintext firewall configurations, firewall backup recovery keys, private keys, or relayed payload bytes.
- After the plaintext-backup migration, verify legacy Hub exports, PostgreSQL backups/snapshots, WAL archives, and storage replicas containing old rows are expired under the deployment's data-retention policy.
- Verify monitoring alerts on unexpected connector/relay opens, authorization failures, connection-limit events, relay allocation failures, and revocations.
