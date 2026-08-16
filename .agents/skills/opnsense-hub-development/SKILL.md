---
name: opnsense-hub-development
description: Implement, debug, review, and test OPNsense Hub dashboard, API, WireGuard security, PostgreSQL migrations, server-rendered UI, Docker deployment, and OPNsense plugin changes. Use for work anywhere in the OPNsense-Hub repository.
---

# OPNsense Hub Development

Use this skill for changes to the OPNsense Hub control plane or OPNsense plugin.

## Start with context

1. Read `AGENTS.md` and follow it.
2. Read the relevant section of `README.md` and `docs/architecture.md` before changing security, networking, enrollment, authentication, backup, restore, or deployment behavior.
3. Inspect the implementation and its existing tests before editing. Make the smallest safe change and preserve unrelated work.

## Repository map

- `dashboard/app/`: FastAPI application, REST API, server-rendered UI, services, security, RBAC, database, and WireGuard logic.
- `dashboard/app/routers/`: API route handlers.
- `dashboard/app/templates/`: Jinja templates.
- `dashboard/app/static/`: dashboard CSS, JavaScript, and assets.
- `dashboard/migrations/`: Alembic/SQL schema migrations.
- `dashboard/tests/`: pytest coverage.
- `net-mgmt/os-opnsensehub/`: OPNsense plugin in standard MVC/configd layout.
- `deploy/`: reverse-proxy and deployment examples.
- `docker-compose.yml`: PostgreSQL, application, WireGuard, and optional Caddy services.

## Architecture and security invariants

Preserve these invariants in every design and review:

- The Hub is a management overlay, not a site-to-site router.
- Each firewall peer route is its unique WireGuard IPv4 `/32`; never add customer LAN subnets to `AllowedIPs`.
- A firewall may reach only the Hub dashboard/control-plane service over the tunnel. It must not reach another firewall, device, or service in the dashboard network.
- Keep IP forwarding disabled by default and preserve the `wg0 -> wg0` forwarding drop behavior.
- The Hub never stores OPNsense administrator passwords or firewall WireGuard private keys.
- Enrollment OTPs are short-lived, single-use, and hashed at rest.
- Dashboard session tokens and device tokens remain random, hashed, expiring/revocable credentials.
- Apply company-scoped RBAC before exposing device data or proxy access, and audit security-sensitive actions.
- Validate all WireGuard addresses, public keys, and returned plugin configuration before invoking privileged commands or persisting state.
- Keep privileged plugin operations in backend scripts under `net-mgmt/os-opnsensehub/src/opnsense/scripts/OPNsense/OPNsenseHub`; PHP controllers should save settings and invoke configd actions.
- The plugin generates and retains its WireGuard private key locally.
- The Hub may request and display firmware checks but must not install OPNsense updates.

When changing network behavior, add or update tests proving narrow `/32` routing and peer/network isolation. Reject broader access rather than silently normalizing it.

## Backend and database changes

- Follow existing FastAPI, SQLAlchemy, Pydantic settings, and service-layer patterns.
- Keep route handlers thin when reusable business logic belongs in a service module.
- Use parameterized ORM/query APIs; do not construct SQL from untrusted input.
- Add a migration for persistent schema changes and keep startup migration behavior compatible with existing deployments.
- Update tests for authorization failures, invalid input, revoked credentials, and expected success paths.
- Avoid leaking credentials, tokens, private keys, configuration archives, or sensitive upstream responses into logs or API errors.

## UI changes

- Reuse the existing Jinja structure, CSS variables, components, density, responsive behavior, and light/dark themes.
- Preserve accessibility: labels, keyboard behavior, focus visibility, semantic controls, and meaningful status text.
- Use green or teal for Backup actions.
- Use amber or orange for Restore actions; use red only when an action is actually destructive.
- Do not introduce a new visual language or dependency for a change that existing components can support.

## Validation

Run the narrowest relevant tests first. Typical dashboard test command from the repository root:

```sh
python -m pytest dashboard/tests/<relevant-test-file>.py
```

If the host environment lacks dependencies, use the project container or install from `dashboard/requirements.txt` only when appropriate. For broader validation, run:

```sh
python -m pytest dashboard/tests
```

For Compose changes, run:

```sh
docker compose config
```

For UI changes, inspect both light and dark themes and narrow/mobile layout when browser tooling is available. For plugin changes, validate syntax with the available PHP/Python tooling and verify paths and commands against current OPNsense conventions rather than guessing.

Report commands actually run and any environment limitation. Do not claim checks passed unless they were executed successfully.
