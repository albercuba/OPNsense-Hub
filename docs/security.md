# Security notes and production hardening checklist

## Current MVP protections

- OTP enrollment codes are generated randomly, short-lived, single-use, and stored only as PBKDF2 hashes.
- Device tokens are random, shown only to the enrolling plugin, and stored hashed in PostgreSQL.
- WireGuard private keys are generated locally on OPNsense and never sent to Hub.
- Hub validates WireGuard public key shape and tunnel IP before invoking `wg`.
- Dashboard RBAC checks happen before device detail, revoke, and proxy access.
- Proxy access and revocation are audit logged.
- Revocation invalidates the stored device token hash and removes the WireGuard peer.
- The Hub never stores OPNsense web UI credentials.

## Redacted/sensitive fields

Never log or display these values:

- OTP enrollment codes after initial display.
- Device tokens.
- WireGuard private keys.
- OPNsense administrator passwords or session cookies.
- Any firewall GUI credentials proxied through the Hub.

## Production hardening checklist

- `security: enforce HTTPS and secure cookies` — set `SESSION_SECURE=true` and deploy behind HTTPS.
- `security: replace default secrets` — set a long random `SECRET_KEY`, admin password, and database password.
- `security: enable MFA` — implement TOTP/WebAuthn using the existing MFA-ready user model.
- `security: harden proxy headers` — strip hop-by-hop headers, restrict methods if needed, and consider a battle-tested reverse proxy.
- `security: pin firewall certificates` — replace `PROXY_VERIFY_TLS=false` with certificate pinning or an internal CA.
- `security: isolate WireGuard management` — move peer updates into a minimal privileged sidecar or host service.
- `security: rate limit login and enrollment` — add IP/user rate limits to auth and enrollment endpoints.
- `security: add CSRF protection` — server-rendered forms should get CSRF tokens before production use.
- `security: encrypt database backups` — configs, tokens hashes, metadata, and audit data are sensitive.
- `security: monitor audit logs` — alert on repeated failed enrollment, unexpected proxy opens, and revocations.
