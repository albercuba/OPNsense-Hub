# Third-party notices

This project uses third-party software, images, fonts, and web assets. This file is a practical notice inventory; verify exact versions and transitive dependencies during each release build.

## Runtime Python dependencies

| Dependency | Version in manifest | License | Notes |
| --- | ---: | --- | --- |
| FastAPI | 0.115.6 | MIT | Web framework in `dashboard/requirements.txt`. |
| Uvicorn | 0.34.0 | BSD-3-Clause | ASGI server in `dashboard/requirements.txt`; installed with the `standard` extra. |
| websockets | 17.0.1 | BSD-3-Clause | WebSocket client/server support in both `dashboard/requirements.txt` and `connector/requirements.txt`. |
| Jinja2 | 3.1.5 | BSD-3-Clause | Template engine in `dashboard/requirements.txt`. |
| python-multipart | 0.0.20 | Apache-2.0 | Form parsing in `dashboard/requirements.txt`. |
| SQLAlchemy | 2.0.36 | MIT | ORM/database toolkit in `dashboard/requirements.txt`. |
| psycopg / psycopg-binary | 3.2.3 | LGPL-3.0-only with exceptions | PostgreSQL driver in `dashboard/requirements.txt`. Keep license text available when distributing container images. |
| pydantic-settings | 2.7.1 | MIT | Environment settings in `dashboard/requirements.txt`. |
| httpx | 0.28.1 | BSD-3-Clause | HTTP client/proxy requests in `dashboard/requirements.txt`. |
| PyJWT | 2.10.1 | MIT | JWT handling in `dashboard/requirements.txt`; installed with the `crypto` extra. |
| cryptography | 45.0.4 | Apache-2.0 OR BSD-3-Clause | Cryptographic primitives used by PyJWT/MFA and secret handling in `dashboard/requirements.txt`. |
| redis | 5.2.1 | MIT | Redis client in `dashboard/requirements.txt`. |
| ldap3 | 2.9.1 | LGPL-3.0-only | Local AD/LDAP integration in `dashboard/requirements.txt`. |
| pyasn1 | >=0.4.8,<0.6 | BSD-2-Clause | ASN.1 support for LDAP integration in `dashboard/requirements.txt`. |
| qrcode | 8.2 | BSD-3-Clause | TOTP QR-code generation in `dashboard/requirements.txt`. |
| Alembic | 1.16.2 | MIT | Database migration tooling used for explicit and startup migrations in `dashboard/requirements.txt`. |
| pytest | 8.3.4 | MIT | Test dependency in `dashboard/requirements.txt`. |

Transitive dependencies are installed by `pip` when building the image. Generate a complete dependency notice for releases with a tool such as `pip-licenses` from inside the built image or virtual environment.

Example:

```sh
pip install pip-licenses
pip-licenses --format=markdown --with-license-file --with-urls > THIRD_PARTY_PYTHON_LICENSES.md
```

## Container base images and OS packages

| Component | Source | License notes |
| --- | --- | --- |
| `python:3.12-slim` | Docker Hub official Python image | Includes Python and Debian packages under their respective licenses. Review image SBOM for release distribution. |
| `postgres:16-alpine` | Docker Hub official PostgreSQL image | PostgreSQL License plus Alpine package licenses. |
| `redis:7-alpine` | Docker Hub official Redis image | Redis server licensing depends on the exact 7.x tag/digest; review the image SBOM and upstream Redis license for the release being distributed, plus Alpine package licenses. |
| `caddy:2-alpine` | Docker Hub official Caddy image | Apache-2.0 for Caddy plus Alpine package licenses. |
| `wireguard-tools` | Debian package in dashboard image | GPL-2.0-only. Used as an external command-line tool. |
| `iproute2` | Debian package in dashboard image | GPL-2.0-only. Used for networking support. |
| `iptables` | Debian package in dashboard image | GPL-2.0-only. Used for tunnel isolation policy fallback. |
| `nftables` | Debian package in dashboard image | GPL-2.0-only. Used for tunnel isolation policy management. |
| `procps` | Debian package in dashboard image | GPL-2.0-or-later. Used for runtime sysctl checks. |
| `ca-certificates` | Debian package in dashboard image | MPL-2.0 and public-domain certificate data; review Debian package notices for exact contents. Used for TLS certificate verification. |

## Web fonts and icons

| Asset | How used | License / terms |
| --- | --- | --- |
| Font Awesome Free 6.5.2 | Loaded from cdnjs in HTML templates | Font Awesome Free License: icons CC BY 4.0, fonts SIL OFL 1.1, code MIT. Keep attribution notices when bundling. |
| JetBrains Mono | Loaded from Google Fonts in CSS | SIL Open Font License 1.1. If self-hosting, include font license text. |
| cdnjs | CDN provider for Font Awesome CSS | Subject to cdnjs/Cloudflare terms. Consider self-hosting for production privacy/compliance. |
| Google Fonts | CDN provider for JetBrains Mono | Subject to Google Fonts terms and client IP disclosure to Google. Consider self-hosting for production privacy/compliance. |

## OPNsense and trademarks

OPNsense is an open-source firewall platform and a trademark of its respective owner(s). OPNsense Hub is an independent project and is not affiliated with, endorsed by, or sponsored by Deciso B.V. or the OPNsense project unless explicitly stated by those parties.

The plugin scaffold follows public OPNsense plugin conventions but does not vendor OPNsense source code in this repository.

## Release checklist

Before publishing a release or distributing container images:

1. Generate a complete dependency license report including transitive Python packages.
2. Capture or link container image SBOMs for base images and OS packages.
3. Include this file, `LICENSE`, and generated notices in source/binary distributions.
4. If fonts/icons are bundled instead of loaded from CDN, include their license files.
5. Re-check trademark wording in UI, README, package metadata, and release notes.
6. Do not include secrets, private keys, OTPs, tokens, customer firewall data, or private OPNsense configuration exports in release artifacts.
