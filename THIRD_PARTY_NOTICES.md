# Third-party notices

This project uses third-party software, images, fonts, and web assets. This file is a practical notice inventory; verify exact versions and transitive dependencies during each release build.

## Runtime Python dependencies

| Dependency | Version in `dashboard/requirements.txt` | License | Notes |
| --- | ---: | --- | --- |
| FastAPI | 0.115.6 | MIT | Web framework. |
| Uvicorn | 0.34.0 | BSD-3-Clause | ASGI server. |
| Jinja2 | 3.1.5 | BSD-3-Clause | Template engine. |
| python-multipart | 0.0.20 | Apache-2.0 | Form parsing. |
| SQLAlchemy | 2.0.36 | MIT | ORM/database toolkit. |
| psycopg / psycopg-binary | 3.2.3 | LGPL-3.0-only with exceptions | PostgreSQL driver. Keep license text available when distributing container images. |
| pydantic-settings | 2.7.1 | MIT | Environment settings. |
| httpx | 0.28.1 | BSD-3-Clause | HTTP client/proxy requests. |
| pytest | 8.3.4 | MIT | Test dependency. |

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
| `caddy:2-alpine` | Docker Hub official Caddy image | Apache-2.0 for Caddy plus Alpine package licenses. |
| `wireguard-tools` | Debian package in dashboard image | GPL-2.0-only. Used as an external command-line tool. |
| `iproute2` | Debian package in dashboard image | GPL-2.0-only. Used for networking support. |

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
