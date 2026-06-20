# Release compliance checklist

Run this before creating public releases or publishing container images.

## Source release

- [ ] Confirm `LICENSE` is present.
- [ ] Confirm `THIRD_PARTY_NOTICES.md` is current.
- [ ] Confirm no secrets are present: `.env`, API keys, OTPs, WireGuard private keys, device tokens, database dumps, customer configs.
- [ ] Confirm OPNsense trademark disclaimer is present in `README.md` and notices.
- [ ] Confirm all generated plugin/package artifacts have correct notices.

## Python dependencies

- [ ] Build a clean virtual environment or image.
- [ ] Run `pip-licenses` and save the report for release artifacts.
- [ ] Review transitive dependencies for copyleft, source-offer, notice, or attribution obligations.

Example:

```sh
cd dashboard
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pip-licenses
pip-licenses --format=markdown --with-license-file --with-urls > ../THIRD_PARTY_PYTHON_LICENSES.md
```

## Container images

- [ ] Generate an SBOM for each published image.
- [ ] Review base image licenses and OS package licenses.
- [ ] Include or link notices for Debian/Alpine packages used in the images.
- [ ] Confirm GPL/LGPL notices for `wireguard-tools`, `iproute2`, and `psycopg` are preserved.

## Web assets

- [ ] If loading from CDN, document privacy implications.
- [ ] If self-hosting Font Awesome, include Font Awesome Free license notices.
- [ ] If self-hosting JetBrains Mono, include SIL OFL 1.1 license notice.

## Final verification

- [ ] Run tests.
- [ ] Run `docker compose config`.
- [ ] Build containers from a clean checkout.
- [ ] Scan release artifacts for private data.
