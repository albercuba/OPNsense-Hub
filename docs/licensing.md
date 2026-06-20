# Licensing and compliance

This repository is licensed under the BSD 2-Clause License. See `LICENSE`.

## Why BSD 2-Clause

BSD 2-Clause is permissive and compatible with the intended OPNsense plugin ecosystem and the MVP dashboard code. It allows source and binary redistribution while requiring preservation of copyright and disclaimer notices.

## Third-party notices

See `THIRD_PARTY_NOTICES.md` for the current dependency and asset inventory.

The most important compliance points are:

- Keep `LICENSE` and `THIRD_PARTY_NOTICES.md` with source and binary distributions.
- Generate complete transitive dependency reports before tagged releases.
- Review Docker image SBOMs because container images include OS packages beyond this repository.
- Keep LGPL/GPL command-line tool notices available when distributing built images.
- If bundling Font Awesome or JetBrains Mono instead of loading from CDN, include the required font/icon license files.

## CDN privacy note

The MVP loads Font Awesome from cdnjs and JetBrains Mono from Google Fonts. That means users' browsers contact those third-party services. For production deployments with stricter privacy requirements, self-host these assets and include their license notices locally.

## OPNsense trademark note

Use of the word `OPNsense` describes compatibility/integration. OPNsense Hub is independent and is not affiliated with, endorsed by, or sponsored by Deciso B.V. or the OPNsense project unless explicitly stated by those parties.

## Plugin packaging note

The plugin is original scaffold code designed to follow public OPNsense plugin conventions. It does not vendor OPNsense source code. When building inside the OPNsense plugin ports tree, comply with the OPNsense ports/plugin build system requirements and preserve upstream notices provided by that build environment.
