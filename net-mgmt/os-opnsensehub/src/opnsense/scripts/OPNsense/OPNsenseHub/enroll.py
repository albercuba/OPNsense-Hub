#!/usr/local/bin/python3
"""Compatibility entrypoint: enrollment is implemented by connect.py."""

import runpy

runpy.run_path(
    "/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/connect.py", run_name="__main__"
)
