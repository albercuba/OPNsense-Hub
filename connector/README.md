# OPNsense Hub Connector

The connector exposes one OPNsense device as a local TCP endpoint for a browser. Every accepted local TCP connection opens a separate authenticated WebSocket to:

```text
wss://HUB/api/v1/connector/devices/DEVICE_UUID
```

The connector forwards opaque binary bytes in both directions. It doesn't terminate or inspect the browser's TLS connection and doesn't log the connector token or relayed payloads.

## Requirements

- Python 3.11 or newer
- Network access to an OPNsense Hub HTTPS/WSS origin
- A device UUID and short-lived connector token issued by the Hub

## Install

```sh
cd connector
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` pins `websockets` so connector behavior doesn't change unexpectedly during installation.

## Run

The secure default listener is `127.0.0.1:8443`:

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef
```

When run interactively, the connector prompts for the token without echoing it; this is the recommended path. For managed non-interactive use, provide exactly one token line on standard input from a short-lived, permission-restricted secret file or secret-manager file descriptor:

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef \
  < /run/secrets/opnsense-hub-connector-token
```

`OPNSENSE_HUB_CONNECTOR_TOKEN` is also supported, but process environments may be inspectable on some systems. The token is never accepted as a command argument or URL value. Do not place a literal token in shell commands or shell history.

Open the URL printed by the connector, normally:

```text
https://127.0.0.1:8443/
```

The browser-to-device traffic remains HTTPS. Browser certificate warnings and hostname validation depend on the certificate configured on the target OPNsense device.

## Browser hostname and listener options

To use the hostname expected by the OPNsense certificate and redirects, map that hostname to loopback locally, then use `--browser-host`:

```text
127.0.0.1 firewall.example.test
```

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef \
  --browser-host firewall.example.test
```

`--browser-host` changes only the displayed browser URL. It doesn't change the listener address or DNS. Override the listener separately when needed:

```sh
.venv/bin/python opnsense_hub_connector.py \
  --hub-url https://hub.example.com \
  --device 01234567-89ab-cdef-0123-456789abcdef \
  --listen 127.0.0.1:9443
```

Binding to a non-loopback address exposes an unauthenticated local TCP entry point to the selected firewall. The connector rejects this configuration unless `--allow-non-loopback` is also supplied. Use the override only when explicitly required and protected by host firewall controls. Any local process or user that can connect to the listener can use the active connector token to reach the selected firewall.

## Timeouts and shutdown

- `--connect-timeout SECONDS` limits the WSS opening handshake; default: 15 seconds.
- `--idle-timeout SECONDS` closes a local connection after no payload bytes move in either direction; default: 300 seconds.
- WebSocket ping/pong and close timeouts detect unavailable peers and bound shutdown work.
- `SIGINT` (`Ctrl+C`) and `SIGTERM` stop accepting connections, close active local sockets and WebSockets, and exit cleanly.

Run `--help` for the complete CLI reference.

## Tests

Install the pinned dependency, then run from the repository root:

```sh
connector/.venv/bin/python -m unittest discover -s connector -p 'test_*.py' -v
```
