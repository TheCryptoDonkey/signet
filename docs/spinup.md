# Signet Local Development — Spinup Guide

## Prerequisites

- Docker (for the strfry relay)
- Node.js v24+
- The `strfry-relay` Docker container must exist (one-time setup, see below)

## Quick Start

### 1. Check and start the relay

```bash
# Check if strfry-relay is running
docker ps --format '{{.Names}}' | grep -q "^strfry-relay$" && echo "Relay: running" || echo "Relay: stopped"

# Start it if stopped
docker start strfry-relay
```

The relay listens on `ws://localhost:7777`. Health check: `curl -s http://localhost:7777/`.

### 2. Start the apps

```bash
# Reference app (port 5174)
cd app && node node_modules/vite/bin/vite.js --host &

# Family app (port 5175)
cd family-app && node node_modules/vite/bin/vite.js --host &
```

### 3. Access

| App | HTTPS | HTTP (auto-redirects) |
|-----|-------|-----------------------|
| Reference app | https://localhost:5174/ | http://localhost:5180/ |
| Family app | https://localhost:5175/ | http://localhost:5181/ |
| Relay | ws://localhost:7777 | — |

HTTP requests to ports 5180/5181 auto-redirect to the HTTPS ports. Both apps also respond on the network IP (https://10.10.10.60:5174/, etc.).

## One-Command Spinup

```bash
# From the Signet root directory:
docker ps --format '{{.Names}}' | grep -q "^strfry-relay$" || docker start strfry-relay
(cd app && node node_modules/vite/bin/vite.js --host &)
(cd family-app && node node_modules/vite/bin/vite.js --host &)
```

## Certificate

Both apps share one self-signed certificate (`app/cert/signet.pem`). Install it once — it covers both ports.

### Downloading

Both apps have a **Download Certificate** button in their Settings page. Or fetch directly:

- https://localhost:5174/signet.pem (reference app)
- https://localhost:5175/signet.pem (family app)

### Regenerating

```bash
bash app/cert/generate-cert.sh
```

This regenerates the cert and copies it to both `app/public/` and `family-app/public/`. The cert covers:

- `localhost`, `*.local`
- `127.0.0.1`, `10.10.10.60`, `172.17.0.1`, `192.168.1.1`, `10.0.2.15`

### Installing on devices

| Platform | Steps |
|----------|-------|
| **iOS** | Download .pem → Settings → General → VPN & Device Management → install profile → Settings → General → About → Certificate Trust Settings → enable |
| **Android** | Download .pem → Settings → Security → Install from storage → CA certificate |
| **macOS** | Download → open in Keychain Access → find "Signet Local Dev" → Trust → Always Trust |
| **Firefox** | Settings → Privacy & Security → Certificates → Import → trust for websites |

## Relay Details

- **Software:** strfry (via Docker image `dockurr/strfry:latest`)
- **Container name:** `strfry-relay`
- **Config:** `/home/mintai/Fathom/relay/strfry.conf`
- **Data:** `/home/mintai/Fathom/.relay-data`
- **Port:** 7777 (bound to all interfaces)

The relay is shared with the Fathom project. Fathom's `start-dev.sh` also starts it.

### First-time relay setup

If the `strfry-relay` container doesn't exist yet:

```bash
docker run -d \
  --name strfry-relay \
  --restart unless-stopped \
  -p 7777:7777 \
  -v /home/mintai/Fathom/relay/strfry.conf:/etc/strfry.conf \
  -v /home/mintai/Fathom/.relay-data:/app/strfry-db \
  --health-cmd="curl -ILfSs http://localhost:7777/ > /dev/null || exit 1" \
  --health-interval=60s \
  --health-timeout=10s \
  --health-retries=2 \
  dockurr/strfry:latest
```

## Port Allocation

| Port | Service | Protocol |
|------|---------|----------|
| 5174 | Signet reference app | HTTPS |
| 5175 | My Signet family app | HTTPS |
| 5180 | Reference app HTTP redirect | HTTP → 5174 |
| 5181 | Family app HTTP redirect | HTTP → 5175 |
| 7777 | strfry relay (shared with Fathom) | WebSocket |
| 7778 | Blossom server (Fathom) | HTTP |

Avoid: 3000, 5173, 80, 443 (used by Fathom/nginx).

## Troubleshooting

**`vite: not found`** — The `.bin` symlinks may be missing. Use `node node_modules/vite/bin/vite.js` instead of `vite`.

**Relay not connecting** — Check `docker ps` to confirm the container is running and healthy. If unhealthy, check logs with `docker logs strfry-relay`.

**Self-signed cert warning** — Install the certificate (see above). Or accept it manually in the browser. The mkcert root CA from Fathom is also at `/home/mintai/Fathom/client/static/rootCA.pem`.

**Cert doesn't cover your IP** — Regenerate with `bash app/cert/generate-cert.sh` after adding your IP to the SAN list in the script.
