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

### 2. Start the app

```bash
# My Signet app (port 5174)
cd app && node node_modules/vite/bin/vite.js --host &
```

### 3. Access

| App | URL |
|-----|-----|
| My Signet | https://localhost:5174/ |

From other devices on the network: `https://10.10.10.60:5174/`.

HTTPS-only. Use `https://` — plain `http://` will not work.

## One-Command Spinup

```bash
# From the Signet root directory:
docker ps --format '{{.Names}}' | grep -q "^strfry-relay$" || docker start strfry-relay
(cd app && node node_modules/vite/bin/vite.js --host &)
```

## Certificate

The self-signed certificate is at `app/cert/signet.pem` (if present). Install it once — it covers all local interfaces.

### Downloading

The app has a **Download Certificate** button in Settings. Or fetch directly:

- https://localhost:5174/signet.pem

### Regenerating

```bash
bash app/cert/generate-cert.sh
```

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

| Port | Service |
|------|---------|
| 5174 | My Signet app (HTTPS) |
| 7777 | strfry relay (WebSocket, shared with Fathom) |
| 7778 | Blossom server (Fathom) |

Avoid: 3000, 5173, 80, 443 (used by Fathom/nginx).

## Troubleshooting

**`vite: not found`** — The `.bin` symlinks may be missing. Use `node node_modules/vite/bin/vite.js` instead of `vite`.

**Relay not connecting** — Check `docker ps` to confirm the container is running and healthy. If unhealthy, check logs with `docker logs strfry-relay`.

**Self-signed cert warning** — Install the certificate (see above), or accept it manually in the browser.

**Cert doesn't cover your IP** — Edit `app/cert/generate-cert.sh`, add your IP to the SAN list, then run `bash app/cert/generate-cert.sh`.
