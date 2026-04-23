# construct-relay

One-command obfs4 relay for [Construct messenger](https://github.com/maximeliseyev/construct-messenger).

Forwards gRPC traffic through the `construct-ice` obfs4 transport — no TLS certificates or nginx required.

```
[iOS client]  ──obfs4──►  [this relay]  ──gRPC TLS──►  [construct-server]
```

Active-probing resistance built in: TLS/HTTP probes are silently forwarded to a real HTTPS site, making the relay indistinguishable from a normal web server.

---

## Deploy in 4 steps

### Prerequisites

- A VPS with a public IP — **Hetzner Finland or Germany recommended** (avoid Yandex Cloud — RU DPI blocks it)
- Docker + Docker Compose installed ([install script](https://get.docker.com))
- Chosen port open in firewall (default: **9894** — avoid 443/9443, they are on DPI watch-lists)

### 1 — Clone and configure

```bash
git clone https://github.com/maximeliseyev/construct-relay
cd construct-relay
cp .env.example .env
nano .env   # set UPSTREAM to your construct-server address
```

Minimum `.env`:
```
UPSTREAM=ams.konstruct.cc:443
LISTEN_PORT=9894
TLS_SNI_HOST=fra1.digitaloceanspaces.com
```

Pick `TLS_SNI_HOST` to match the VPS provider's region:

| Provider / region | Recommended SNI |
|---|---|
| Hetzner DE / FI | `fra1.digitaloceanspaces.com` |
| DigitalOcean AMS | `ams3.digitaloceanspaces.com` |
| OVH / Scaleway | `storage.sbg.cloud.ovh.net` |
| Any | `storage.bunnycdn.com` |

### 2 — Start

```bash
docker compose pull
docker compose up -d
```

### 3 — Collect values from logs

```bash
docker compose logs relay | grep -E "bridge cert|SPKI|bridge line"
```

You will see three lines:
```
║  obfs4 bridge cert:
║    <BRIDGE_CERT>
║  TLS SPKI fingerprint (→ iOS ICEConfig):
║    <SPKI_HEX>
║  bridge line:
║    obfs4 <IP>:<PORT> <FINGERPRINT> cert=<BRIDGE_CERT> iat-mode=0
```

Copy `<BRIDGE_CERT>` and `<SPKI_HEX>` — you need them in Step 4.

### 4 — Publish config (clients auto-update via OTA)

In `construct-server/tools/`:

1. Add the new relay to `relays.json`:
   ```json
   {
     "id": "ru-het-1",
     "addr": "<VPS_IP>",
     "port": 9894,
     "domain": "ru-het-1.relay.konstruct.cc",
     "sni": "fra1.digitaloceanspaces.com",
     "spki_sha256": "<SPKI_HEX from logs>",
     "bridge_cert": "<BRIDGE_CERT from logs>",
     "wt_path": null,
     "region": "RU"
   }
   ```

2. Sign and publish:
   ```bash
   pip3 install cryptography
   python3 sign_relay_manifest.py sign relays.json --key relay_signing_key.hex
   ```
   Output: `.well-known/construct-server`

3. Commit and push (iOS clients auto-fetch via GitHub mirror within minutes):
   ```bash
   git add .well-known/construct-server
   git commit -m "relay: add ru-het-1"
   git push
   ```

> **iOS clients pick up the new relay automatically** — no app update required.
> Config is fetched from `konstruct.cc/.well-known/construct-server` and the GitHub mirror on every app start.

---

## Do NOT enable WebTunnel on bare IPs

WebTunnel (WebSocket-over-TLS) triggers DPI active probing. The prober sees a WebSocket upgrade response → identifies it as a proxy → **IP gets blocked within hours**.

Enable WebTunnel **only** after placing a real CDN (Cloudflare Workers, etc.) in front of the relay so TLS terminates at the CDN node, not at your VPS IP.

Leave `WT_PATH=` empty in `.env` (the default).

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM` | *(required)* | gRPC server, e.g. `ams.konstruct.cc:443` |
| `LISTEN_PORT` | `9894` | **Host** port exposed to clients |
| `TLS_SNI_HOST` | `fra1.digitaloceanspaces.com` | TLS cert CN / SNI to impersonate |
| `WT_PATH` | *(empty)* | WebTunnel path — leave empty unless behind CDN |
| `STATE_DIR` | `/data` | Persistent key storage (mapped to Docker volume) |
| `RUST_LOG` | `info` | Log verbosity |

The relay keypair is generated on first start and persisted in the `relay_data` Docker volume.  
**Do not delete the volume** — clients are pinned to the SPKI fingerprint derived from this key.

---

## Key rotation

If you need to recreate the container (new server, new cert):

1. `docker compose down -v` — deletes the volume and forces new key generation
2. Restart → new SPKI + bridge_cert printed in logs
3. Update `relays.json` with new values → re-sign → push

---

## Build from source

```bash
# Requires Rust 1.87+
cargo build --release
UPSTREAM=ams.konstruct.cc:443 LISTEN_ADDR=0.0.0.0:9894 ./target/release/construct-relay
```

For local development with a checked-out `construct-ice`, uncomment the `[patch]` block in `Cargo.toml`.
