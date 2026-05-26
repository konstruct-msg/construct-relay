# construct-relay

One-command obfs4 relay for [Construct messenger](https://github.com/konstruct-msg/construct-messenger).

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
git clone https://github.com/konstruct-msg/construct-relay
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

## Behind nginx with Apple CDN anti-probe (RU VPS)

For high-risk deployments (Russia, Kazakhstan, etc.) run the relay behind nginx with
SNI-based routing. The key insight: **all non-relay traffic is forwarded to Apple CDN**,
making the IP look like a CDN node — not a proxy.

### Why the naive nginx setup breaks obfs4

A standard `proxy_pass` config (L7 HTTP proxy) terminates TLS and then sees binary
obfs4 bytes — which nginx can't route → 404. WebTunnel worked only because it is a
valid HTTP WebSocket upgrade that nginx could proxy.

### Fix: SNI-based TCP passthrough with Apple CDN default

nginx reads the TLS SNI from the ClientHello **without terminating TLS** and routes:

```
Port 443 inbound
  SNI = api.divany-kresla.uk  →  construct-relay (port 8443, handles own TLS)
  SNI = anything else         →  Apple CDN 17.253.144.10:443
         ↑ scanners, RKN, bare IP probes — they see Apple's certificate
```

Relay clients use `api.divany-kresla.uk` as SNI. Everything else looks like Apple
CDN traffic. The IP is too risky to block (Apple is not blocked in Russia).

### Setup steps

**1. nginx stream module** — `stream {}` блок требует отдельного модуля.

```bash
# Проверить, есть ли модуль:
nginx -V 2>&1 | grep stream_ssl_preread_module   # должно что-то напечатать

# Если нет — установить (Ubuntu/Debian):
apt install libnginx-mod-stream

# Если модуль стоит, но nginx.conf его не видит — добавить ПЕРЕД events{}:
# load_module modules/ngx_stream_module.so;
```

> **Альтернатива без stream-модуля: HAProxy** (`deploy/haproxy-ru-vps.cfg`)  
> `apt install haproxy` — умеет SNI-роутинг из коробки, без доп. модулей.  
> nginx оставляете только на порту 80 (HTTP cover site).

**Важно:** блок `stream {}` должен быть на **верхнем уровне** `/etc/nginx/nginx.conf`,
а не внутри `http {}`. Если вы используете include conf.d/*.conf — этот include обычно
находится внутри `http {}`, туда `stream {}` класть нельзя. Добавляйте `stream {}`
напрямую в nginx.conf вне `http {}`.

```
# /etc/nginx/nginx.conf (структура):
events { ... }
stream { ... }   ← здесь, снаружи http
http {
    include /etc/nginx/conf.d/*.conf;   ← conf.d идёт сюда, stream туда нельзя
}
```

**2. Cover site** HTML in `/var/www/divany-kresla/` (served on port 80 via HTTP).

**3. Relay `.env`**:
```
LISTEN_PORT=127.0.0.1:8443        # loopback only — nginx proxies port 443
TLS_SNI_HOST=api.divany-kresla.uk # MUST match the SNI nginx routes on
WT_PATH=/api/stream               # WebTunnel OK here
TRUSTED_PROXIES=172.16.0.0/12    # Docker bridge (already the default)
```

> **Important:** `TLS_SNI_HOST` must match the SNI clients send (`api.divany-kresla.uk`).
> The relay generates a self-signed cert for this name; iOS clients verify by SPKI
> fingerprint only — hostname mismatch is not an error.

**4. Firewall** — block direct access to port 8443 from the internet:
```bash
ufw deny 8443/tcp
ufw allow 443/tcp
ufw allow 80/tcp
```

**5. Start** relay and reload nginx:
```bash
docker compose up -d
nginx -t && systemctl reload nginx
```

**6. Update `relays.json`** — use port 443 and the relay SNI subdomain:
```json
{
  "addr":        "<VPS_IP>",
  "port":        443,
  "sni":         "api.divany-kresla.uk",
  "wt_path":     "/api/stream",
  "spki_sha256": "<SPKI_HEX from docker logs>",
  "bridge_cert": "<BRIDGE_CERT from docker logs>"
}
```
Add a second entry for the alt-listener (port 52143) as a direct obfs4 fallback
that bypasses nginx.

### Why Apple CDN and not a fake site on port 443

Serving a local cover site on port 443 requires a valid TLS cert for the domain, which
anchors the IP to that domain and makes DPI fingerprinting easier. Forwarding to Apple CDN:
- Presents Apple's valid cert to scanners (no fingerprinting gap)
- Makes the IP appear as an Apple CDN/Akamai node
- Apple IPs are categorically safe from RKN blocking

---

## Do NOT enable WebTunnel on bare IPs (without nginx)

WebTunnel (WebSocket-over-TLS) triggers DPI active probing on bare IP deployments.
The prober sees a WebSocket upgrade response → identifies it as a proxy → **IP blocked
within hours**.

Enable WebTunnel **only** when the relay is behind nginx (cover site setup above) or
a real CDN (Cloudflare Workers, etc.) so TLS terminates somewhere other than the raw
relay IP.

Leave `WT_PATH=` empty in `.env` for the simple bare-IP deployment.

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
