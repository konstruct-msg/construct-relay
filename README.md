# construct-relay

One-command obfs4 relay for [Construct messenger](https://github.com/maximeliseyev/construct-messenger).

Forwards gRPC traffic through the `construct-ice` obfs4 transport — no TLS certificates or nginx required.

```
[iOS client]  ──obfs4──►  [this relay]  ──gRPC TLS──►  [construct-server]
```

Active-probing resistance built in: TLS/HTTP probes are silently forwarded to a real HTTPS site (`COVER_SITE`), making the relay indistinguishable from a normal web server.

---

## Deploy in 3 steps

### Prerequisites

- A VPS with a public IP (any Linux distro, 1 vCPU / 256 MB RAM is enough)
- Docker + Docker Compose installed ([install script](https://get.docker.com))
- Port 443 open in your firewall

### 1 — Clone and configure

```bash
git clone https://github.com/maximeliseyev/construct-relay
cd construct-relay
cp .env.example .env
nano .env   # set UPSTREAM to your construct-server address
```

`.env`:
```
UPSTREAM=ams.konstruct.cc:443   # your construct-server
LISTEN_PORT=443                 # port exposed to clients
COVER_SITE=cloudflare.com:443   # where TLS probes are forwarded
```

### 2 — Start

```bash
docker compose pull   # pull pre-built image from ghcr.io
docker compose up -d
```

### 3 — Add the bridge cert to your server

```bash
docker compose logs relay | grep "bridge"
```

Copy the **bridge line** from the output and add it to your `construct-server` relay config.  
Copy the **bridge cert** (shorter form) and add it to the iOS app build config.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM` | *(required)* | gRPC server to forward to, e.g. `ams.konstruct.cc:443` |
| `LISTEN_PORT` | `443` | Host port to bind |
| `LISTEN_ADDR` | `0.0.0.0:443` | Full bind address inside container |
| `COVER_SITE` | `cloudflare.com:443` | Cover destination for active probes |
| `STATE_FILE` | `/data/relay.key` | Path for persisted keypair (in Docker volume) |
| `RUST_LOG` | `info` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |

The relay keypair is generated on first start and persisted in the `relay_data` Docker volume.  
**Do not delete the volume** — clients are pinned to the bridge cert derived from this key.

---

## Build from source

```bash
# Requires Rust 1.87+
cargo build --release
UPSTREAM=ams.konstruct.cc:443 ./target/release/construct-relay
```

For local development with a checked-out `construct-ice`, uncomment the `[patch]` block in `Cargo.toml`.
