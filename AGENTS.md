# AGENTS.md — construct-relay

Context for AI agents working in this repository.

---

## What is construct-relay?

A one-command obfs4 relay that forwards gRPC traffic through the `construct-ice` obfs4 transport.

```
[iOS/Android/Desktop client]  ──obfs4──►  [this relay]  ──gRPC TLS──►  [construct-server]
```

Active-probing resistance: TLS/HTTP probes are forwarded to a real HTTPS site — relay
is indistinguishable from a normal web server.

---

## Structure

```
src/
├── main.rs   — relay server, obfs4 listener, upstream gRPC forwarding
└── tls.rs    — TLS certificate handling, SNI domain-fronting
Dockerfile
docker-compose.yml
.env.example
```

---

## Deploy

```bash
cp .env.example .env
# Edit .env — set UPSTREAM, LISTEN_PORT, TLS_SNI_HOST
docker compose up -d
```

Key `.env` variables:
- `UPSTREAM` — construct-server address (e.g. `ams.konstruct.cc:443`)
- `LISTEN_PORT` — public listen port (default: 9894 — avoid 443/9443, on DPI watch-lists)
- `TLS_SNI_HOST` — SNI hostname for domain-fronting (match VPS provider region)

## Build (without Docker)

```bash
cargo build --release
# binary: target/release/construct-relay
```

---

## Key conventions

- Recommended VPS: Hetzner Finland or Germany — avoid Yandex Cloud (RU DPI blocks it)
- Avoid ports 443 and 9443 — both are on DPI watch-lists
- `TLS_SNI_HOST` should match the VPS provider's region CDN hostname for convincing probe resistance

---
---

## Shared Construct Docs Workflow

These instructions apply to GitHub Copilot, Codex, OpenCode, and similar coding agents.

### Division of labour — read this first

| Role | Tool | Responsibility |
|------|------|----------------|
| **Coding agent** (you) | Copilot / Codex | Write code + drop raw session notes into `wiki/sessions/` and `wiki/decisions/`. That is all. |
| **Wiki pipeline** | `obsidian-llm-wiki-local` (olw) | Reads `raw/`, synthesizes concepts, creates/updates wiki articles, generates cross-links. |
| **Developer** | Human + Obsidian | Reviews wiki draft articles, approves/rejects. Curates `raw/`. |

**Your job is code.** olw handles article synthesis. Write plain-markdown session notes; let the pipeline do the rest.

### Shared knowledge base

- Vault: `/Users/maximeliseyev/Code/constrcut-docs`
- `raw/` — source corpus. Do **not** rewrite or reorganize.
- `wiki/` — canonical curated knowledge base. **Read** from here before architectural work.
- `wiki/.drafts/` — **reserved for olw**. Never write here manually.
- `wiki/sessions/` — where coding agents write session notes.
- `wiki/decisions/` — where coding agents write long-lived decision records.

### Where to save durable reasoning

After any session involving architectural changes, design decisions, API changes, or non-obvious implementation choices:

1. **Always** create or update `wiki/sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `# Why` — reasoning, alternatives considered, why rejected. Most important section.
3. If the decision constrains future work, also create `wiki/decisions/<topic>.md`.
4. Session notes: plain markdown, **no YAML frontmatter, no `[[wikilinks]]`** — olw adds those.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `wiki/log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`

