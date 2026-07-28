# Nasdeck Agent

A tiny always-on service that runs **on the NAS** and executes `docker compose`
on behalf of the Nasdeck iOS app. The app never holds the DSM admin password for
deploys — it sends signed commands over a pinned-TLS channel, and the agent runs
compose locally.

- **Language:** Go (static binary, multi-arch `linux/arm64,amd64`).
- **Auth:** Ed25519 signed requests (`X-Nasdeck-*` headers) + replay protection.
- **Transport:** HTTPS with a self-signed cert the app **pins by SHA-256 fingerprint**.

## Build & run

```bash
make build            # native binary → ./bin/nasdeck-agent
make docker           # host-arch image
make multiarch        # linux/arm64,linux/amd64 → push to $IMAGE
make test             # unit + signature interop + integration tests
```

### Run on the NAS (what the iOS bootstrap automates)

```bash
docker run -d --name nasdeck-agent --restart unless-stopped \
  -p 8443:8443 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /volume1/docker:/data \
  -e NASDECK_TRUSTED_PUBKEY=<base64 app pubkey> \
  -e NASDECK_PAIRING_SECRET=<one-time secret> \
  ghcr.io/phuctu1901/nasdeck-agent:latest
```

> The `docker compose` CLI parses the compose file in its own process, so the
> `-f` path must be the path the CLI sees — which is `NASDECK_DATA_DIR` (`/data`,
> the mount above). `NASDECK_HOST_DATA_DIR` defaults to `NASDECK_DATA_DIR`, so you
> don't set it for the normal container case. Override only if the agent writes
> files and the compose CLI see different mount namespaces.

On boot the agent prints `NASDECK_CERT_FINGERPRINT=<base64 sha256(der)>`, which the
app reads from the Task Scheduler output and pins for TLS.

## Environment

| Var | Default | Purpose |
|-----|---------|---------|
| `NASDECK_PORT` | `8443` | listen port |
| `NASDECK_DATA_DIR` | `/data` | container path where compose artifacts are written (mount the NAS docker share here) |
| `NASDECK_HOST_DATA_DIR` | `= NASDECK_DATA_DIR` | path the compose CLI sees for `-f` (defaults to DATA_DIR; override only for split mounts) |
| `NASDECK_TRUSTED_PUBKEY` | — | comma-separated base64 Ed25519 public keys allowed to command the agent |
| `NASDECK_PAIRING_SECRET` | — | one-time secret confirmed via `POST /pair` |
| `NASDECK_VERSION` | `0.1.0` | reported version |

## HTTP API

All routes except `/ping` require a valid Ed25519 signature (see scheme below).

| Method | Path | Body | Returns |
|--------|------|------|---------|
| GET  | `/ping` | — | `{ok, version}` (unsigned liveness) |
| POST | `/pair` | `{pairingSecret, label?}` | `{ok, certFingerprint, version, keyId}` |
| POST | `/deploy` | `{id, compose, version?}` | `{ok, version, hostPath, output}` |
| GET  | `/logs/{id}?follow=1` | — | SSE stream `data: <line>` |
| GET  | `/health/{id}` | — | `{id, state, detail, path}` |
| POST | `/rollback/{id}` | — | `{ok, version, previous, output}` |

`id` must match `^[A-Za-z0-9_-]+$`. Each deploy is an immutable artifact at
`<data>/<id>/v<sha256[:6]>/docker-compose.yml`; rollback repoints `current`.

## Signature scheme (must match iOS `AgentTransport`)

```
X-Nasdeck-Keyid: base64( 32-byte Ed25519 public key )
X-Nasdeck-Ts:    decimal unix seconds          (±60s window)
X-Nasdeck-Nonce: base64( 16 random bytes )     (replay-protected 120s)
X-Nasdeck-Sig:   base64( 64-byte signature )

sigBase = METHOD + "\n" + PATH + "\n" + ts + "\n" + nonce + "\n" + hex(sha256(body))
```

Ed25519 keys are raw 32-byte; iOS CryptoKit `Curve25519.Signing` and Go
`crypto/ed25519` are interoperable (deterministic, RFC 8032). See
`interop_test.go` for the canonical vectors the iOS test reproduces.
