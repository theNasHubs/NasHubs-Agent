# Agent 2.2: app folders, remote access and first-run setup

## App folders (`{{APP_DIR}}`)

Each mini-app keeps its data in exactly one folder of the NAS `docker` share:

```
/volumeX/docker/
├── nashubs-agent/data/   agent identity, devices, compose artifacts (DSM installer)
├── jellyfin/config …
└── immich/library, immich/postgres …
```

The agent renders `{{APP_DIR}}` as `<AppsDir>/<id>`. `AppsDir` is derived from
the data directory (`/volumeX/docker/nashubs-agent/data` → `/volumeX/docker`;
legacy `/volumeX/docker` → itself) or set with `NASHUBS_APPS_DIR=/volumeX/docker`.
A deploy that still contains an unrendered `{{UPPER_CASE}}` variable is
refused (`UNRENDERED_PLACEHOLDER`). Existing deployments are never moved.

`GET /shares` (viewer+) lists the top-level folders of every `/volumeN` (system
`@…`/`#…` folders skipped) and returns `appsDir`, so the app offers real shared
folders for media. Media folders are mounted read-only at the same path, so
Jellyfin/Immich show `/volume1/video` exactly as DSM does.

## Remote status

`GET /remote-status` now reports, per app: `lanURL`, `tailscaleURL`,
`publicURL` (Cloudflare hostname routed to the app port), `appDir` and `mounts`
(NAS path ↔ container path). The LAN address comes from `NASHUBS_LAN_IP`
(written by the DSM installer) or the private address the client used; a
container-internal address is never reported. Tailscale status is parsed from
JSON (`Self.TailscaleIPs`, `Self.DNSName`, `BackendState`).

## Tailscale and Funnel

Tailscale runs as the `tailscale` mini-app (`nashubs-tailscale`, host network).

- `GET /remote/tailscale` (admin): login state, tailnet IP and MagicDNS name;
  while logged out an `authURL` (`https://login.tailscale.com/a/…`) the app
  opens — no auth key is stored in the compose file.
- `GET /remote/funnel` (viewer) / `POST /remote/funnel {"enable":bool}` (owner):
  publishes only the agent at `https://<magicdns>:10000` →
  `https+insecure://localhost:<agent port>`. Every request through it is still
  Ed25519-signed and role-checked; unauthenticated callers only reach `/ping`
  and invitation redemption. If Funnel is not allowed in the tailnet the
  response is `FUNNEL_NOT_ALLOWED` with the admin-console link.

Phones need no Tailscale app for agent access through Funnel. Through Funnel
the TLS certificate is the tailnet's public certificate; clients verify the
backend agent identity (`agentId` from `/ping`) against the pinned fingerprint.

## Cloudflare

`POST /configure-cloudflare` accepts `"mode":"merge"` with `ingress` upserts and
`remove` hostnames, keeping other apps' rules. The default (`replace`) is kept
for older clients. `GET /configure-cloudflare` parses the config as YAML.

## First-run setup

- `POST /apps/jellyfin/setup` (admin): `{port, username, password, language,
  country, libraries:[{name,type,paths}]}` → startup wizard + libraries.
- `POST /apps/immich/setup` (admin): `{port, email, password, name,
  libraries:[{name,paths}]}` → admin sign-up, login, external libraries + scan.

Both refuse a server that is already set up (`ALREADY_SET_UP`) and accept only
`/volumeN/<share>/…` paths. The agent reaches the app through the bridge
gateway (the NAS) and stores no credential.

## Upgrade through the DSM installer

`dsm-bootstrap` with `"upgrade": true` recreates an existing `nashubs-agent`
that runs a different image, keeping its env (trusted keys, data dir), binds and
published ports. The old container is renamed and kept until the new one
reports its identity, then removed; on failure it is restored and started.
Without `upgrade` an existing agent is never touched.
