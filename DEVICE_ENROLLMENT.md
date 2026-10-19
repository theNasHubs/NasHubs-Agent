# Install once, enroll devices live

The Agent runs on the NAS. Android/iOS clients sign requests with their own
Ed25519 identity. NAS device roles (`owner`, `admin`, `viewer`) are independent
of Firebase accounts and NasHubs Pro entitlements.

## Existing devices

Keep the persisted data directory, `agent.crt`, `agent.key`, and `devices.json`
when updating the image. `POST /pair` remains compatible with the existing iOS
signature format and returns the same device identity without a pairing secret
for already enrolled keys. A damaged existing TLS identity now stops startup;
restore it from backup instead of silently rotating every client's pin.

## Add another phone

1. An enrolled owner calls signed `POST /devices/invitations` with
   `{"role":"admin"}` or `{"role":"viewer"}`.
2. The response contains `code`, `expiresAt`, `role`, and `certFingerprint`.
   Share the code privately and independently verify the Agent's TLS identity.
3. The new phone signs `POST /devices/enroll` with
   `{"code":"<invitation>","label":"My phone"}` using its own new key.
4. The Agent records the device while running. No image pull, container restart,
   DSM session, Google account, or change to other devices is required.
5. Subsequent connections use signed `/pair` with an empty secret.

Invitations expire after ten minutes, contain 192 random bits, and are stored
only as SHA-256 hashes. Consumption is persisted before granting access. A code
cannot enroll another key after a restart. Revocation of the issuing owner
invalidates their outstanding invitations. Public endpoints cannot issue owner
invitations. A revoked key cannot re-enroll itself with a different invitation.

## First owner and SSH recovery

An administrator who already controls the NAS through SSH/sudo can run:

```sh
sudo docker exec nashubs-agent nashubs-agent invite --role owner
```

This is an explicit OS-administrator recovery action. Use `--role admin` or
`--role viewer` for ordinary invitations. The CLI uses the live Agent's local
Unix socket (`<data-dir>/control.sock`, mode 0600); it does not rewrite a running
Agent's store or retain a permanent recovery token. Keep the output private.

Initial legacy bootstrap using an env-trusted public key and pairing secret
still works. Its consumption is persisted per trusted key across restarts, preserving multiple legacy bootstrap devices. Updating an
old Agent to this protocol is a separate one-time maintenance operation.

## Discovery and NAS resources

Unsigned `GET /ping` advertises `agentId` (stable TLS fingerprint) and
`capabilities: ["device-enrollment-v1", "resources-v1"]`. Discovery proves
availability, not ownership; clients must still verify TLS and authenticate.

Signed viewer+ `GET /resources` returns CPU utilization sampled over 250 ms and
host memory from Linux procfs. `GET /volumes` returns mounted `/volumeN` capacity.
Neither endpoint uses Synology APIs. Mini-app deploy/state/health/logs/rollback/
remove already operate through Docker, independently of a DSM login.

`NASHUBS_AUTO_PROXY=false` disables automatic DSM nginx changes on startup.
The default remains `true` for compatibility. Manual proxy/tunnel actions are
separate privileged operations and are not required for direct Agent access.

## Migration limits

This protocol does not turn DSM File Station, Synology Photos or DSM user/package
administration into native Agent APIs. Those Android modules retain their DSM
integration. Legacy iOS installers must not be rerun to add a phone; they need
a separate client migration to invitations. Existing enrolled iOS clients retain
their signing protocol and keys.

## Validation

Run `go vet ./...` and `go test -race -count=1 ./...` on Linux. Tests cover
legacy signing/reconnect, persistent one-use invitations, concurrent redemption,
roles, revocation, corrupt storage, disk failure, root socket permissions, host
resources, and stable TLS identity. CI tests PRs without publishing images.

## Isolated preview image

Pushes to `codex/live-device-enrollment` run the pinned publish workflow after
Go vet and race tests pass. The multi-architecture image is published to
`ghcr.io/thenashubs/nashubs-agent:sha-<full commit SHA>`. The shared `latest`
tag is emitted only on the default branch. Android's preview installer selects
an exact commit tag rather than silently upgrading existing installations.
Publishing source to Git does not itself publish a Docker image; the workflow
and an anonymous registry manifest check must both succeed before installation.
