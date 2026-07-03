# Nexus Controller

A **central fleet console** for [Nexus Dashboard](https://github.com/brainchillz/NexusStationDashboard)
nodes. Enroll your single-host Nexus dashboards as "nodes," then monitor and
control the whole fleet from one pane of glass — over each node's existing
token-authed REST API.

The per-node dashboards keep working standalone; the controller is a console on
top of them, not a replacement.

> **Unprivileged by design.** The controller needs **no root, no sudo, no
> shell-outs** — it only ever speaks HTTPS to nodes. All privileged work stays on
> the node, behind that node's own auth + RBAC + audit. That keeps the
> controller's own attack surface tiny.

---

## What it does

- **Enroll** nodes with a URL + API token, with a connection test that captures
  the node's TLS cert fingerprint, role, version, and capabilities.
- **Virtualization hosts too** — enroll **Proxmox VE, VMware vCenter, or
  standalone ESXi** hosts (username/password) right alongside Nexus nodes. Their
  row shows host count, running/total **VMs & containers**, CPU/RAM, and
  datastore usage; **Open console ▸** deep-links to the native web UI. Slow
  hypervisor APIs are polled in the background so they never stall the fleet view.
- **NAS appliances too** — enroll **TrueNAS (SCALE / CORE)** with a read-only
  **API key**. The row shows pool health (✓ / ⚠ degraded), disk count, and
  capacity/CPU/memory, and its status dot goes amber on a degraded pool or an
  active alert. Read-only calls over the **JSON-RPC 2.0 WebSocket API**, polled in
  the background like the hypervisors. (Unraid and Synology are next.)
- **Fleet Overview** — hosts as compact horizontal rows **grouped by type**
  (Storage / Virtualization / AI / General): each row shows reachability, the
  reachable IP, CPU/mem/storage mini-bars, and type-specific chips (ZFS/shares/
  disks, VM & container counts, or **llama-server health + model + tok/s**).
- **Fleet-wide views** — every **alert** across the fleet, **storage** totals,
  and a **services matrix** (node × service status).
- **Control at scale** — start / stop / restart / enable / disable services on a
  node, view its logs, or run a **fleet-wide action** ("restart `smbd`
  everywhere") with per-node success/failure reporting.
- **Drill-in** — "Open dashboard ▸" opens a node's *own* dashboard SPA **through**
  the controller; the node's token stays server-side, and every action is audited
  on the controller in addition to the node.
- **Graceful degradation** — a slow or unreachable node never blocks the fleet
  view; results are briefly cached so auto-refresh doesn't hammer nodes.

## Architecture

```
   Browser ──HTTPS──▶  Nexus Controller  ──bearer token + cert-pinned TLS──▶  Node A /api/*
   (operator)          (Flask + SPA,      ──(parallel fan-out, per-node    ─▶  Node B /api/*
                        NO sudo)             timeout, brief cache)          ─▶  Node C /api/*
```

The controller is a **node registry** + a **fan-out aggregator** + an **action
reverse-proxy**. Nodes never call back — communication is pull-only, so the
controller's own IP can change without breaking anything (see *Networking*).

## Requirements

- **Controller host:** Linux with `python3` + `python3-venv`, systemd, and
  network reach to your nodes. ~40 MB disk, ~40 MB RAM, near-zero CPU.
- **Nodes:** Nexus Dashboard **v1.0.0+** (needs `/api/version` and token-aware
  `/api/me`, returning `role` + `version` + `capabilities`). Older nodes will
  reject enrollment with a 401 — upgrade the node first.
- An **API token** from each node (Nexus Dashboard → System → Users & Tokens). A
  **readonly** token is enough to monitor; an **admin** token is required to
  control the node or drill in with write access.

## Install

Run from the repo directory, as root:

```bash
sudo ./install.sh
```

This creates a dedicated unprivileged `nexuscontroller` user, installs to
`/opt/nexus-controller`, sets up a venv, writes a hardened systemd unit, and
starts the service on HTTPS `:9443` (self-signed cert auto-generated).

Set a known admin password up front (otherwise one is generated and printed to
the journal):

```bash
sudo CONTROLLER_ADMIN_PASSWORD='choose-a-strong-one' ./install.sh
```

**Configuration** (environment variables):

| Variable | Default | Meaning |
|----------|---------|---------|
| `CONTROLLER_DIR` | `/opt/nexus-controller` | Install directory |
| `CONTROLLER_USER` | `nexuscontroller` | Service user |
| `CONTROLLER_SERVICE` | `nexus-controller` | systemd unit name |
| `CONTROLLER_PORT` | `9443` | Listen port |
| `CONTROLLER_TLS` | `1` | `1` = HTTPS, `0` = HTTP (e.g. behind a TLS proxy) |
| `CONTROLLER_ADMIN_PASSWORD` | *(random)* | Seed the admin password |

After install, browse to `https://<host>:9443` and log in as `admin`. Get the
generated password with:

```bash
journalctl -u nexus-controller | grep -A2 'created initial admin account'
```

Reset it anytime:

```bash
sudo -u nexuscontroller /opt/nexus-controller/venv/bin/python \
  /opt/nexus-controller/app.py set-password admin
```

## TLS certificate

The controller serves HTTPS with a self-signed certificate generated on first
start (using the `cryptography` lib — no `openssl` binary required). Replace it
with a real certificate at any time; the key is validated against the cert before
install, and the service must be **restarted to apply**:

- **In the UI** — log in as admin → **🔒 Cert** → paste your certificate + key
  (PEM) → *Install certificate*, then restart the service. (You can also
  regenerate the self-signed cert here.)
- **CLI** — ideal for Let's Encrypt renewal hooks or `docker exec`:
  ```bash
  sudo -u nexuscontroller /opt/nexus-controller/venv/bin/python \
    /opt/nexus-controller/app.py install-cert /etc/letsencrypt/live/HOST/fullchain.pem \
                                               /etc/letsencrypt/live/HOST/privkey.pem
  sudo systemctl restart nexus-controller
  ```
  `app.py cert-info` prints the current cert's subject / issuer / expiry.

Or run HTTP-only (`CONTROLLER_TLS=0`) behind a reverse proxy that terminates TLS.

## Docker

The controller containerizes cleanly (it has no host dependencies — no root, no
sudo, no external binaries). A `Dockerfile` + `docker-compose.yml` are included.

```bash
# from a checkout on the Docker host:
echo "CONTROLLER_BIND_IP=192.168.1.10"        >  .env   # host IP to expose on (optional)
echo "CONTROLLER_ADMIN_PASSWORD=choose-one"   >> .env   # first run only
docker compose up -d --build
```

- State persists in the **`./data`** bind mount (`CONTROLLER_DATA_DIR=/data`):
  the encrypted registry, credentials, audit log, and TLS cert. Back it up by
  copying that directory.
- Runs as a **non-root** user (uid 10001) with a healthcheck on the SPA root.
- **Bind to one interface:** set `CONTROLLER_BIND_IP` to publish HTTPS only on a
  specific host IP (default `0.0.0.0`).
- **Upgrade:** `git pull && docker compose up -d --build` — `./data` survives.
- **Migrating an existing install:** copy the source controller's
  `controller-auth.json` **and** `nodes.json` into `./data` (keep them together —
  the Fernet key in the auth file decrypts the node tokens), `chown 10001:10001
  data -R`, then `docker compose up -d`.
- TLS: self-signed by default (swap a real cert via the Cert UI/CLI — see *TLS
  certificate*), or set `CONTROLLER_TLS=0` to run HTTP behind a reverse proxy.

## Upgrade

`install.sh` is **idempotent** — re-run it from a fresh checkout to upgrade in
place. It refreshes the code and dependencies, rewrites the unit, and restarts,
while **preserving** `nodes.json` (the encrypted registry) and
`controller-auth.json` (credentials).

## Uninstall

```bash
sudo ./uninstall.sh          # remove service + dir; back up registry/auth/audit
                             # to /var/backups, keep the service user
sudo ./uninstall.sh --purge  # remove everything incl. the user and all state
```

The default backs up your enrolled-node tokens before deleting, so you don't lose
the registry by accident.

## Using it

### Enroll a node

**Add Host** → pick a **host type**, then fill the fields it shows. **Test
connection** validates + pins the host's cert; **Enroll** saves it. Secrets
(API tokens/keys *and* virtualization passwords) are encrypted at rest and never
returned through the API.

- **Nexus Dashboard node** — name, base URL (e.g. `https://192.168.1.10:8443`),
  API token, optional tags.
- **Proxmox VE** — base URL (`https://host:8006`), username (`root@pam`),
  password, TLS-verify toggle.
- **VMware vCenter / ESXi** — base URL (`https://host`), username
  (`administrator@vsphere.local` for vCenter, `root` for ESXi), password.
- **TrueNAS (SCALE / CORE)** — base URL (`https://host`), an **API key**, and a
  TLS-verify toggle. Create the key under a user with the **Read Only Admin**
  role (Credentials → Users → *Roles*) — a key without it authenticates but
  gets `403` on every call.

Virtualization and NAS hosts are polled in the background (default every 60s);
their row shows the last poll. **Open console ▸** / **Open UI ▸** links to the
host's own web UI.

### Edit a host

The **✎** button on a host row opens an editor — change the **display name**,
**base URL**, **tags**, **type**, or install a **new credential** (token / API
key / password; leave blank to keep the current one). No need to delete and
re-enroll.

Changing the **base URL** or a **credential** re-probes the node: it re-validates
reachability, **re-pins the new certificate**, and refreshes the role / version /
capabilities. A failed probe leaves the node unchanged. (API:
`PUT /api/nodes/<id>` with any of `name`, `tags`, `type`, `base_url`, `token`,
`username`, `password`.)

### Host types (Storage / AI / Mixed / Virtualization)

Each host is auto-classified from what it actually runs:

- **Storage** — serving ZFS / SMB / NFS / iSCSI (a **TrueNAS** appliance
  classifies here too).
- **AI** — running `llama.cpp` with a model loaded.
- **Mixed** — a meaningful amount of both.
- **Virtualization** — a Proxmox / vCenter / ESXi host.

The suggestion (`type_auto`) refreshes each poll. In the Edit dialog the **Type**
dropdown lets you keep **Auto (follow detection)** or pin a manual override
(Storage / AI / Mixed / Unknown). Picking **Auto** un-pins it again.

### Roles

Controller logins have a role: **admin** (manage nodes + full control),
**operator** (control, no enroll/remove), **viewer** (read-only). Write controls
are also gated by the *node's* enrolled token role — a node enrolled with a
readonly token shows as read-only.

## Security model

- **No privilege:** the service runs as an unprivileged user with no sudo;
  privileged work happens on the node behind its own auth.
- **Tokens encrypted at rest** (Fernet) in `nodes.json`; never returned via the
  API.
- **Per-node TLS cert pinning** (trust-on-first-use): the fingerprint is captured
  at enroll and checked on every call; a changed cert fails closed.
- **RBAC** enforced centrally (viewer can't write; enroll/remove is admin-only).
- **Audit log** of every controller-side mutation (operator, node, method, path,
  result) — in addition to the node's own audit.

## Files & state

All under the install dir (`/opt/nexus-controller`), mode `0600`, gitignored:

| File | Contents |
|------|----------|
| `controller-auth.json` | secret key, Fernet key, controller users |
| `nodes.json` | the node registry (encrypted tokens, cert fingerprints) |
| `audit.log` | append-only controller audit trail |
| `certs/` | auto-generated self-signed TLS cert |

## Networking

Communication is **controller → node** only; nodes never call back and store no
reference to the controller. So you can change the **controller's** IP freely —
nothing to re-enroll — as long as it can still reach the node IPs/ports. (Node IP
changes do matter: a node's `base_url` is stored in the registry; update it with
`PUT /api/nodes/<id>` or re-enroll.)

## API reference

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/login`, `/api/logout` | session auth |
| `GET` | `/api/me` | current user + role |
| `POST` | `/api/account/password` | change own password |
| `GET` | `/api/nodes` | list nodes (tokens stripped) |
| `POST` | `/api/nodes` | enroll (admin) |
| `POST` | `/api/nodes/test` | test-connection without enrolling |
| `PUT` | `/api/nodes/<id>` | update name/tags/type/token (admin) |
| `DELETE` | `/api/nodes/<id>` | un-enroll (admin) |
| `GET` | `/api/fleet/summary` | fan-out rollup (`?fresh=1` bypasses cache) |
| `POST` | `/api/fleet/action` | fleet-wide service action |
| `*` | `/api/nodes/<id>/proxy/<path>` | reverse-proxy to a node's `/api/<path>` |
| `GET` | `/nodes/<id>/` | drill-in: the node's SPA, retargeted |
| `GET` | `/api/tls/info` | current serving certificate metadata |
| `POST` | `/api/tls/regenerate` | regenerate the self-signed cert (admin) |
| `POST` | `/api/tls/cert` | install a supplied cert + key (admin) |

## Development

```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements-dev.txt
CONTROLLER_TLS=0 ./venv/bin/python app.py     # HTTP on :9080 for local dev
./venv/bin/python -m pytest tests/ -q
```

Conventions mirror the node app: one Flask app + vanilla-JS SPA, no build step,
atomic JSON writes, `escapeHtml`/`jsArg`, central RBAC guard.

## Status

Implemented: enrollment + in-UI editing + encrypted registry, cert-pinning
`NodeClient`, cached fan-out fleet view, alerts/storage/services aggregation,
fleet-wide service actions, drill-in reverse-proxy, AI/llama status, node-type
classification, **Proxmox / VMware (vCenter + ESXi) virtualization adapters**,
**a TrueNAS NAS adapter (read-only JSON-RPC 2.0 WebSocket, API-key auth)**, TLS certificate
management, and both systemd (`install.sh`) and Docker (`docker-compose.yml`)
deployment.

Roadmap: **more NAS adapters (Unraid, Synology)**, virtualization write actions
(start/stop VM), per-node/tag RBAC scoping, cert-change & version-skew warnings in
the UI, controller user-management UI, and fan-out rate-limiting for large fleets.
