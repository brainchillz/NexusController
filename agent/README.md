# Nexus Agent

An **ultra-light, read-only metrics endpoint** for machines that don't warrant
a full [Nexus Dashboard](https://github.com/brainchillz/NexusDashboard-Modular)
— drop it on any Linux or Windows box and enroll the machine in the
[Nexus Controller](../README.md) as host type **Nexus Agent**.

It reports exactly four things: **up/down** (implicit — the endpoint answers),
**CPU %**, **memory**, and **mounted-storage utilization** (per filesystem on
Linux, per fixed drive on Windows). Both implementations speak the **same API
contract**, so the controller doesn't care which OS is behind an enrollment.

## Security model

- **Read-only by construction** — there are no write endpoints at all. The
  agent reads OS counters and nothing else.
- **No dependencies** — Linux: one stdlib-only Python file (any distro's
  system `python3`). Windows: one PowerShell 5.1 script (preinstalled since
  Server 2016). Nothing is downloaded at install or run time.
- **Bearer-token auth** — a random token is minted at install (`na_…`) and
  stored `0600` (Linux) / admin-only ACL (Windows). Only `GET /` (a tiny
  identity blob used by healthchecks) answers without it.
- **HTTPS with a self-signed certificate** — the controller captures the
  cert fingerprint at enroll (trust-on-first-use) and verifies it
  **in-handshake on every poll**; a changed cert fails closed.
- **Least privilege** — Linux: a dedicated no-login `nexusagent` user under a
  hardened systemd unit (`ProtectSystem=strict`, empty capability set,
  `NoNewPrivileges`). Windows: runs as **NETWORK SERVICE**; TLS terminates in
  `http.sys` via a machine-level binding, so the agent process never has
  access to the private key.

---

## Linux install

**Requirements:** `python3` (3.6+), `systemd`, `openssl` (used once, at
install, to generate the certificate), root for the installer.

From this directory (a git checkout, or just copy `nexus_agent.py` +
`install.sh` to the target machine):

```bash
sudo ./install.sh
```

That's the whole install. It is **idempotent** — re-run it any time to
upgrade in place (the token and pinned certificate are preserved). What it
does:

1. Creates the dedicated no-login system user `nexusagent`.
2. Installs the agent to `/opt/nexus-agent` with state in
   `/opt/nexus-agent/data` (mode `700`).
3. Generates a self-signed TLS certificate (once — never overwritten,
   because the controller pins it).
4. Writes and starts the hardened `nexus-agent` systemd unit (enabled at
   boot, auto-restart on failure).
5. Prints the **Base URL and token to enroll with**:

```
Nexus Agent is running.
  Enroll in the controller as host type 'Nexus Agent':
    Base URL:  https://192.168.1.88:9143
    Token:     na_iLsm...
```

**Options** (environment variables for `install.sh`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENT_PORT` | `9143` | Listen port |
| `AGENT_DIR` | `/opt/nexus-agent` | Install directory |
| `AGENT_USER` | `nexusagent` | Service user |
| `AGENT_SERVICE` | `nexus-agent` | systemd unit name |

**Manage it:**

```bash
systemctl status nexus-agent          # state
journalctl -u nexus-agent             # logs (incl. the minted token line)
cat /opt/nexus-agent/data/token       # the enrollment token (root)
sudo ./install.sh --uninstall         # remove the service (files/token kept)
sudo rm -rf /opt/nexus-agent          # ... and the files, if you're done
```

The agent itself also honors `AGENT_PORT`, `AGENT_BIND`, `AGENT_DATA_DIR`,
`AGENT_SAMPLE_INTERVAL`, and `AGENT_TLS=0` (plain HTTP for use behind a
TLS-terminating reverse proxy — enroll with the proxy's `https://` URL, or the
`http://` URL knowing there is then no transport security).

---

## Windows install

**Requirements:** Windows Server 2016+ or Windows 10+ (PowerShell 5.1 is
preinstalled), an **elevated** PowerShell for the installer.

Copy `nexus_agent.ps1` + `install.ps1` to the machine (any folder), then in an
elevated PowerShell:

```powershell
Set-Location C:\path\to\files
.\install.ps1                # -> C:\Program Files\NexusAgent on :9143
.\install.ps1 -Port 9200     # custom port
```

Idempotent like the Linux installer — re-run to upgrade (token + certificate
binding preserved). What it does:

1. Installs the agent to `C:\Program Files\NexusAgent`, state in
   `C:\ProgramData\NexusAgent` (ACL: SYSTEM/Administrators full, NETWORK
   SERVICE read).
2. Generates a self-signed certificate and binds it to the port **in
   http.sys** (`netsh http add sslcert`) with a URL ACL for NETWORK SERVICE —
   this is why the agent needs no privileged account.
3. Mints the token, opens an inbound firewall rule for the port.
4. Registers and starts the **`NexusAgent` Scheduled Task** (at startup, runs
   as NETWORK SERVICE, no time limit, auto-restart every minute on failure).
   A task rather than a service is deliberate: a `.ps1` cannot be a native
   SCM service without a third-party wrapper, and the agent ships with zero
   dependencies.
5. Prints the **Base URL and token to enroll with** (same format as Linux).

**Manage it:**

```powershell
Get-ScheduledTask NexusAgent                    # state
Start-ScheduledTask NexusAgent                  # (re)start
Get-Content C:\ProgramData\NexusAgent\token     # the enrollment token
.\install.ps1 -Uninstall                        # remove task/firewall/TLS binding
Remove-Item -Recurse 'C:\Program Files\NexusAgent', C:\ProgramData\NexusAgent
```

---

## Enrolling in the controller

Controller UI → **+ Add Host** → host type **Nexus Agent** → paste the Base
URL and Token the installer printed → **Test connection** (shows hostname, OS,
and filesystem count) → **Enroll**.

The row shows the up/down dot, CPU/Mem/Store meters, an OS chip, a Mounts chip
(hover lists each filesystem/drive with its usage %), load (Linux only),
uptime, and the agent version — agent upgrades are visible fleet-wide via the
version column. The token is encrypted at rest in the controller's registry
and never returned by its API.

## API contract (what the controller consumes)

| Method | Path | Auth | Returns |
|--------|------|------|---------|
| `GET` | `/` | none | `{"app":"nexus-agent","version":…}` (healthcheck/identity) |
| `GET` | `/api/v1/metrics` | `Authorization: Bearer <token>` | the full payload |

Payload (both platforms; `load1` is `null` on Windows):

```json
{
  "agent": "nexus-agent", "version": "1.0.0", "platform": "linux|windows",
  "hostname": "…", "os": "…", "kernel": "…", "arch": "…",
  "uptime_seconds": 12345, "sampled_at": 1783208020.0,
  "cpu":    {"percent": 6.0, "count": 4, "load1": 0.22},
  "memory": {"total": 0, "available": 0, "used": 0, "percent": 0.0},
  "mounts": [{"device": "…", "mountpoint": "/", "fstype": "ext4",
              "total": 0, "used": 0, "free": 0, "percent": 0.0}]
}
```

Implementation notes: on Linux, CPU % comes from `/proc/stat` deltas computed
by a background sampler, which also refreshes the mount table — so a hung
network mount can never block a metrics request (it just serves the last
snapshot). Pseudo-filesystems (tmpfs/overlay/squashfs/…), `/snap`, and Docker
overlay mounts are filtered out, and bind mounts are deduplicated. On Windows,
CPU is the average `Win32_Processor` load, memory comes from
`Win32_OperatingSystem`, and mounts are fixed drives (`DriveType=3`) only.
