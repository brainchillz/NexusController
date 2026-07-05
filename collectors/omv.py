"""OpenMediaVault collector — the OMV JSON-RPC API (`/rpc.php`), read-only.

Auth: ``Session.login`` with the **web-UI admin credentials** (NOT the box's
system/SSH password — OMV's UI login is separate) → PHP session cookie,
cached per host between polls and refreshed on "Session not authenticated".

Calls (all reads):
  * ``System.getInformation``           hostname, OMV version, CPU %, memory
  * ``FileSystemMgmt.getList``          the OMV-managed data filesystems → pools
  * ``MdMgmt.getList``                  mdadm arrays (state → pool health);
                                        tolerated missing (plugin/OMV version)
  * ``Smart.getList``                   disks + SMART overallstatus

`build_metrics` emits the SAME normalized dict as the TrueNAS/Synology/ZimaOS/
Unraid collectors → `build_nas_envelope` + the whole NAS UI are reused.

Shape gotchas (seen live on OMV 8.5 "pinas"): filesystem `size`/`available`
are byte STRINGS but `used` is a human string ("2.04 MiB") — usage is computed
as size-available; `memTotal`/`memUsed` are byte strings; `cpuUtilization` is
a percent while `memUtilization` is a fraction (we compute from bytes
instead); SMART `overallstatus` is BAD_STATUS on devices that simply can't do
SMART (USB sticks), so only `monitor`-enabled disks raise alerts.
"""
import threading

import requests

TIMEOUT = (5, 20)

# md array states that do NOT indicate a problem.
_MD_OK = {'clean', 'active', 'active, checking', 'clean, checking'}

_sessions = {}   # base URL -> requests.Session
_lock = threading.Lock()


class OmvError(Exception):
    pass


def _rpc(s, base, service, method, params=None):
    try:
        r = s.post(base + '/rpc.php',
                   json={'service': service, 'method': method, 'params': params},
                   timeout=TIMEOUT)
    except requests.RequestException as e:
        raise OmvError(f'{service}.{method}: {e}')
    try:
        doc = r.json()
    except ValueError:
        raise OmvError(f'{service}.{method}: non-JSON response (HTTP '
                       f'{r.status_code} — is this an OpenMediaVault URL?)')
    err = (doc.get('error') or {}).get('message')
    if err:
        if 'not authenticated' in err.lower():
            raise PermissionError(err)
        raise OmvError(f'{service}.{method}: {err}')
    return doc.get('response')


def _login(base, username, password, verify_ssl):
    s = requests.Session()
    s.verify = bool(verify_ssl)
    try:
        resp = _rpc(s, base, 'Session', 'login',
                    {'username': username, 'password': password})
    except PermissionError as e:
        raise OmvError(f'login: {e}')
    except OmvError as e:
        if 'Incorrect username or password' in str(e):
            raise OmvError('login failed: incorrect username or password '
                           "(note: OMV's WEB-UI password, not the SSH one)")
        raise
    role = ((resp or {}).get('permissions') or {}).get('role')
    if role != 'admin':
        raise OmvError(f'login ok but role is {role!r} — an admin-role web-UI '
                       'account is required (the RPC API is admin-gated)')
    return s


def _paged(s, base, service, method):
    r = _rpc(s, base, service, method,
             {'start': 0, 'limit': 500, 'sortfield': None, 'sortdir': None})
    return (r or {}).get('data') or []


def _collect(s, base):
    info = _rpc(s, base, 'System', 'getInformation') or {}
    filesystems = _paged(s, base, 'FileSystemMgmt', 'getList')
    try:
        raids = _paged(s, base, 'MdMgmt', 'getList')
    except OmvError:
        raids = []   # no mdadm plugin / older service name — fine
    try:
        smart = _paged(s, base, 'Smart', 'getList')
    except OmvError:
        smart = []
    return build_metrics(info, filesystems, raids, smart)


def collect_metrics(host, username, password, port=80, scheme='http',
                    verify_ssl=False):
    """One poll (cached session; re-login on expiry) → normalized NAS metric
    dict. Raises OmvError."""
    base = f'{scheme}://{host}:{port}'
    with _lock:
        s = _sessions.get(base)
    if s is not None:
        try:
            return _collect(s, base)
        except PermissionError:
            pass   # stale session — fall through to re-login
    s = _login(base, username, password, verify_ssl)
    try:
        metrics = _collect(s, base)
    except PermissionError as e:
        raise OmvError(f'authenticated but the RPC rejected the session: {e}')
    with _lock:
        _sessions[base] = s
    return metrics


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def build_metrics(info, filesystems, raids, smart):
    """Pure transform: OMV RPC payloads → the normalized NAS metric dict
    (same shape as collectors/truenas.build_metrics)."""
    info = info or {}
    filesystems = filesystems or []
    raids = raids or []
    smart = smart or []
    GB = 1024 ** 3

    # md arrays by device file — folded into the pool built on that device.
    md_by_dev = {}
    for r in raids:
        for dev in [r.get('devicefile')] + list(r.get('devicefiles') or []):
            if dev:
                md_by_dev[dev] = r

    size = used = 0.0
    pool_list, healthy, degraded, alerts = [], 0, 0, []
    for fs in filesystems:
        name = fs.get('label') or fs.get('devicename') or 'filesystem'
        ftotal = _num(fs.get('size'))
        favail = _num(fs.get('available'))
        fused = max(0.0, ftotal - favail)
        ok = fs.get('status', 1) == 1 and fs.get('mounted', True)
        status = fs.get('type') or 'filesystem'
        md = md_by_dev.get(fs.get('canonicaldevicefile') or fs.get('parentdevicefile'))
        if md:
            state = (md.get('state') or '').lower()
            level = md.get('level') or 'md'
            status = f'{level} {state}' if state else level
            if state and state not in _MD_OK:
                ok = False
                alerts.append(f'{name} ({md.get("devicefile")}): RAID state {md.get("state")}')
        if not ok and not any(name in a for a in alerts):
            alerts.append(f'{name}: not healthy (status {fs.get("status")}, '
                          f'mounted {fs.get("mounted")})')
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        size += ftotal
        used += fused
        pool_list.append({
            'name': name, 'status': status, 'healthy': ok,
            'size_gb': round(ftotal / GB, 1), 'used_gb': round(fused / GB, 1),
            'used_pct': round(fused / ftotal * 100, 1) if ftotal else None,
        })

    # Arrays with a problem but no mounted filesystem still deserve an alert.
    for r in raids:
        state = (r.get('state') or '').lower()
        if state and state not in _MD_OK and not any(str(r.get('devicefile')) in a for a in alerts):
            alerts.append(f'{r.get("devicefile")}: RAID state {r.get("state")}')

    # SMART: only monitored disks alert (unsupported devices — USB sticks —
    # report BAD_STATUS just because SMART can't be read).
    for d in smart:
        if d.get('monitor') and (d.get('overallstatus') or 'GOOD') != 'GOOD':
            alerts.append(f'disk {d.get("devicename")} ({d.get("model") or "?"}): '
                          f'SMART {d.get("overallstatus")}')

    mem_total = _num(info.get('memTotal'))
    mem_used = _num(info.get('memUsed'))
    cpu = info.get('cpuUtilization')
    parts = (info.get('version') or '').split()   # '8.5.0-3 (Synchrony)' → '8.5.0-3'
    version = parts[0] if parts else None

    return {
        'hostname': info.get('hostname'),
        'version': ('OMV ' + version) if version else None,
        'model': info.get('cpuModelName'),
        'uptime_seconds': int(_num(info.get('uptime'))) or None,
        'cpu_usage_percent': round(float(cpu), 1) if cpu is not None else None,
        'memory_total_gb': round(mem_total / GB, 1) if mem_total else None,
        'memory_used_gb': round(mem_used / GB, 1) if mem_total else None,
        'memory_usage_percent': (round(mem_used / mem_total * 100, 1)
                                 if mem_total else None),
        'storage_total_gb': size / GB,
        'storage_used_gb': used / GB,
        'storage_usage_percent': round(used / size * 100, 1) if size else None,
        'pool_count': len(pool_list),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(smart),
        'alert_count': len(alerts),
        'alerts': alerts[:10],
    }
