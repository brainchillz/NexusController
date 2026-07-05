"""ZimaOS collector — the ZimaOS (ZimaCube) HTTP API, read-only.

ZimaOS serves PLAIN HTTP on the LAN (no TLS listener), so there is no
certificate to pin — the adapter skips pinning for http:// base URLs and the
poller connects over http. Auth is a JWT from ``POST /v1/users/login`` (a
local ZimaOS account), sent RAW in the Authorization header (no "Bearer"
prefix). Tokens are short-lived; each poll logs in fresh. Calls (all reads):

  * ``POST /v1/users/login``            → data.token.access_token
  * ``GET  /v1/sys/utilization``        CPU % / temperature, memory
  * ``GET  /v2/local_storage/storages`` volumes ("storages": SYSTEM/RAIDn/SSD)
  * ``GET  /v2/local_storage/raid``     RAID arrays + member-disk health
  * ``GET  /v2/local_storage/disk``     physical disks (health, temperature)

`build_metrics` emits the SAME normalized dict as the TrueNAS/Synology
collectors, so `build_nas_envelope` and the whole NAS UI are reused — ZimaOS
"storages" appear as the envelope's pools.
"""
import requests

TIMEOUT = (5, 15)


class ZimaOSError(Exception):
    pass


def _get(session, base, path, token, what):
    try:
        r = session.get(base + path, headers={'Authorization': token},
                        timeout=TIMEOUT)
    except requests.RequestException as e:
        raise ZimaOSError(f'{what}: {e}')
    try:
        doc = r.json()
    except ValueError:
        raise ZimaOSError(f'{what}: non-JSON response (HTTP {r.status_code} — '
                          'is this a ZimaOS URL?)')
    if r.status_code != 200:
        msg = doc.get('message') if isinstance(doc, dict) else None
        raise ZimaOSError(f'{what}: {msg or ("HTTP %d" % r.status_code)}')
    # v1 + most v2 endpoints wrap the payload in {"data": …}; /v2/…/storages
    # returns the bare list (seen live on ZimaOS at 192.168.2.5).
    return doc.get('data') if isinstance(doc, dict) else doc


def collect_metrics(host, username, password, port=80, scheme='http',
                    verify_ssl=False):
    """Login, pull utilization/storages/raid/disks. Returns the normalized NAS
    metric dict (see build_metrics). Raises ZimaOSError."""
    base = f'{scheme}://{host}:{port}'
    s = requests.Session()
    s.verify = bool(verify_ssl)

    try:
        r = s.post(base + '/v1/users/login',
                   json={'username': username, 'password': password},
                   timeout=TIMEOUT)
    except requests.RequestException as e:
        raise ZimaOSError(f'login: {e}')
    try:
        doc = r.json()
    except ValueError:
        raise ZimaOSError(f'login: non-JSON response (HTTP {r.status_code} — '
                          'is this a ZimaOS URL?)')
    token = (((doc.get('data') or {}).get('token')) or {}).get('access_token')
    if r.status_code != 200 or not token:
        raise ZimaOSError('login failed: %s'
                          % (doc.get('message') or 'HTTP %d' % r.status_code))

    util = _get(s, base, '/v1/sys/utilization', token, 'utilization') or {}
    storages = _get(s, base, '/v2/local_storage/storages', token, 'storages') or []
    raids = _get(s, base, '/v2/local_storage/raid', token, 'raid info') or []
    disks = _get(s, base, '/v2/local_storage/disk', token, 'disk list') or []
    # (No logout endpoint — the JWT just expires.)
    return build_metrics(util, storages, raids, disks)


def build_metrics(util, storages, raids, disks):
    """Pure transform: ZimaOS API payloads → the normalized NAS metric dict
    (same shape as collectors/truenas.build_metrics)."""
    util = util or {}
    storages = storages or []
    raids = raids or []
    disks = disks or []
    GB = 1024 ** 3

    # RAID detail by storage name — folds array status into its storage's pool
    # entry and yields member-level alerts.
    raid_by_name = {r.get('name'): r for r in raids if isinstance(r, dict)}

    size = used = 0
    pool_list, healthy, degraded, alerts = [], 0, 0, []
    for st in storages:
        ext = st.get('extensions') or {}
        name = st.get('name') or st.get('path') or 'storage'
        ok = bool(ext.get('health', True))
        status = st.get('type') or 'storage'
        raid = raid_by_name.get(name)
        if raid:
            rst = (raid.get('raid_status') or '').lower()
            if rst and rst != 'ok':
                ok = False
                status = f'{status} ({rst})'
                alerts.append(f'{name}: RAID status {raid.get("raid_status")}')
            if raid.get('shortage'):
                ok = False
                alerts.append(f'{name}: RAID is missing a member disk')
            for dev in raid.get('devices') or []:
                if dev.get('faulty') or dev.get('missing') or dev.get('health') is False:
                    alerts.append(f'{name} member {dev.get("path")}: '
                                  + ('missing' if dev.get('missing') else
                                     'faulty' if dev.get('faulty') else 'unhealthy'))
        if not ok and not raid:
            alerts.append(f'{name}: unhealthy')
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        stotal, sused = int(ext.get('size') or 0), int(ext.get('used') or 0)
        size += stotal
        used += sused
        pool_list.append({
            'name': name, 'status': status, 'healthy': ok,
            'size_gb': round(stotal / GB, 1), 'used_gb': round(sused / GB, 1),
            'used_pct': round(sused / stotal * 100, 1) if stotal else None,
        })

    for d in disks:
        if d.get('health') is False:
            alerts.append(f'disk {d.get("path") or d.get("name")}: unhealthy '
                          f'({d.get("model") or "?"})')

    cpu = util.get('cpu') or {}
    mem = util.get('mem') or {}
    mem_total = int(mem.get('total') or 0)
    mem_used = int(mem.get('used') or 0)
    mem_pct = mem.get('usedPercent')

    return {
        'hostname': None,     # ZimaOS exposes no hostname/version via the API
        'version': None,
        'model': None,
        'uptime_seconds': None,
        'cpu_usage_percent': (round(float(cpu['percent']), 1)
                              if cpu.get('percent') is not None else None),
        'memory_total_gb': round(mem_total / GB, 1) if mem_total else None,
        'memory_used_gb': round(mem_used / GB, 1) if mem_total else None,
        'memory_usage_percent': (round(float(mem_pct), 1)
                                 if mem_pct is not None else None),
        'storage_total_gb': size / GB,
        'storage_used_gb': used / GB,
        'storage_usage_percent': round(used / size * 100, 1) if size else None,
        'pool_count': len(storages),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(disks),
        'alert_count': len(alerts),
        'alerts': alerts[:10],
    }
