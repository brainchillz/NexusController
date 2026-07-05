"""Synology DSM collector — the DSM Web API over HTTP(S), read-only.

Auth model: session login with a LOCAL DSM account (**no 2FA**; DSM has no
read-only admin role, and the system/storage APIs require an account in the
**administrators** group). `SYNO.API.Auth` login → `sid`, passed to each call,
best-effort logout after. Calls used (all reads):

  * ``SYNO.API.Info``                (query.cgi, no auth) — endpoint discovery
  * ``SYNO.API.Auth``                login/logout
  * ``SYNO.Core.System``             model / DSM version / hostname
  * ``SYNO.Core.System.Utilization`` CPU + memory
  * ``SYNO.Storage.CGI.Storage``     volumes / disks / RAID health

`build_metrics` is a pure transform returning the SAME normalized metric dict
as collectors/truenas.build_metrics, so `build_nas_envelope` (and therefore the
rollup, NAS row chips, and storage view) work unchanged. DSM "volumes" map to
the envelope's "pools".
"""
import requests

TIMEOUT = (5, 15)

# Login error codes → operator-actionable messages (DSM Web API docs).
_AUTH_ERRORS = {
    400: 'invalid account or password',
    401: 'account disabled',
    402: 'account lacks permission',
    403: '2-factor auth required — use a local account without 2FA',
    404: '2-factor auth failed',
    406: '2FA enforced on this account — use a local account without 2FA',
    407: 'IP blocked by DSM auto-block (check Security > Account)',
    408: 'password expired',
    409: 'password expired',
    410: 'password must be changed',
}


class SynologyError(Exception):
    pass


def _get(session, url, params, what):
    try:
        r = session.get(url, params=params, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise SynologyError(f'{what}: {e}')
    if r.status_code != 200:
        raise SynologyError(f'{what}: HTTP {r.status_code}')
    try:
        doc = r.json()
    except ValueError:
        raise SynologyError(f'{what}: non-JSON response (is this a DSM URL?)')
    if not doc.get('success'):
        code = (doc.get('error') or {}).get('code')
        if what == 'login' and code in _AUTH_ERRORS:
            raise SynologyError(f'login failed: {_AUTH_ERRORS[code]} (code {code})')
        if code == 105:
            raise SynologyError(f'{what}: insufficient privilege (code 105) — the '
                                'account must be in the administrators group')
        raise SynologyError(f'{what}: API error code {code}')
    return doc.get('data') or {}


def collect_metrics(host, username, password, port=5001, verify_ssl=False,
                    scheme='https'):
    """Login, pull system/utilization/storage, logout. Returns the normalized
    metric dict (see build_metrics). Raises SynologyError."""
    base = f'{scheme}://{host}:{port}/webapi'
    s = requests.Session()
    s.verify = bool(verify_ssl)

    apis = _get(s, base + '/query.cgi',
                {'api': 'SYNO.API.Info', 'version': 1, 'method': 'query',
                 'query': 'SYNO.API.Auth,SYNO.Core.System,'
                          'SYNO.Core.System.Utilization,SYNO.Storage.CGI.Storage'},
                'API discovery')

    def path(api):
        return base + '/' + ((apis.get(api) or {}).get('path') or 'entry.cgi')

    def ver(api, want):
        return min(want, (apis.get(api) or {}).get('maxVersion') or want)

    auth = _get(s, path('SYNO.API.Auth'),
                {'api': 'SYNO.API.Auth', 'version': ver('SYNO.API.Auth', 7),
                 'method': 'login', 'account': username, 'passwd': password,
                 'session': 'NexusController', 'format': 'sid'},
                'login')
    sid = auth.get('sid')
    if not sid:
        raise SynologyError('login returned no session id')

    try:
        info = _get(s, path('SYNO.Core.System'),
                    {'api': 'SYNO.Core.System', 'version': ver('SYNO.Core.System', 3),
                     'method': 'info', '_sid': sid}, 'system info')
        util = _get(s, path('SYNO.Core.System.Utilization'),
                    {'api': 'SYNO.Core.System.Utilization', 'version': 1,
                     'method': 'get', '_sid': sid}, 'utilization')
        storage = _get(s, path('SYNO.Storage.CGI.Storage'),
                       {'api': 'SYNO.Storage.CGI.Storage', 'version': 1,
                        'method': 'load_info', '_sid': sid}, 'storage info')
    finally:
        try:   # logout is best-effort — never mask the real error
            s.get(path('SYNO.API.Auth'),
                  params={'api': 'SYNO.API.Auth', 'version': 1, 'method': 'logout',
                          'session': 'NexusController', '_sid': sid},
                  timeout=TIMEOUT)
        except requests.RequestException:
            pass

    return build_metrics(info, util, storage)


def _num(v):
    """DSM reports byte sizes as strings; coerce defensively."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def build_metrics(info, util, storage):
    """Pure transform: DSM API payloads → the normalized NAS metric dict
    (same shape as collectors/truenas.build_metrics)."""
    info = info or {}
    util = util or {}
    storage = storage or {}
    GB = 1024 ** 3

    volumes = storage.get('volumes') or []
    disks = storage.get('disks') or []

    size = used = 0.0
    pool_list, healthy, degraded, alerts = [], 0, 0, []
    for v in volumes:
        st = (v.get('status') or '').lower()
        ok = st == 'normal'
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        sz = v.get('size') or {}
        vtotal, vused = _num(sz.get('total')), _num(sz.get('used'))
        size += vtotal
        used += vused
        name = (v.get('display_name') or v.get('id') or 'volume')
        if not ok:
            alerts.append(f'{name}: status {v.get("status")}')
        pool_list.append({
            'name': name, 'status': v.get('status'), 'healthy': ok,
            'size_gb': round(vtotal / GB, 1), 'used_gb': round(vused / GB, 1),
            'used_pct': round(vused / vtotal * 100, 1) if vtotal else None,
        })
    for d in disks:
        dst = (d.get('status') or '').lower()
        smart = (d.get('smart_status') or '').lower()
        if dst not in ('', 'normal') or smart not in ('', 'normal', 'safe'):
            alerts.append(f'disk {d.get("name") or d.get("id")}: '
                          f'status {d.get("status")}/smart {d.get("smart_status")}')

    cpu = util.get('cpu') or {}
    cpu_pct = None
    if cpu.get('user_load') is not None or cpu.get('system_load') is not None:
        cpu_pct = _num(cpu.get('user_load')) + _num(cpu.get('system_load'))
    mem = util.get('memory') or {}
    mem_pct = _num(mem.get('real_usage')) if mem.get('real_usage') is not None else None
    mem_total = _num(mem.get('memory_size'))          # KB per DSM docs

    return {
        'hostname': info.get('hostname'),
        'version': (info.get('firmware_ver') or '').strip() or None,
        'model': info.get('model'),
        'uptime_seconds': None,   # DSM reports up_time as a string; not needed
        'cpu_usage_percent': round(cpu_pct, 1) if cpu_pct is not None else None,
        'memory_total_gb': round(mem_total * 1024 / GB, 1) if mem_total else None,
        'memory_used_gb': (round(mem_total * 1024 / GB * mem_pct / 100, 1)
                           if (mem_total and mem_pct is not None) else None),
        'memory_usage_percent': mem_pct,
        'storage_total_gb': size / GB,
        'storage_used_gb': used / GB,
        'storage_usage_percent': round(used / size * 100, 1) if size else None,
        'pool_count': len(volumes),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(disks),
        'alert_count': len(alerts),
        'alerts': alerts[:10],
    }
