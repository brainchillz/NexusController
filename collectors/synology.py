"""Synology DSM collector — the DSM Web API over HTTP(S), read-only.

Auth model: session login with a LOCAL DSM account (**no 2FA**; DSM has no
read-only admin role, and the system/storage APIs require an account in the
**administrators** group). `SYNO.API.Auth` login → `sid`, passed to each call.
The session is **cached per host between polls** (omv/unraid pattern) and
re-established on any session-lost error code — DSM recycles sids at will
(worker session-table races, hibernation housekeeping, duplicate logins; the
live DS723+ intermittently returned **code 119 "SID not found"** to a
seconds-old sid under the old fresh-login-per-poll scheme, failing ~1% of
polls). No logout: DSM expires the cached session itself if we stop calling.
Calls used (all reads):

  * ``SYNO.API.Info``                (query.cgi, no auth) — endpoint discovery
  * ``SYNO.API.Auth``                login/logout
  * ``SYNO.Core.System``             model / DSM version / hostname
  * ``SYNO.Core.System.Utilization`` CPU + memory
  * ``SYNO.Storage.CGI.Storage``     volumes / disks / RAID health
  * ``SYNO.Core.Service``            file/access services (best-effort)

`build_metrics` is a pure transform returning the SAME normalized metric dict
as collectors/truenas.build_metrics, so `build_nas_envelope` (and therefore the
rollup, NAS row chips, and storage view) work unchanged. DSM "volumes" map to
the envelope's "pools".
"""
import threading

import requests

TIMEOUT = (5, 15)

# Non-login error codes that mean the session died under us (not that the
# request was wrong): 106 timeout, 107 duplicate-login interrupt, 119 SID not
# found — and 105, which DSM returns for a lost session as often as for a
# genuinely under-privileged account (a fresh login settles which it was).
_SESSION_LOST = {105, 106, 107, 119}

_sessions = {}   # base URL -> {'s': requests.Session, 'sid': str, 'apis': dict}
_lock = threading.Lock()

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
        if what != 'login' and code in _SESSION_LOST:
            e = PermissionError(f'{what}: session rejected (code {code})')
            e.code = code
            raise e
        raise SynologyError(f'{what}: API error code {code}')
    return doc.get('data') or {}


def _path(apis, base, api):
    return base + '/' + ((apis.get(api) or {}).get('path') or 'entry.cgi')


def _ver(apis, api, want):
    return min(want, (apis.get(api) or {}).get('maxVersion') or want)


def _collect(s, base, apis, sid):
    """The read calls of one poll against an authenticated session. Raises
    PermissionError (via _get) if DSM dropped the sid — the caller re-logins."""
    info = _get(s, _path(apis, base, 'SYNO.Core.System'),
                {'api': 'SYNO.Core.System', 'version': _ver(apis, 'SYNO.Core.System', 3),
                 'method': 'info', '_sid': sid}, 'system info')
    util = _get(s, _path(apis, base, 'SYNO.Core.System.Utilization'),
                {'api': 'SYNO.Core.System.Utilization', 'version': 1,
                 'method': 'get', '_sid': sid}, 'utilization')
    storage = _get(s, _path(apis, base, 'SYNO.Storage.CGI.Storage'),
                   {'api': 'SYNO.Storage.CGI.Storage', 'version': 1,
                    'method': 'load_info', '_sid': sid}, 'storage info')
    try:   # best-effort — an older DSM without it must still render
        services = _get(s, _path(apis, base, 'SYNO.Core.Service'),
                        {'api': 'SYNO.Core.Service',
                         'version': _ver(apis, 'SYNO.Core.Service', 3),
                         'method': 'get', '_sid': sid}, 'services')
    except SynologyError:
        services = None
    return build_metrics(info, util, storage, services)


def collect_metrics(host, username, password, port=5001, verify_ssl=False,
                    scheme='https'):
    """One poll (cached session; re-login + retry when DSM drops the sid) →
    the normalized metric dict (see build_metrics). Raises SynologyError."""
    base = f'{scheme}://{host}:{port}/webapi'
    with _lock:
        cached = _sessions.get(base)
    if cached:
        try:
            return _collect(cached['s'], base, cached['apis'], cached['sid'])
        except PermissionError:
            pass   # DSM recycled the sid — fall through to a fresh login

    s = requests.Session()
    s.verify = bool(verify_ssl)
    apis = _get(s, base + '/query.cgi',
                {'api': 'SYNO.API.Info', 'version': 1, 'method': 'query',
                 'query': 'SYNO.API.Auth,SYNO.Core.System,'
                          'SYNO.Core.System.Utilization,SYNO.Storage.CGI.Storage,'
                          'SYNO.Core.Service'},
                'API discovery')
    auth = _get(s, _path(apis, base, 'SYNO.API.Auth'),
                {'api': 'SYNO.API.Auth', 'version': _ver(apis, 'SYNO.API.Auth', 7),
                 'method': 'login', 'account': username, 'passwd': password,
                 'session': 'NexusController', 'format': 'sid'},
                'login')
    sid = auth.get('sid')
    if not sid:
        raise SynologyError('login returned no session id')

    try:
        metrics = _collect(s, base, apis, sid)
    except PermissionError as e:
        # A brand-new session was rejected too: code 105 here really is the
        # missing administrators-group privilege, anything else is DSM
        # misbehaving in a way a retry can't paper over.
        if getattr(e, 'code', None) == 105:
            raise SynologyError(f'{e} — the account must be in the '
                                'administrators group')
        raise SynologyError(f'authenticated but DSM rejected the fresh session: {e}')
    with _lock:
        _sessions[base] = {'s': s, 'sid': sid, 'apis': apis}
    return metrics


def _num(v):
    """DSM reports byte sizes as strings; coerce defensively."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# DSM service_id → canonical (key, display name) matching the nexus nodes'
# summary.services keys, so the Services matrix merges the columns. ftp-ssl
# folds into 'ftp'; 'static' (system-managed, e.g. pkg-iscsi with no targets)
# entries are skipped — they say nothing about what the admin turned on.
_SERVICE_KEYS = {
    'pkg-synosamba-smbd': ('smb', 'Samba'),
    'nfs-server': ('nfs', 'NFS Server'),
    'atalk': ('afp', 'AFP'),
    'ftp-pure': ('ftp', 'FTP'),
    'ftp-ssl': ('ftp', 'FTP'),
    'rsyncd': ('rsync', 'Rsync'),
    'sftp': ('sftp', 'SFTP'),
    'ssh-shell': ('ssh', 'SSH'),
}


def map_services(services):
    """SYNO.Core.Service get → the nexus-style summary.services dict. DSM only
    reports enable state (it runs what's enabled), so active mirrors enabled;
    disabled services are omitted (see the enabled-or-running rule in
    collectors/truenas.map_services)."""
    out = {}
    for s in (services or {}).get('service') or []:
        mapped = _SERVICE_KEYS.get(s.get('service_id'))
        if not mapped:
            continue
        key, name = mapped
        if s.get('enable_status') != 'enabled':
            continue
        out[key] = {'name': name, 'active': 'active', 'enabled': 'enabled'}
    return out


def build_metrics(info, util, storage, services=None):
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
        'services': map_services(services),
    }
