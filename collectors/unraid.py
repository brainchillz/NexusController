"""Unraid collector — the Unraid 7.x GraphQL API, read-only.

Auth: Unraid's /graphql wants either an API key or a webGui session + CSRF
token. This collector uses the **webGui username/password** (what an operator
already has): ``POST /login`` → session cookie, scrape ``csrf_token`` from a
webGui page, then POST GraphQL queries with ``?csrf_token=``. The session +
token are CACHED per host between polls (re-login only when a poll comes back
unauthenticated), so steady-state polling is one GraphQL round-trip.

Queries (all reads):
  * ``info { os {...} }``                      hostname, "Unraid OS 7.x"
  * ``metrics { cpu memory }``                 live CPU % + memory %
  * ``array { state capacity disks parities caches }``  the parity array +
    every pool member ("caches"); entries carrying ``fsSize`` are mounted
    pools. Sizes here are **kilobytes**.
  * ``notifications { overview { unread } }``  alert/warning counts

`build_metrics` emits the SAME normalized dict as the TrueNAS/Synology/ZimaOS
collectors → `build_nas_envelope` + the whole NAS UI are reused. Pools = the
parity-protected array (when populated) + each mounted pool; a pool-less,
all-NVMe/SSD Unraid (like MiniRackUnraid) still reports correctly.
"""
import re
import threading

import requests

TIMEOUT = (5, 15)

_QUERY = """{
  info { os { distro release hostname } }
  metrics { cpu { percentTotal } memory { percentTotal total used } }
  array {
    state
    capacity { kilobytes { free used total } }
    disks   { name status temp fsSize fsUsed fsFree }
    parities { name status }
    caches  { name status fsSize fsUsed fsFree }
  }
  notifications { overview { unread { alert warning total } } }
}"""

# session cache: host -> {'session': requests.Session, 'csrf': str}
_sessions = {}
_lock = threading.Lock()


class UnraidError(Exception):
    pass


def _login(base, username, password, verify_ssl):
    s = requests.Session()
    s.verify = bool(verify_ssl)
    try:
        r = s.post(base + '/login',
                   data={'username': username, 'password': password},
                   timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        raise UnraidError(f'login: {e}')
    # Success = redirect with a session cookie; failure re-renders the form.
    if r.status_code != 302 or not s.cookies:
        raise UnraidError('login failed: invalid username or password')
    try:
        page = s.get(base + '/Main', timeout=TIMEOUT)
    except requests.RequestException as e:
        raise UnraidError(f'login: {e}')
    m = re.search(r"csrf_token['\"]?\s*[:=]\s*['\"]([0-9A-Fa-f]{8,})", page.text)
    if not m:
        raise UnraidError('login ok but no csrf_token on the webGui page '
                          '(unsupported Unraid version?)')
    return s, m.group(1)


def _graphql(base, s, csrf, query):
    try:
        r = s.post(base + '/graphql', json={'query': query},
                   params={'csrf_token': csrf}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise UnraidError(f'graphql: {e}')
    try:
        doc = r.json()
    except ValueError:
        raise UnraidError(f'graphql: non-JSON response (HTTP {r.status_code} — '
                          'is this an Unraid 7.x URL?)')
    errs = doc.get('errors') or []
    if any('UNAUTHENTICATED' in str(e.get('extensions', {}).get('code')) or
           'CSRF' in str(e.get('message', '')) for e in errs):
        raise PermissionError('session expired')
    if errs and not doc.get('data'):
        raise UnraidError('graphql: ' + '; '.join(e.get('message', '?')[:80] for e in errs[:3]))
    return doc.get('data') or {}


def collect_metrics(host, username, password, port=80, scheme='http',
                    verify_ssl=False):
    """One poll: (cached session) GraphQL query → normalized NAS metric dict.
    Raises UnraidError."""
    base = f'{scheme}://{host}:{port}'
    with _lock:
        cached = _sessions.get(base)
    if cached:
        try:
            data = _graphql(base, cached['session'], cached['csrf'], _QUERY)
            return build_metrics(data)
        except PermissionError:
            pass   # stale session — fall through to re-login
    s, csrf = _login(base, username, password, verify_ssl)
    try:
        data = _graphql(base, s, csrf, _QUERY)
    except PermissionError:
        raise UnraidError('authenticated but the GraphQL API rejected the '
                          'session (is the Unraid API enabled?)')
    with _lock:
        _sessions[base] = {'session': s, 'csrf': csrf}
    return build_metrics(data)


def _kb(v):
    """Array/pool sizes arrive as kilobyte counts (sometimes strings)."""
    try:
        return int(float(v)) * 1024
    except (TypeError, ValueError):
        return 0


def build_metrics(data):
    """Pure transform: the GraphQL response → the normalized NAS metric dict
    (same shape as collectors/truenas.build_metrics)."""
    data = data or {}
    info = ((data.get('info') or {}).get('os')) or {}
    metrics = data.get('metrics') or {}
    array = data.get('array') or {}
    unread = (((data.get('notifications') or {}).get('overview')) or {}).get('unread') or {}
    GB = 1024 ** 3

    size = used = 0
    pool_list, healthy, degraded, alerts = [], 0, 0, []

    state = (array.get('state') or '').upper()
    cap = ((array.get('capacity') or {}).get('kilobytes')) or {}
    cap_total, cap_used = _kb(cap.get('total')), _kb(cap.get('used'))
    disks = array.get('disks') or []
    parities = array.get('parities') or []
    caches = array.get('caches') or []

    if cap_total:   # a populated parity array → one "array" pool
        ok = state == 'STARTED' and all(
            (d.get('status') or 'DISK_OK') == 'DISK_OK' for d in disks + parities)
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        size += cap_total
        used += cap_used
        pool_list.append({
            'name': 'array', 'status': state if state != 'STARTED' else
                    ('DEGRADED' if not ok else 'STARTED'),
            'healthy': ok,
            'size_gb': round(cap_total / GB, 1), 'used_gb': round(cap_used / GB, 1),
            'used_pct': round(cap_used / cap_total * 100, 1),
        })
    elif state and state != 'STARTED':
        alerts.append(f'array state: {state}')

    for c in caches:
        if c.get('fsSize') is None:   # extra pool member, not a mounted pool
            continue
        ok = (c.get('status') or 'DISK_OK') == 'DISK_OK'
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        ctotal, cused = _kb(c.get('fsSize')), _kb(c.get('fsUsed'))
        size += ctotal
        used += cused
        pool_list.append({
            'name': c.get('name') or 'pool', 'status': c.get('status'),
            'healthy': ok,
            'size_gb': round(ctotal / GB, 1), 'used_gb': round(cused / GB, 1),
            'used_pct': round(cused / ctotal * 100, 1) if ctotal else None,
        })

    for d in disks + parities + caches:
        st = d.get('status') or 'DISK_OK'
        if st != 'DISK_OK':
            alerts.append(f'{d.get("name") or "disk"}: {st}')
    n_alert, n_warn = unread.get('alert') or 0, unread.get('warning') or 0
    if n_alert:
        alerts.append(f'{n_alert} unread ALERT notification(s) in Unraid')
    if n_warn:
        alerts.append(f'{n_warn} unread warning notification(s) in Unraid')

    cpu_pct = ((metrics.get('cpu') or {}).get('percentTotal'))
    mem = metrics.get('memory') or {}
    mem_pct = mem.get('percentTotal')
    mem_total, mem_used = int(mem.get('total') or 0), int(mem.get('used') or 0)
    parts = (info.get('release') or '').split()   # '7.3 x86_64' → '7.3'
    release = parts[0] if parts else None

    return {
        'hostname': info.get('hostname'),
        'version': ('Unraid ' + release) if release else None,
        'model': info.get('distro'),
        'uptime_seconds': None,
        'cpu_usage_percent': round(float(cpu_pct), 1) if cpu_pct is not None else None,
        'memory_total_gb': round(mem_total / GB, 1) if mem_total else None,
        'memory_used_gb': round(mem_used / GB, 1) if mem_total else None,
        'memory_usage_percent': round(float(mem_pct), 1) if mem_pct is not None else None,
        'storage_total_gb': size / GB,
        'storage_used_gb': used / GB,
        'storage_usage_percent': round(used / size * 100, 1) if size else None,
        'pool_count': len(pool_list),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(disks) + len(parities) + len(caches),
        'alert_count': len(alerts),
        'alerts': alerts[:10],
    }
