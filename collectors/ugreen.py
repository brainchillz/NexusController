"""UGREEN UGOS Pro collector — the NAS's own web-UI API over HTTPS, read-only.

UGREEN publishes no official API; this speaks the community-reverse-engineered
UGOS Pro API (the one the UGOS web GUI uses — documented by the
home-assistant_ugreen-nas integration). Auth is username/password of a LOCAL
UGOS account **without 2FA**, with an RSA twist: ``POST
/ugreen/v1/verify/check?token=`` returns the box's RSA public key in the
``x-rsa-token`` RESPONSE HEADER (base64 wrapping DER or PEM — seen PEM live on
a DXP8800 Plus); the password is encrypted with it (PKCS#1 v1.5) and posted to
``POST /ugreen/v1/verify/login`` → ``data.token``, which every read passes as
a ``?token=`` query parameter. The token is cached per host between polls
(omv/unraid/synology pattern); UGOS answers ``code 1024`` when it expires →
PermissionError → ONE fresh login + retry inside the same poll. No logout —
UGOS expires idle tokens itself. Calls used (all reads):

  * ``GET /ugreen/v1/sysinfo/machine/common``  name / model / version / uptime
                                               / installed DIMMs (memory total)
  * ``GET /ugreen/v1/taskmgr/stat/get_all``    CPU + memory utilization
  * ``GET /ugreen/v1/storage/pool/list``       pools + their volumes
  * ``GET /ugreen/v2/storage/disk/list``       physical disks

`build_metrics` is a pure transform returning the SAME normalized metric dict
as collectors/truenas.build_metrics, so `build_nas_envelope` (and therefore
the rollup, NAS row chips, and storage view) work unchanged. Status values
are undocumented and the int convention differs per object (see
`_ok_status`/`_vol_ok`); capacity comes from the volumes, not the pool's own
allocation counters (see build_metrics).
"""
import base64
import threading

import requests

TIMEOUT = (5, 15)

# Error codes that mean the cached token died under us (not that the request
# was wrong): 1024 = token expired, 1010 = token rejected/"cannot be empty"
# (seen live on a DXP8800 Plus when presenting an invalidated token).
_TOKEN_LOST = {1010, 1024}

_sessions = {}   # base URL -> {'s': requests.Session, 'token': str}
_lock = threading.Lock()


class UgreenError(Exception):
    pass


def _encrypt_password(rsa_header, password):
    """Encrypt the login password with the RSA public key UGOS handed us in
    the x-rsa-token header (base64 wrapping DER or PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        pub_bytes = base64.b64decode(rsa_header)
    except Exception:
        pub_bytes = rsa_header.encode('utf-8')
    try:
        pub = serialization.load_der_public_key(pub_bytes)
    except Exception:
        try:
            pub = serialization.load_pem_public_key(pub_bytes)
        except Exception:
            raise UgreenError('cannot parse the RSA public key from the NAS')
    enc = pub.encrypt(password.encode('utf-8'), padding.PKCS1v15())
    return base64.b64encode(enc).decode('ascii')


def _login(s, base, username, password):
    """RSA-encrypted login → API token. Raises UgreenError."""
    try:
        r = s.post(base + '/ugreen/v1/verify/check?token=',
                   json={'username': username}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise UgreenError(f'login: {e}')
    hdr = r.headers.get('x-rsa-token', '')
    if not hdr:
        raise UgreenError(f'login: no RSA key in the verify/check response '
                          f'(HTTP {r.status_code} — is this a UGOS Pro URL?)')
    payload = {'is_simple': True, 'keepalive': True, 'otp': False,
               'username': username, 'password': _encrypt_password(hdr, password)}
    try:
        r = s.post(base + '/ugreen/v1/verify/login', json=payload, timeout=TIMEOUT)
        doc = r.json()
    except requests.RequestException as e:
        raise UgreenError(f'login: {e}')
    except ValueError:
        raise UgreenError(f'login: non-JSON response (HTTP {r.status_code})')
    token = (doc.get('data') or {}).get('token')
    if doc.get('code') != 200 or not token:
        raise UgreenError('login failed: %s (code %s) — use a local UGOS '
                          'account without 2FA'
                          % (doc.get('msg') or 'rejected', doc.get('code')))
    return token


def _get(s, base, path, token, what):
    url = base + path + ('&' if '?' in path else '?') + 'token=' + token
    try:
        r = s.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise UgreenError(f'{what}: {e}')
    try:
        doc = r.json()
    except ValueError:
        raise UgreenError(f'{what}: non-JSON response (HTTP {r.status_code} — '
                          'is this a UGOS Pro URL?)')
    code = doc.get('code')
    if code in _TOKEN_LOST:   # token expired/invalidated — caller re-logins
        raise PermissionError(f'{what}: token rejected (code {code})')
    if code != 200:
        raise UgreenError(f'{what}: {doc.get("msg") or "API error"} (code {code})')
    return doc.get('data') or {}


def _collect(s, base, token):
    """The read calls of one poll against an authenticated session. Raises
    PermissionError (via _get) if UGOS expired the token — the caller
    re-logins."""
    info = _get(s, base, '/ugreen/v1/sysinfo/machine/common', token, 'system info')
    stat = _get(s, base, '/ugreen/v1/taskmgr/stat/get_all', token, 'utilization')
    pools = _get(s, base, '/ugreen/v1/storage/pool/list', token, 'pool list')
    disks = _get(s, base, '/ugreen/v2/storage/disk/list', token, 'disk list')
    return build_metrics(info, stat, pools, disks)


def collect_metrics(host, username, password, port=9443, verify_ssl=False,
                    scheme='https'):
    """One poll (cached token; re-login + retry when UGOS expires it) → the
    normalized metric dict (see build_metrics). Raises UgreenError."""
    from collectors import session_key
    base = f'{scheme}://{host}:{port}'
    key = session_key(base, username, password)
    with _lock:
        cached = _sessions.get(key)
    if cached:
        try:
            return _collect(cached['s'], base, cached['token'])
        except PermissionError:
            pass   # token expired — fall through to a fresh login

    s = requests.Session()
    s.verify = bool(verify_ssl)
    token = _login(s, base, username, password)
    try:
        metrics = _collect(s, base, token)
    except PermissionError as e:
        raise UgreenError(f'authenticated but UGOS rejected the fresh token: {e}')
    with _lock:
        _sessions[key] = {'s': s, 'token': token}
    return metrics


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


_OK_WORDS = ('normal', 'ok', 'good', 'healthy', 'online')


def _ok_status(v, ok_ints=(1,)):
    """UGOS status/health → healthy? The values are undocumented
    (reverse-engineered API) and the int convention DIFFERS per object — seen
    live on a DXP8800 Plus: pools and the top-level disk list report ``1``
    when normal, but a healthy mounted volume (and pool-member disks) report
    ``0``. Known-good ints/spellings pass, anything else flags degraded so a
    sick pool can't hide. Absent/empty means the field wasn't reported, not
    that something is wrong."""
    if v is None or v == '':
        return True
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return int(v) in ok_ints
    return str(v).strip().lower() in _OK_WORDS


def _vol_ok(v):
    """Volume health/status: 0 = normal (seen live); accept 1 too rather than
    guess which of the two this enum uses for 'fine'."""
    return _ok_status(v, ok_ints=(0, 1))


def build_metrics(info, stat, pools, disks):
    """Pure transform: UGOS API payloads → the normalized NAS metric dict
    (same shape as collectors/truenas.build_metrics)."""
    info = info or {}
    common = info.get('common') or {}
    hardware = info.get('hardware') or {}
    overview = (stat or {}).get('overview') or {}
    pool_res = (pools or {}).get('result') or []
    disk_res = (disks or {}).get('result') or []
    GB = 1024 ** 3

    size = used = 0.0
    pool_list, healthy, degraded, alerts = [], 0, 0, []
    for p in pool_res:
        name = p.get('label') or p.get('name') or 'pool'
        ok = _ok_status(p.get('status'))
        status = str(p.get('level') or '').strip() or 'pool'
        if not ok:
            status = f'{status} (status {p.get("status")})'
            alerts.append(f'{name}: status {p.get("status")}')
        vols = p.get('volumes') or []
        for v in vols:
            vname = v.get('label') or v.get('name') or 'volume'
            if not (_vol_ok(v.get('health')) and _vol_ok(v.get('status'))):
                ok = False
                alerts.append(f'{name}/{vname}: health {v.get("health")}'
                              f'/status {v.get("status")}')
        healthy += 1 if ok else 0
        degraded += 0 if ok else 1
        # The pool's own used/free track ALLOCATION to volumes (a volume
        # spanning the pool reads 100% "used" while empty — seen live);
        # real capacity lives in the volumes' filesystem totals.
        if vols:
            ptotal = sum(_num(v.get('total')) for v in vols)
            pused = sum(_num(v.get('used')) for v in vols)
        else:
            ptotal, pused = _num(p.get('total')), 0.0
        size += ptotal
        used += pused
        pool_list.append({
            'name': name, 'status': status, 'healthy': ok,
            'size_gb': round(ptotal / GB, 1), 'used_gb': round(pused / GB, 1),
            'used_pct': round(pused / ptotal * 100, 1) if ptotal else None,
        })

    for d in disk_res:
        if not _ok_status(d.get('status')):
            alerts.append(f'disk {d.get("label") or d.get("name")}: '
                          f'status {d.get("status")} ({d.get("model") or "?"})')

    cpu = (overview.get('cpu') or [{}])[0]
    mem = (overview.get('mem') or [{}])[0]
    cpu_pct = cpu.get('used_percent')
    mem_pct = mem.get('used_percent')
    mem_total = sum(int(m.get('size') or 0) for m in hardware.get('mem') or [])

    return {
        'hostname': common.get('nas_name'),
        'version': common.get('system_version'),
        'model': common.get('model'),
        'uptime_seconds': common.get('run_time'),
        'cpu_usage_percent': (round(float(cpu_pct), 1)
                              if cpu_pct is not None else None),
        'memory_total_gb': round(mem_total / GB, 1) if mem_total else None,
        'memory_used_gb': (round(mem_total / GB * float(mem_pct) / 100, 1)
                           if (mem_total and mem_pct is not None) else None),
        'memory_usage_percent': (round(float(mem_pct), 1)
                                 if mem_pct is not None else None),
        'storage_total_gb': size / GB,
        'storage_used_gb': used / GB,
        'storage_usage_percent': round(used / size * 100, 1) if size else None,
        'pool_count': len(pool_res),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(disk_res),
        'alert_count': len(alerts),
        'alerts': alerts[:10],
    }
