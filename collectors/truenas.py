"""TrueNAS collector — SCALE/CORE over the JSON-RPC 2.0 WebSocket API (API key).

Read-only by design: only ever calls read methods (system.info, pool.query,
disk.query, alert.list) plus one reporting read (CPU/memory). Auth is the API key
via ``auth.login_with_api_key`` over ``wss://<host>/api/current`` — the key's user
needs the *Read Only Admin* role (every method errors otherwise). Talks to
app.py's TrueNasAdapter.

Migrated from the REST v2.0 API, which TrueNAS **deprecated in 25.04 and removes
in 26.04**. The JSON-RPC method names and payload shapes match the old REST paths
(system/info→system.info, pool→pool.query, disk→disk.query, alert/list→alert.list,
reporting/get_data→reporting.get_data), so ``build_metrics`` is unchanged.
``collect_metrics`` does the WebSocket I/O (imports ``websocket-client`` lazily so
the controller and the pure-function unit tests don't need it unless a NAS is
enrolled); ``build_metrics`` is a pure transform (unit-tested).
"""
import json

CONNECT_TIMEOUT = (10, 30)   # (connect, read) — reporting can be a touch slow
WS_ENDPOINT = "wss://%s:%s/api/current"   # versioned JSON-RPC 2.0 socket


def collect_metrics(host, api_key, port=443, verify_ssl=False, timeout=CONNECT_TIMEOUT):
    """Open the JSON-RPC 2.0 WebSocket, authenticate with the API key, and read
    the same read-only methods the REST collector used. Raises on connect/auth
    failure (so the probe fails cleanly); the per-endpoint reads are best-effort."""
    import ssl
    import websocket   # websocket-client; lazy — only imported when a NAS is polled

    connect_to, read_to = timeout if isinstance(timeout, (tuple, list)) else (timeout, timeout)
    # The controller pins the leaf cert fingerprint itself before each poll, so we
    # don't chain-verify here unless explicitly asked (matches the old REST path).
    sslopt = None if verify_ssl else {'cert_reqs': ssl.CERT_NONE}
    ws = websocket.create_connection(WS_ENDPOINT % (host, port),
                                     sslopt=sslopt, timeout=connect_to)
    state = {'id': 0}

    def call(method, *params):
        state['id'] += 1
        rid = state['id']
        ws.send(json.dumps({'jsonrpc': '2.0', 'id': rid,
                            'method': method, 'params': list(params)}))
        while True:                       # skip any unsolicited notifications
            msg = json.loads(ws.recv())
            if msg.get('id') != rid:
                continue
            if msg.get('error'):
                err = msg['error']
                raise RuntimeError('%s: %s' % (
                    method, err.get('message', err) if isinstance(err, dict) else err))
            return msg.get('result')

    try:
        ws.settimeout(read_to)
        # Authenticate first: a bad/under-privileged key returns False here,
        # failing the probe cleanly (needs the Read Only Admin role, as before).
        if call('auth.login_with_api_key', api_key) is not True:
            raise RuntimeError('API key rejected (needs the Read Only Admin role)')

        info = call('system.info')        # identity/RAM + validates the session
        pools = call('pool.query')
        # Best-effort below — a NAS with a restricted key, no disks, no alerts, or
        # reporting disabled must still render its pools + capacity.
        try:
            disks = call('disk.query')
        except Exception:
            disks = []
        try:
            alerts = call('alert.list')
        except Exception:
            alerts = []
        cpu_graph = mem_graph = None
        try:
            graphs = call('reporting.get_data',
                          [{'name': 'cpu'}, {'name': 'memory'}],
                          {'unit': 'HOUR', 'aggregate': True})
            by_name = {g.get('name'): g for g in graphs} if isinstance(graphs, list) else {}
            cpu_graph, mem_graph = by_name.get('cpu'), by_name.get('memory')
        except Exception:
            pass
    finally:
        try:
            ws.close()
        except Exception:
            pass

    return build_metrics(info, pools, disks, alerts, cpu_graph, mem_graph)


def _recent_avg(graph, column, n=60):
    """Mean of the last ``n`` complete samples of a named column from a netdata
    reporting graph (``{'legend': [...], 'data': [[ts, v0, ...], ...]}``). The
    final row is the in-progress second and reads 0/partial, so it's dropped —
    otherwise CPU flickers to 0 and memory-available to 0 (→ 100% used). None if
    the column/data is absent."""
    if not isinstance(graph, dict):
        return None
    legend = graph.get('legend') or []
    data = graph.get('data') or []
    if column not in legend or not data:
        return None
    i = legend.index(column)
    rows = data[:-1] if len(data) > 1 else data   # drop the incomplete last second
    vals = [row[i] for row in rows[-n:] if i < len(row) and row[i] is not None]
    return (sum(vals) / len(vals)) if vals else None


# Non-dismissed alerts at/above WARNING count toward the health rollup (INFO —
# e.g. "an update is available" — does not).
_SEVERE = {'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'}


def build_metrics(info, pools, disks, alerts, cpu_graph=None, mem_graph=None):
    """Pure transform: TrueNAS JSON-RPC payloads → the normalized metric dict.
    (Shapes are identical to the old REST payloads, so this is unchanged.)"""
    info = info or {}
    pools = pools or []
    disks = disks or []
    alerts = alerts or []
    GB = 1024 ** 3

    size = sum((p.get('size') or 0) for p in pools)
    alloc = sum((p.get('allocated') or 0) for p in pools)
    pool_list, healthy, degraded = [], 0, 0
    for p in pools:
        ph = bool(p.get('healthy'))
        healthy += 1 if ph else 0
        degraded += 0 if ph else 1
        psize, pal = (p.get('size') or 0), (p.get('allocated') or 0)
        pool_list.append({
            'name': p.get('name'), 'status': p.get('status'), 'healthy': ph,
            'size_gb': round(psize / GB, 1), 'used_gb': round(pal / GB, 1),
            'used_pct': round(pal / psize * 100, 1) if psize else None,
        })

    active = [a for a in alerts
              if not a.get('dismissed') and (a.get('level') in _SEVERE)]

    phys = info.get('physmem') or 0
    avail = _recent_avg(mem_graph, 'available')   # bytes of truly-available RAM
    # NOTE: ZFS ARC counts as "used" here (available excludes it), so a healthy,
    # idle TrueNAS legitimately reports high memory use — the usual ZFS quirk.
    mem_used = (phys - avail) if (phys and avail is not None) else None

    cpu_pct = _recent_avg(cpu_graph, 'cpu')   # aggregate CPU busy %, already 0..100

    return {
        'hostname': info.get('hostname'),
        'version': info.get('version'),
        'model': info.get('model'),
        'uptime_seconds': info.get('uptime_seconds'),
        'cpu_usage_percent': round(cpu_pct, 1) if cpu_pct is not None else None,
        'memory_total_gb': (phys / GB) if phys else None,
        'memory_used_gb': (mem_used / GB) if mem_used is not None else None,
        'memory_usage_percent': round(mem_used / phys * 100, 1) if (mem_used is not None and phys) else None,
        'storage_total_gb': size / GB,
        'storage_used_gb': alloc / GB,
        'storage_usage_percent': round(alloc / size * 100, 1) if size else None,
        'pool_count': len(pools),
        'pools_healthy': healthy,
        'pools_degraded': degraded,
        'pools': pool_list,
        'disk_count': len(disks),
        'alert_count': len(active),
        'alerts': [(a.get('formatted') or a.get('text') or '').strip() for a in active][:10],
    }
