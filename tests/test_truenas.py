"""TrueNAS adapter — pure-function tests (no live NAS needed).

Covers the collector's build_metrics transform (pool/disk/alert folding, the
ZFS-ARC memory calc, and dropping netdata's incomplete last sample) and
app.build_nas_envelope (metric-dict → fan-out envelope), plus adapter dispatch,
the token auth-model, and that compute_rollup tolerates a NAS envelope."""
import app
from collectors import truenas

GB = 1024 ** 3

# ~64 GiB box, one healthy 16 TB pool ~3% full, 9 disks.
INFO = {'hostname': 'nas1', 'version': 'TrueNAS-25.10.2.1',
        'model': 'Intel(R) Xeon(R) CPU D-1521', 'physmem': 64 * GB,
        'uptime_seconds': 10795843.8}
POOLS = [{'name': 'SATAFLASH', 'status': 'ONLINE', 'healthy': True,
          'size': 16 * 1024 ** 4, 'allocated': 480 * GB, 'free': 16 * 1024 ** 4 - 480 * GB}]
DISKS = [{'name': 'sd%s' % c, 'type': 'SSD'} for c in 'abcdefghi']   # 9
ALERTS = [
    {'level': 'INFO', 'dismissed': False, 'formatted': 'An update is available.'},
    {'level': 'WARNING', 'dismissed': False, 'formatted': 'Pool scrub found errors.'},
    {'level': 'CRITICAL', 'dismissed': True, 'formatted': 'Old dismissed alert.'},
]
# netdata graphs: the LAST row is the in-progress second (reads 0) and must be
# dropped, else cpu→0 and available→0 (→100% mem used).
CPU_GRAPH = {'legend': ['time', 'cpu', 'cpu0', 'cpu1'],
             'data': [[1, 2, 1, 3], [2, 4, 5, 3], [3, 0, 0, 0]]}
MEM_GRAPH = {'legend': ['time', 'available'],
             'data': [[1, 8 * GB], [2, 8 * GB], [3, 0]]}

NAS_NODE = {'id': 'n1', 'name': 'nas1', 'base_url': 'https://192.168.1.20',
            'host_type': 'truenas', 'type': 'Storage', 'type_pinned': False, 'tags': []}


def test_build_metrics_pools_disks_and_capacity():
    m = truenas.build_metrics(INFO, POOLS, DISKS, ALERTS, CPU_GRAPH, MEM_GRAPH)
    assert m['pool_count'] == 1 and m['pools_healthy'] == 1 and m['pools_degraded'] == 0
    assert m['disk_count'] == 9
    assert round(m['storage_used_gb']) == 480
    assert round(m['storage_usage_percent'], 1) == 2.9   # 480 GiB / 16 TiB
    assert m['pools'][0]['name'] == 'SATAFLASH' and m['pools'][0]['healthy'] is True


def test_build_metrics_alerts_only_active_severe():
    m = truenas.build_metrics(INFO, POOLS, DISKS, ALERTS)
    # INFO ignored, dismissed CRITICAL ignored → only the WARNING counts
    assert m['alert_count'] == 1
    assert m['alerts'] == ['Pool scrub found errors.']


def test_build_metrics_drops_incomplete_last_sample():
    m = truenas.build_metrics(INFO, POOLS, DISKS, [], CPU_GRAPH, MEM_GRAPH)
    # CPU = mean of the two complete rows (2, 4) = 3.0, NOT the trailing 0
    assert m['cpu_usage_percent'] == 3.0
    # available = mean(8, 8) GiB → used = 64-8 = 56 GiB → 87.5% (ARC-inflated)
    assert round(m['memory_used_gb']) == 56
    assert round(m['memory_usage_percent'], 1) == 87.5


def test_build_metrics_no_reporting_leaves_cpu_mem_none():
    m = truenas.build_metrics(INFO, POOLS, DISKS, [])   # no graphs
    assert m['cpu_usage_percent'] is None
    assert m['memory_usage_percent'] is None
    assert m['memory_total_gb'] == 64.0                 # still from physmem


def test_build_metrics_degraded_pool_counts():
    pools = POOLS + [{'name': 'tank', 'status': 'DEGRADED', 'healthy': False,
                      'size': 4 * 1024 ** 4, 'allocated': 1 * 1024 ** 4}]
    m = truenas.build_metrics(INFO, pools, DISKS, [])
    assert m['pool_count'] == 2 and m['pools_healthy'] == 1 and m['pools_degraded'] == 1


def test_build_nas_envelope_shape():
    m = truenas.build_metrics(INFO, POOLS, DISKS, ALERTS, CPU_GRAPH, MEM_GRAPH)
    env = app.build_nas_envelope(NAS_NODE, m)
    assert env['ok'] is True
    assert env['host_type'] == 'truenas'
    assert env['type_auto'] == 'Storage'
    assert env['resources']['cpu_pct'] == 3.0
    assert env['resources']['memory']['pct'] is not None
    assert env['used_bytes'] == int(m['storage_used_gb'] * GB)
    assert env['size_bytes'] == int(m['storage_total_gb'] * GB)
    nas = env['nas']
    assert nas['pools'] == 1 and nas['pools_degraded'] == 0 and nas['disks'] == 9
    assert nas['alerts'] == 1 and nas['alert_list'] == ['Pool scrub found errors.']


def test_compute_rollup_tolerates_nas_envelope():
    env = app.build_nas_envelope(NAS_NODE, truenas.build_metrics(INFO, POOLS, DISKS, []))
    r = app.compute_rollup([env])
    assert r['healthy'] == 1 and r['unreachable'] == 0
    assert r['storage_used'] == int(480 * GB)          # folds into fleet capacity
    assert r['vms'] == 0 and r['containers'] == 0       # a NAS has neither


def test_truenas_adapter_dispatch_and_auth():
    a = app._adapter_for({'host_type': 'truenas'})
    assert a.kind == 'truenas'
    assert a.auth == 'token'          # API key, not username/password
    assert a.default_type == 'Storage'


def test_public_node_strips_truenas_key():
    n = {'id': '1', 'name': 'nas', 'host_type': 'truenas', 'token_enc': 'ciphertext'}
    pub = app._public_node(n)
    assert 'token_enc' not in pub
