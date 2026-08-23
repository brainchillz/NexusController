"""UGREEN UGOS Pro collector: pure build_metrics transform + adapter wiring.
Fixture shapes mirror a live DXP8800 Plus (sysinfo/machine/common,
taskmgr/stat/get_all, storage/pool+disk lists) with synthetic values. The
pool fixture keeps the two live-verified UGOS quirks: a healthy mounted
volume reports health 0 / status 0 (pools report 1), and the pool's own
used/free are ALLOCATION (a full-pool volume reads used == total while
empty) — capacity must come from the volumes. No network."""
import app
from collectors import ugreen


INFO = {
    'common': {'nas_name': 'nas1', 'model': 'DXP8800 Plus',
               'serial': 'TESTSERIAL000000', 'system_version': '1.18.1.0098',
               'run_time': 2936, 'product_series': 'nasync'},
    'hardware': {
        'cpu': [{'model': 'test cpu', 'core': 10, 'thread': 12, 'temperature': 37}],
        'mem': [{'model': 'dimm', 'size': 17179869184},
                {'model': 'dimm', 'size': 17179869184}],
    },
}
STAT = {'overview': {
    'cpu': [{'time': 1700000000, 'used_percent': 0.67, 'temp': 37}],
    'mem': [{'time': 1700000000, 'used_percent': 5.28}],
}}
POOLS = {'result': [
    {'name': 'pool1', 'label': 'Pool 1', 'level': 'raid5', 'pvs': '/dev/md1',
     'status': 1, 'is_sync_delay': False,
     # pool used/free = allocation: the volume spans the pool
     'total': 12002361090048, 'used': 12002361090048, 'free': 0,
     'total_disk_num': 4,
     'disks': [{'name': '/dev/sda', 'label': 'Hard Drive 1', 'slot': 'ata1',
                'size': 3984266887168, 'status': 0}],   # member: 0 = normal
     'volumes': [{'name': 'volume1', 'label': 'Volume 1', 'poolname': 'pool1',
                  'filesystem': 'ext4', 'mntpath': '/volume1',
                  'status': 0, 'health': 0,             # live: 0 = normal
                  'total': 11951890268160, 'used': 3983963422720,
                  'available': 7967926845440, 'ready_to_use': True}]},
]}
DISKS = {'result': [
    {'model': 'TESTDISK', 'serial': 'D%d' % i, 'size': 4000787030016,
     'name': 'sd%s' % c, 'dev_name': '/dev/sd%s' % c, 'slot': 'ata%d' % i,
     'interface_type': 'sata', 'label': 'Hard Drive %d' % i, 'used_for': 'Pool 1',
     'status': 1, 'temperature': 42, 'power_on_hours': 100, 'brand': 'Test'}
    for i, c in ((1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'))
]}


def test_build_metrics_healthy():
    m = ugreen.build_metrics(INFO, STAT, POOLS, DISKS)
    assert m['hostname'] == 'nas1' and m['model'] == 'DXP8800 Plus'
    assert m['version'] == '1.18.1.0098' and m['uptime_seconds'] == 2936
    assert m['cpu_usage_percent'] == 0.7 and m['memory_usage_percent'] == 5.3
    assert m['memory_total_gb'] == 32.0
    assert m['pool_count'] == 1 and m['pools_healthy'] == 1 and m['pools_degraded'] == 0
    assert m['disk_count'] == 4 and m['alert_count'] == 0
    p = m['pools'][0]
    assert p['name'] == 'Pool 1' and p['status'] == 'raid5' and p['healthy']
    # capacity from the VOLUME (filesystem), not the pool's allocation
    # counters — the pool itself reads used == total (fully allocated)
    assert round(m['storage_total_gb']) == 11131
    assert p['used_pct'] == 33.3
    assert m['storage_usage_percent'] == 33.3


def test_degraded_pool_and_volume_alert():
    pools = {'result': [dict(POOLS['result'][0], status='DEGRADED')]}
    m = ugreen.build_metrics(INFO, STAT, pools, DISKS)
    assert m['pools_degraded'] == 1 and m['pools_healthy'] == 0
    assert not m['pools'][0]['healthy'] and 'DEGRADED' in m['pools'][0]['status']
    assert any('Pool 1: status DEGRADED' in a for a in m['alerts'])

    pools = {'result': [dict(POOLS['result'][0],
                             volumes=[dict(POOLS['result'][0]['volumes'][0],
                                           health='BAD')])]}
    m = ugreen.build_metrics(INFO, STAT, pools, DISKS)
    assert m['pools_degraded'] == 1
    assert any('Pool 1/Volume 1' in a for a in m['alerts'])


def test_bad_disk_alert():
    disks = {'result': [dict(DISKS['result'][0], status=0)]}
    m = ugreen.build_metrics(INFO, STAT, POOLS, disks)
    assert m['alert_count'] == 1
    assert 'disk Hard Drive 1: status 0' in m['alerts'][0]


def test_ok_status_mapping():
    assert ugreen._ok_status(None) and ugreen._ok_status('')
    assert ugreen._ok_status(1) and ugreen._ok_status('Normal') and ugreen._ok_status('GOOD')
    assert not ugreen._ok_status(0) and not ugreen._ok_status(2)
    assert not ugreen._ok_status('degraded') and not ugreen._ok_status(False)
    # volumes/pool-member disks: 0 is normal (seen live), 1 accepted too
    assert ugreen._vol_ok(0) and ugreen._vol_ok(1) and ugreen._vol_ok(None)
    assert not ugreen._vol_ok(2) and not ugreen._vol_ok('BAD')


def test_empty_payloads_survive():
    m = ugreen.build_metrics({}, {}, {}, {})
    assert m['pool_count'] == 0 and m['cpu_usage_percent'] is None
    assert m['memory_total_gb'] is None
    assert m['storage_total_gb'] == 0 and m['alert_count'] == 0


def test_nas_envelope_from_ugreen_metrics():
    node = {'id': 'u1', 'name': 'nas1', 'base_url': 'https://192.168.1.50:9443',
            'host_type': 'ugreen'}
    env = app.build_nas_envelope(node, ugreen.build_metrics(INFO, STAT, POOLS, DISKS))
    assert env['ok'] and env['type_auto'] == 'Storage'
    assert env['nas']['kind'] == 'ugreen' and env['nas']['pools'] == 1
    assert env['nas']['model'] == 'DXP8800 Plus'
    assert env['resources']['cpu_pct'] == 0.7


def test_ugreen_adapter_registered():
    a = app._adapter_for({'host_type': 'ugreen'})
    assert a.kind == 'ugreen' and a.auth == 'userpass'
    assert a.default_type == 'Storage' and a.polled and not a.supports_write
    d = a.descriptor()
    assert d['label'].startswith('UGREEN') and d['verify_tls']
    assert d['url_placeholder'].endswith(':9443')
