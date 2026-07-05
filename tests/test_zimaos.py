"""ZimaOS collector: pure build_metrics transform + adapter wiring. Fixtures
are trimmed from the live ZimaCube at 192.168.2.5 (ZimaOS, 2×8TB RAID1 +
system NVMe + SSD). No network."""
import app
from collectors import zimaos


UTIL = {'cpu': {'model': 'intel', 'num': 4, 'percent': 2.7, 'temperature': 43},
        'mem': {'available': 10860146688, 'free': 5965762560,
                'total': 12303036416, 'used': 1072017408, 'usedPercent': 8.8}}
STORAGES = [
    {'name': 'ZimaOS-HD', 'path': '/media/ZimaOS-HD', 'type': 'SYSTEM',
     'extensions': {'health': True, 'size': 112551780352, 'used': 9766977536}},
    {'name': 'SpinningRust', 'path': '/media/SpinningRust', 'type': 'RAID1',
     'extensions': {'health': True, 'shortage': False,
                    'size': 8001427931136, 'used': 6062080}},
    {'name': 'SSD', 'path': '/media/SSD', 'type': 'SSD',
     'extensions': {'health': True, 'size': 1000204886016, 'used': 27213824}},
]
RAIDS = [
    {'name': 'SpinningRust', 'path': '/dev/md0', 'raid_level': 1,
     'raid_status': 'ok', 'shortage': False, 'status': 'idle',
     'size': 8001427931136, 'used': 6062080,
     'devices': [
         {'path': '/dev/sda', 'disk_type': 'HDD', 'health': True,
          'faulty': False, 'missing': False, 'model': 'HUH728080ALE604'},
         {'path': '/dev/sdb', 'disk_type': 'HDD', 'health': True,
          'faulty': False, 'missing': False, 'model': 'HUH728080ALE604'},
     ]},
]
DISKS = [
    {'path': '/dev/nvme0n1', 'model': 'System', 'disk_type': 'SSD', 'health': True},
    {'path': '/dev/sda', 'model': 'HUH728080ALE604', 'disk_type': 'HDD', 'health': True},
    {'path': '/dev/sdb', 'model': 'HUH728080ALE604', 'disk_type': 'HDD', 'health': True},
    {'path': '/dev/nvme1n1', 'model': 'WD Blue SN580 1TB', 'disk_type': 'SSD', 'health': True},
]


def test_build_metrics_healthy():
    m = zimaos.build_metrics(UTIL, STORAGES, RAIDS, DISKS)
    assert m['pool_count'] == 3 and m['pools_healthy'] == 3 and m['pools_degraded'] == 0
    assert m['disk_count'] == 4 and m['alert_count'] == 0
    assert m['cpu_usage_percent'] == 2.7 and m['memory_usage_percent'] == 8.8
    assert m['memory_total_gb'] == 11.5
    assert round(m['storage_total_gb']) == 8488   # sum of all three storages
    names = [p['name'] for p in m['pools']]
    assert names == ['ZimaOS-HD', 'SpinningRust', 'SSD']
    assert m['pools'][1]['status'] == 'RAID1' and m['pools'][1]['healthy']


def test_degraded_raid_flags_pool_and_alerts():
    raids = [dict(RAIDS[0], raid_status='degraded', shortage=True,
                  devices=[RAIDS[0]['devices'][0],
                           dict(RAIDS[0]['devices'][1], missing=True)])]
    m = zimaos.build_metrics(UTIL, STORAGES, raids, DISKS)
    assert m['pools_degraded'] == 1 and m['pools_healthy'] == 2
    p = next(p for p in m['pools'] if p['name'] == 'SpinningRust')
    assert not p['healthy'] and 'degraded' in p['status']
    assert any('RAID status degraded' in a for a in m['alerts'])
    assert any('missing a member' in a for a in m['alerts'])
    assert any('/dev/sdb' in a and 'missing' in a for a in m['alerts'])


def test_unhealthy_storage_and_disk_alert():
    sts = [dict(STORAGES[2], extensions={'health': False, 'size': 1, 'used': 0})]
    disks = [dict(DISKS[0], health=False)]
    m = zimaos.build_metrics(UTIL, sts, [], disks)
    assert m['pools_degraded'] == 1
    assert any('SSD: unhealthy' in a for a in m['alerts'])
    assert any('disk /dev/nvme0n1' in a for a in m['alerts'])


def test_empty_payloads_survive():
    m = zimaos.build_metrics({}, [], [], [])
    assert m['pool_count'] == 0 and m['cpu_usage_percent'] is None
    assert m['storage_total_gb'] == 0 and m['alert_count'] == 0


def test_nas_envelope_from_zimaos_metrics():
    node = {'id': 'z1', 'name': 'zimacube', 'base_url': 'http://192.168.2.5',
            'host_type': 'zimaos'}
    env = app.build_nas_envelope(node, zimaos.build_metrics(UTIL, STORAGES, RAIDS, DISKS))
    assert env['ok'] and env['type_auto'] == 'Storage'
    assert env['nas']['kind'] == 'zimaos' and env['nas']['pools'] == 3
    assert env['resources']['cpu_pct'] == 2.7


def test_zimaos_adapter_registered_and_http_aware():
    a = app._adapter_for({'host_type': 'zimaos'})
    assert a.kind == 'zimaos' and a.auth == 'userpass'
    assert a.default_type == 'Storage' and a.polled
    d = a.descriptor()
    assert d['label'].startswith('ZimaOS') and not d['verify_tls']
    assert d['url_placeholder'].startswith('http://')
    # http base URL → no cert to pin; https → pin path applies
    from adapters.zimaos import _scheme
    assert _scheme('http://192.168.2.5') == 'http'
    assert _scheme('https://zimacube.local') == 'https'
