"""OpenMediaVault collector: pure build_metrics transform + adapter wiring.
Fixtures trimmed from the live pinas box (OMV 8.5 on a Raspberry Pi 5,
raid5 md0 + SMART-incapable USB boot stick). No network."""
import app
from collectors import omv


INFO = {'hostname': 'pinas', 'version': '8.5.0-3 (Synchrony)',
        'cpuModelName': 'Raspberry Pi 5 Model B Rev 1.0',
        'cpuUtilization': 0.5, 'memTotal': '8454029312', 'memUsed': '542113792',
        'uptime': 4117.96, 'loadAverage': {'1min': 0.04}}
FILESYSTEMS = [
    {'devicename': 'md0', 'canonicaldevicefile': '/dev/md0',
     'parentdevicefile': '/dev/md0', 'label': '', 'type': 'ext4',
     'mounted': True, 'used': '2.04 MiB',   # human string — must be ignored
     'available': '1475202334720', 'size': '1475221258240',
     'percentage': 1, 'status': 1},
]
RAIDS = [
    {'devicefile': '/dev/md0', 'level': 'raid5', 'numdevices': 4,
     'devices': ['/dev/sdb', '/dev/sdc', '/dev/sdd', '/dev/sde'],
     'size': '1499917713408', 'state': 'clean'},
]
SMART = [
    {'devicename': 'sda', 'model': 'USB Flash Drive', 'monitor': False,
     'overallstatus': 'BAD_STATUS'},   # SMART-incapable boot stick: no alert
    {'devicename': 'sdb', 'model': 'WDC WDS500G2B0A', 'monitor': False, 'overallstatus': 'GOOD'},
    {'devicename': 'sdc', 'model': 'WD Blue SA510', 'monitor': False, 'overallstatus': 'GOOD'},
    {'devicename': 'sdd', 'model': 'WDC WDS500G2B0A', 'monitor': False, 'overallstatus': 'GOOD'},
    {'devicename': 'sde', 'model': 'WDC WDS500G2B0A', 'monitor': False, 'overallstatus': 'GOOD'},
]


def test_healthy_box():
    m = omv.build_metrics(INFO, FILESYSTEMS, RAIDS, SMART)
    assert m['hostname'] == 'pinas' and m['version'] == 'OMV 8.5.0-3'
    assert m['model'].startswith('Raspberry Pi 5')
    assert m['pool_count'] == 1 and m['pools_healthy'] == 1 and m['pools_degraded'] == 0
    p = m['pools'][0]
    assert p['name'] == 'md0' and p['status'] == 'raid5 clean' and p['healthy']
    # used computed from size-available (the 'used' field is a human string)
    assert round(m['storage_used_gb'], 2) == round((1475221258240 - 1475202334720) / 1024**3, 2)
    assert m['disk_count'] == 5
    assert m['alert_count'] == 0      # unmonitored BAD_STATUS stick stays quiet
    assert m['cpu_usage_percent'] == 0.5 and m['memory_usage_percent'] == 6.4


def test_degraded_raid():
    raids = [dict(RAIDS[0], state='clean, degraded')]
    m = omv.build_metrics(INFO, FILESYSTEMS, raids, SMART)
    assert m['pools_degraded'] == 1
    assert m['pools'][0]['status'] == 'raid5 clean, degraded'
    assert any('RAID state clean, degraded' in a for a in m['alerts'])


def test_unmounted_filesystem_alerts():
    fs = [dict(FILESYSTEMS[0], mounted=False)]
    m = omv.build_metrics(INFO, fs, [], SMART)
    assert m['pools_degraded'] == 1
    assert any('not healthy' in a for a in m['alerts'])


def test_monitored_smart_failure_alerts():
    smart = [dict(SMART[1], monitor=True, overallstatus='BAD_ATTRIBUTE_NOW')]
    m = omv.build_metrics(INFO, FILESYSTEMS, RAIDS, smart)
    assert any('SMART BAD_ATTRIBUTE_NOW' in a for a in m['alerts'])


def test_raid_without_filesystem_still_alerts():
    raids = [dict(RAIDS[0], devicefile='/dev/md1', state='inactive')]
    m = omv.build_metrics(INFO, FILESYSTEMS, raids, SMART)
    assert any('/dev/md1: RAID state inactive' in a for a in m['alerts'])


def test_empty_payloads_survive():
    m = omv.build_metrics({}, [], [], [])
    assert m['pool_count'] == 0 and m['cpu_usage_percent'] is None
    assert m['storage_total_gb'] == 0 and m['version'] is None


def test_omv_adapter_registered():
    a = app._adapter_for({'host_type': 'omv'})
    assert a.kind == 'omv' and a.auth == 'userpass'
    assert a.default_type == 'Storage' and a.polled
    d = a.descriptor()
    assert d['label'] == 'OpenMediaVault' and d['url_placeholder'].startswith('http://')
