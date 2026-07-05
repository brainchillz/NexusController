"""Synology DSM collector: pure build_metrics transform + adapter wiring.
Fixtures follow the documented DSM Web API shapes (sizes are strings,
memory_size is KB, volume status 'normal'). No network."""
import app
from collectors import synology


INFO = {'model': 'DS920+', 'firmware_ver': 'DSM 7.2.1-69057 Update 5',
        'hostname': 'syno'}
UTIL = {'cpu': {'user_load': 3, 'system_load': 2, 'other_load': 1},
        'memory': {'real_usage': 24, 'memory_size': 4194304}}   # KB → 4 GB
STORAGE = {
    'volumes': [
        {'id': 'volume_1', 'display_name': 'Volume 1', 'status': 'normal',
         'size': {'total': '3897496567808', 'used': '2529148383232'}},
    ],
    'disks': [
        {'id': 'sata1', 'name': 'Drive 1', 'status': 'normal', 'smart_status': 'normal'},
        {'id': 'sata2', 'name': 'Drive 2', 'status': 'normal', 'smart_status': 'normal'},
    ],
}


def test_build_metrics_healthy():
    m = synology.build_metrics(INFO, UTIL, STORAGE)
    assert m['hostname'] == 'syno' and m['model'] == 'DS920+'
    assert m['version'].startswith('DSM 7.2.1')
    assert m['pool_count'] == 1 and m['pools_healthy'] == 1 and m['pools_degraded'] == 0
    assert m['disk_count'] == 2 and m['alert_count'] == 0
    assert m['cpu_usage_percent'] == 5.0          # user + system, not other
    assert m['memory_usage_percent'] == 24
    assert m['memory_total_gb'] == 4.0            # memory_size is KB
    assert round(m['storage_total_gb']) == 3630   # string bytes parsed
    assert m['pools'][0]['name'] == 'Volume 1' and m['pools'][0]['healthy']


def test_build_metrics_degraded_volume_alerts():
    st = {'volumes': [dict(STORAGE['volumes'][0], status='degraded')],
          'disks': STORAGE['disks']}
    m = synology.build_metrics(INFO, UTIL, st)
    assert m['pools_degraded'] == 1 and m['pools_healthy'] == 0
    assert m['alert_count'] == 1 and 'degraded' in m['alerts'][0]


def test_build_metrics_bad_disk_alerts():
    st = {'volumes': STORAGE['volumes'],
          'disks': [dict(STORAGE['disks'][0], smart_status='warning')]}
    m = synology.build_metrics(INFO, UTIL, st)
    assert m['pools_degraded'] == 0               # volume fine
    assert m['alert_count'] == 1 and 'Drive 1' in m['alerts'][0]


def test_build_metrics_empty_payloads_survive():
    m = synology.build_metrics({}, {}, {})
    assert m['pool_count'] == 0 and m['disk_count'] == 0
    assert m['cpu_usage_percent'] is None and m['storage_total_gb'] == 0
    assert m['version'] is None


def test_nas_envelope_from_synology_metrics():
    node = {'id': 'y1', 'name': 'syno', 'base_url': 'https://192.168.2.1:5001',
            'host_type': 'synology'}
    m = synology.build_metrics(INFO, UTIL, STORAGE)
    env = app.build_nas_envelope(node, m)
    assert env['ok'] and env['type_auto'] == 'Storage'
    assert env['nas']['pools'] == 1 and env['nas']['kind'] == 'synology'
    assert env['resources']['cpu_pct'] == 5.0


def test_synology_adapter_registered():
    a = app._adapter_for({'host_type': 'synology'})
    assert a.kind == 'synology' and a.auth == 'userpass'
    assert a.default_type == 'Storage' and a.polled
    d = a.descriptor()
    assert d['label'].startswith('Synology') and d['verify_tls']
