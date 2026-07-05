"""Unraid collector: pure build_metrics transform + adapter wiring. The
pool-only fixture is trimmed from the live MiniRackUnraid (Unraid 7.3, no
parity array — all storage in cache pools); the array fixture is synthetic.
No network."""
import app
from collectors import unraid


LIVE = {   # MiniRackUnraid: pools only, empty parity array
    'info': {'os': {'distro': 'Unraid OS', 'release': '7.3 x86_64',
                    'hostname': 'MiniRackUnraid'}},
    'metrics': {'cpu': {'percentTotal': 7.06},
                'memory': {'percentTotal': 9.24, 'total': 16540282880, 'used': 3373436928}},
    'array': {
        'state': 'STARTED',
        'capacity': {'kilobytes': {'free': '0', 'used': '0', 'total': '0'}},
        'disks': [], 'parities': [],
        'caches': [
            {'name': 'nvme', 'status': 'DISK_OK',
             'fsSize': 5666806693, 'fsUsed': 109967985, 'fsFree': 5556838708},
            {'name': 'nvme2', 'status': 'DISK_OK', 'fsSize': None, 'fsUsed': None, 'fsFree': None},
            {'name': 'sata', 'status': 'DISK_OK',
             'fsSize': 3861712470, 'fsUsed': 9522192, 'fsFree': 3852190278},
            {'name': 'sata2', 'status': 'DISK_OK', 'fsSize': None, 'fsUsed': None, 'fsFree': None},
        ],
    },
    'notifications': {'overview': {'unread': {'alert': 0, 'warning': 0, 'total': 0}}},
}

ARRAYED = {   # classic Unraid: parity array + one cache pool
    'info': {'os': {'distro': 'Unraid OS', 'release': '7.3 x86_64', 'hostname': 'tower'}},
    'metrics': {'cpu': {'percentTotal': 12.0},
                'memory': {'percentTotal': 50.0, 'total': 8 * 1024**3, 'used': 4 * 1024**3}},
    'array': {
        'state': 'STARTED',
        'capacity': {'kilobytes': {'free': '2000000000', 'used': '6000000000',
                                   'total': '8000000000'}},
        'disks': [{'name': 'disk1', 'status': 'DISK_OK'},
                  {'name': 'disk2', 'status': 'DISK_OK'}],
        'parities': [{'name': 'parity', 'status': 'DISK_OK'}],
        'caches': [{'name': 'cache', 'status': 'DISK_OK',
                    'fsSize': 500000000, 'fsUsed': 250000000, 'fsFree': 250000000}],
    },
    'notifications': {'overview': {'unread': {'alert': 0, 'warning': 2, 'total': 2}}},
}


def test_pool_only_box():
    m = unraid.build_metrics(LIVE)
    assert m['hostname'] == 'MiniRackUnraid' and m['version'] == 'Unraid 7.3'
    # mounted pools only — null-fsSize members are not pools
    assert m['pool_count'] == 2 and m['pools_healthy'] == 2 and m['pools_degraded'] == 0
    assert [p['name'] for p in m['pools']] == ['nvme', 'sata']
    assert m['alert_count'] == 0
    assert m['cpu_usage_percent'] == 7.1 and m['memory_usage_percent'] == 9.2
    # kilobyte units → GB
    assert round(m['storage_total_gb']) == round((5666806693 + 3861712470) * 1024 / 1024**3)
    assert m['disk_count'] == 4    # every member counts as a disk


def test_parity_array_plus_cache():
    m = unraid.build_metrics(ARRAYED)
    assert m['pool_count'] == 2
    arr = next(p for p in m['pools'] if p['name'] == 'array')
    assert arr['healthy'] and arr['used_pct'] == 75.0
    assert round(m['storage_total_gb']) == round(8500000000 * 1024 / 1024**3)
    # unread warnings surface as an alert line
    assert m['alert_count'] == 1 and 'warning notification' in m['alerts'][0]


def test_degraded_array_and_bad_disk():
    d = {**ARRAYED, 'array': {**ARRAYED['array'],
         'disks': [{'name': 'disk1', 'status': 'DISK_OK'},
                   {'name': 'disk2', 'status': 'DISK_DSBL'}]}}
    m = unraid.build_metrics(d)
    arr = next(p for p in m['pools'] if p['name'] == 'array')
    assert not arr['healthy'] and m['pools_degraded'] == 1
    assert any('disk2: DISK_DSBL' in a for a in m['alerts'])


def test_stopped_array_no_capacity_alerts():
    d = {**LIVE, 'array': {**LIVE['array'], 'state': 'STOPPED'}}
    m = unraid.build_metrics(d)
    assert any('array state: STOPPED' in a for a in m['alerts'])


def test_empty_payload_survives():
    m = unraid.build_metrics({})
    assert m['pool_count'] == 0 and m['cpu_usage_percent'] is None
    assert m['storage_total_gb'] == 0


def test_unraid_adapter_registered():
    a = app._adapter_for({'host_type': 'unraid'})
    assert a.kind == 'unraid' and a.auth == 'userpass'
    assert a.default_type == 'Storage' and a.polled
    d = a.descriptor()
    assert d['label'].startswith('Unraid') and d['url_placeholder'].startswith('http://')
