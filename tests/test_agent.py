"""nexus-agent parsers (pure, stdlib) + the controller's agent adapter."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'agent'))
import nexus_agent   # noqa: E402
import app           # noqa: E402


def test_cpu_percent_from_proc_stat_delta():
    prev = nexus_agent.parse_proc_stat('cpu  100 0 100 700 100 0 0 0 0 0\n')
    cur = nexus_agent.parse_proc_stat('cpu  200 0 200 1500 200 0 0 0 0 0\n')
    # idle delta = (1500+200)-(700+100)=900; total delta = 2300-1000=1300... let's compute
    pct = nexus_agent.cpu_percent(prev, cur)
    assert pct is not None and 0 <= pct <= 100
    # all-idle delta → 0%
    a = nexus_agent.parse_proc_stat('cpu  100 0 100 1000 0 0 0 0 0 0\n')
    b = nexus_agent.parse_proc_stat('cpu  100 0 100 2000 0 0 0 0 0 0\n')
    assert nexus_agent.cpu_percent(a, b) == 0.0
    assert nexus_agent.cpu_percent(None, b) is None


def test_parse_meminfo():
    m = nexus_agent.parse_meminfo('MemTotal: 16384000 kB\nMemAvailable: 8192000 kB\n')
    assert m['total'] == 16384000 * 1024
    assert m['available'] == 8192000 * 1024
    assert m['percent'] == 50.0
    assert nexus_agent.parse_meminfo('')['percent'] is None


MOUNTS = """\
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/vda1 / ext4 rw,relatime 0 0
/dev/vda1 /home/bind ext4 rw,relatime 0 0
/dev/vdb1 /data xfs rw 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
/dev/loop3 /snap/core/1 squashfs ro 0 0
192.168.1.9:/export /mnt/nfs nfs4 rw 0 0
tmpfs /run/user/1000 tmpfs rw 0 0
"""


def test_parse_mounts_filters_and_dedupes():
    got = nexus_agent.parse_mounts(MOUNTS)
    mps = sorted(mp for _, mp, _ in got)
    assert mps == ['/', '/data', '/mnt/nfs']    # bind dup + pseudo fs dropped
    assert ('192.168.1.9:/export', '/mnt/nfs', 'nfs4') in got


def test_mount_usage_with_fake_statvfs():
    class SV:
        f_blocks, f_bfree, f_frsize = 1000, 250, 4096
    out = nexus_agent.mount_usage([('/dev/vda1', '/', 'ext4')], statvfs=lambda p: SV())
    assert out == [{'device': '/dev/vda1', 'mountpoint': '/', 'fstype': 'ext4',
                    'total': 4096000, 'used': 3072000, 'free': 1024000,
                    'percent': 75.0}]

    def boom(p):
        raise OSError('stale NFS')
    assert nexus_agent.mount_usage([('x', '/dead', 'nfs')], statvfs=boom) == []


PAYLOAD = {
    'agent': 'nexus-agent', 'version': '1.0.0', 'platform': 'linux',
    'hostname': 'otn-storage', 'os': 'Ubuntu 24.04.2 LTS', 'kernel': '6.8.0-59-generic',
    'uptime_seconds': 86400 * 3,
    'cpu': {'percent': 12.5, 'count': 4, 'load1': 0.42},
    'memory': {'total': 8 * 1024**3, 'available': 6 * 1024**3,
               'used': 2 * 1024**3, 'percent': 25.0},
    'mounts': [
        {'device': '/dev/vda1', 'mountpoint': '/', 'fstype': 'ext4',
         'total': 100 * 1024**3, 'used': 40 * 1024**3, 'free': 60 * 1024**3, 'percent': 40.0},
        {'device': '/dev/vdb1', 'mountpoint': '/data', 'fstype': 'xfs',
         'total': 400 * 1024**3, 'used': 100 * 1024**3, 'free': 300 * 1024**3, 'percent': 25.0},
    ],
}


def test_agent_envelope():
    node = {'id': 'a1', 'name': '.88 canary', 'base_url': 'https://192.168.1.88:9143',
            'host_type': 'agent'}
    env = app.build_agent_envelope(node, PAYLOAD)
    assert env['ok'] and env['version'] == '1.0.0'
    assert env['resources'] == {'cpu_pct': 12.5, 'memory': {'pct': 25.0}}
    assert env['used_bytes'] == 140 * 1024**3 and env['size_bytes'] == 500 * 1024**3
    a = env['agent']
    assert a['mounts'] == 2 and a['os'].startswith('Ubuntu') and a['load1'] == 0.42
    assert env['type_auto'] == 'Unknown'


def test_agent_adapter_registered_live_fetch():
    a = app._adapter_for({'host_type': 'agent'})
    assert a.kind == 'agent' and a.auth == 'token'
    assert a.polled is False        # live fan-out — the poller must skip it
    d = a.descriptor()
    assert d['label'].startswith('Nexus Agent') and not d['verify_tls']


def test_poller_skips_live_fetched_types():
    from adapters.virt import _is_virt
    assert _is_virt({'host_type': 'proxmox'})
    assert _is_virt({'host_type': 'truenas'})
    assert not _is_virt({'host_type': 'agent'})
    assert not _is_virt({'host_type': 'nexus'})
    assert not _is_virt({})


def test_seed_cache_noops_for_live_fetched_types():
    # Enrolling an agent must not touch the poll cache (its adapter has no
    # envelope()) — this 500'd the very first live enroll.
    node = {'id': 'ax', 'name': 'a', 'base_url': 'https://h:9143', 'host_type': 'agent'}
    app._virt_seed_cache(node, PAYLOAD)   # must not raise
    from adapters import virt
    with virt._lock:
        assert 'ax' not in virt._cache


def test_agent_envelope_windows_payload():
    # The Windows agent (nexus_agent.ps1) speaks the same contract; the
    # envelope must handle its shape (no load1, drive-letter mounts).
    payload = {
        'agent': 'nexus-agent', 'version': '1.0.0', 'platform': 'windows',
        'hostname': 'WIN-HVJH71TH5QA', 'os': 'Microsoft Windows Server 2025 Datacenter',
        'kernel': '10.0.26100', 'arch': '64-bit', 'uptime_seconds': 3601973,
        'cpu': {'percent': 6, 'count': 4, 'load1': None},
        'memory': {'total': 17178873856, 'available': 13126316032,
                   'used': 4052557824, 'percent': 23.6},
        'mounts': [{'device': 'C:', 'mountpoint': 'C:\\', 'fstype': 'NTFS',
                    'total': 106320359424, 'used': 24539533312,
                    'free': 81780826112, 'percent': 23.1}],
    }
    node = {'id': 'w1', 'name': 'win2025', 'base_url': 'https://192.168.1.129:9143',
            'host_type': 'agent'}
    env = app.build_agent_envelope(node, payload)
    assert env['ok'] and env['agent']['platform'] == 'windows'
    assert env['agent']['load1'] is None and env['agent']['mounts'] == 1
    assert env['size_bytes'] == 106320359424
    assert env['resources']['cpu_pct'] == 6
