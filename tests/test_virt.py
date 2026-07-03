"""Virtualization host adapters — pure-function tests (no hypervisor needed).

Covers the Proxmox collector's build_metrics transform and app.build_virt_envelope
(the collector-dict → fan-out-envelope mapping), plus that compute_rollup tolerates
a virt envelope (no `summary`, but storage still sums)."""
import app
from collectors import proxmox, vmware


class _Obj:
    """Stub for a pyVmomi managed object (build_metrics only reads ._moId)."""
    def __init__(self, moid):
        self._moId = moid

# One Proxmox node: 2 QEMU VMs (1 running) + 1 LXC container (running),
# 2/8 GiB RAM used, 100/500 GiB storage used.
BLOBS = [{
    'node': 'pve1',
    'status': {'cpu': 0.10, 'memory': {'used': 2 * 1024 ** 3, 'total': 8 * 1024 ** 3}},
    'storages': [{'used': 100 * 1024 ** 3, 'total': 500 * 1024 ** 3}],
    'qemus': [
        {'vmid': 100, 'name': 'web', 'status': 'running', 'cpus': 2, 'maxmem': 2 * 1024 ** 3},
        {'vmid': 101, 'name': 'db', 'status': 'stopped', 'cpus': 4, 'maxmem': 4 * 1024 ** 3},
    ],
    'containers': [
        {'vmid': 200, 'name': 'dns', 'status': 'running', 'cpus': 1, 'maxmem': 512 * 1024 ** 2},
    ],
}]

VIRT_NODE = {'id': 'abc', 'name': 'pve', 'base_url': 'https://h:8006',
             'host_type': 'proxmox', 'type': 'Virtualization', 'type_pinned': False, 'tags': []}


def test_proxmox_build_metrics_counts_and_ratios():
    m = proxmox.build_metrics(BLOBS)
    assert m['host_count'] == 1
    assert m['vm_count'] == 3                 # 2 qemu + 1 lxc merged into vms
    assert m['vm_running_count'] == 2         # web + dns
    assert m['memory_usage_percent'] == 25.0  # 2/8 GiB
    assert m['storage_usage_percent'] == 20.0
    assert round(m['cpu_usage_percent'], 1) == 10.0
    assert len(m['vms']) == 3


def test_proxmox_build_metrics_empty():
    m = proxmox.build_metrics([])
    assert m['host_count'] == 0
    assert m['vm_count'] == 0
    assert m['cpu_usage_percent'] is None      # avoid div-by-zero
    assert m['memory_usage_percent'] is None


def test_build_virt_envelope_splits_containers_from_vms():
    env = app.build_virt_envelope(VIRT_NODE, proxmox.build_metrics(BLOBS))
    assert env['ok'] is True
    assert env['host_type'] == 'proxmox'
    assert env['type_auto'] == 'Virtualization'
    v = env['virt']
    assert v['vms'] == 2 and v['vms_running'] == 1            # qemu only
    assert v['containers'] == 1 and v['containers_running'] == 1
    assert v['hosts'] == 1
    # resources feed the existing CPU/Mem meters; bytes feed the storage rollup
    assert env['resources']['cpu_pct'] is not None
    assert env['resources']['memory']['pct'] == 25.0
    assert env['used_bytes'] == 100 * 1024 ** 3
    assert env['size_bytes'] == 500 * 1024 ** 3


def test_compute_rollup_tolerates_virt_envelope():
    env = app.build_virt_envelope(VIRT_NODE, proxmox.build_metrics(BLOBS))
    r = app.compute_rollup([env])
    assert r['healthy'] == 1 and r['unreachable'] == 0
    assert r['alerts'] == 0 and r['services_down'] == 0   # no nexus summary
    assert r['storage_used'] == 100 * 1024 ** 3
    assert r['storage_size'] == 500 * 1024 ** 3
    # VM/CT counts fold into the fleet rollup (2 qemu + 1 lxc = 3 guests, 1 CT)
    assert r['vms'] == 3 and r['containers'] == 1


def test_vmware_build_metrics_ratios_and_hostnames():
    h1 = _Obj('host-1')
    hosts = [{'_obj': h1, 'name': 'esxi1',
              'hardware.cpuInfo.numCpuCores': 8,
              'hardware.cpuInfo.hz': 2_000_000_000,               # 2 GHz → 16000 MHz total
              'hardware.memorySize': 16 * 1024 ** 3,
              'summary.quickStats.overallCpuUsage': 1600,          # MHz used → 10%
              'summary.quickStats.overallMemoryUsage': 4096}]      # MB used → 4/16 GiB = 25%
    vms = [
        {'_obj': _Obj('vm-1'), 'name': 'web', 'runtime.powerState': 'poweredOn',
         'config.hardware.numCPU': 2, 'config.hardware.memoryMB': 4096,
         'config.guestFullName': 'Ubuntu', 'runtime.host': h1},
        {'_obj': _Obj('vm-2'), 'name': 'db', 'runtime.powerState': 'poweredOff',
         'config.hardware.numCPU': 4, 'config.hardware.memoryMB': 8192,
         'config.guestFullName': 'Windows', 'runtime.host': h1},
    ]
    datastores = [{'summary.capacity': 1000 * 1024 ** 3, 'summary.freeSpace': 250 * 1024 ** 3}]  # 75% used
    m = vmware.build_metrics(hosts, vms, datastores, {'host-1': 'esxi1'})
    assert m['host_count'] == 1
    assert m['vm_count'] == 2 and m['vm_running_count'] == 1
    assert round(m['cpu_usage_percent'], 1) == 10.0
    assert round(m['memory_usage_percent'], 1) == 25.0
    assert round(m['storage_usage_percent'], 1) == 75.0
    assert m['vms'][0]['host_name'] == 'esxi1'   # runtime.host resolved via host_names


def test_build_virt_envelope_vmware_has_no_containers():
    node = {'id': 'v', 'name': 'vc', 'base_url': 'https://vc:443',
            'host_type': 'vcenter', 'type': 'Virtualization', 'tags': []}
    h = _Obj('h')
    hosts = [{'_obj': h, 'name': 'e', 'hardware.cpuInfo.numCpuCores': 4,
              'hardware.cpuInfo.hz': 2_000_000_000, 'hardware.memorySize': 8 * 1024 ** 3,
              'summary.quickStats.overallCpuUsage': 800,
              'summary.quickStats.overallMemoryUsage': 2048}]
    vms = [{'_obj': _Obj('vm1'), 'name': 'a', 'runtime.powerState': 'poweredOn', 'runtime.host': h}]
    env = app.build_virt_envelope(node, vmware.build_metrics(hosts, vms, [], {'h': 'e'}))
    assert env['virt']['containers'] == 0
    assert env['virt']['vms'] == 1 and env['virt']['vms_running'] == 1


def test_adapter_dispatch_defaults_to_nexus():
    assert app._adapter_for({}).kind == 'nexus'
    assert app._adapter_for({'host_type': 'nexus'}).kind == 'nexus'
    assert app._adapter_for({'host_type': 'proxmox'}).kind == 'proxmox'
    assert app._adapter_for({'host_type': 'vcenter'}).kind == 'vcenter'
    assert app._adapter_for({'host_type': 'esxi'}).kind == 'esxi'


def test_public_node_strips_password():
    n = {'id': '1', 'name': 'pve', 'host_type': 'proxmox',
         'username': 'root@pam', 'password_enc': 'secret-ciphertext', 'token_enc': 'x'}
    pub = app._public_node(n)
    assert 'password_enc' not in pub and 'token_enc' not in pub
    assert pub['username'] == 'root@pam'   # username is not a secret
