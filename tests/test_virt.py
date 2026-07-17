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


# ── guest write actions ───────────────────────────────────────────────
def test_proxmox_adapter_parses_guest_id(monkeypatch):
    from adapters.proxmox import ProxmoxAdapter
    seen = {}
    def fake(host, user, pw, node_name, kind, vmid, action, port=8006, verify_ssl=False):
        seen.update(node=node_name, kind=kind, vmid=vmid, action=action)
        return 'UPID:task'
    monkeypatch.setattr(proxmox, 'vm_action', fake)
    a = ProxmoxAdapter()
    # a node name that itself contains a hyphen must still parse (vmid = trailing int)
    a._vm_action('h', 8006, 'root@pam', 'pw', False, 'qemu-pve-01-100', 'reboot')
    assert seen == {'node': 'pve-01', 'kind': 'qemu', 'vmid': '100', 'action': 'reboot'}
    a._vm_action('h', 8006, 'root@pam', 'pw', False, 'lxc-pve1-200', 'stop')
    assert seen['kind'] == 'lxc' and seen['vmid'] == '200'


def test_proxmox_adapter_rejects_bad_guest_id(monkeypatch):
    from adapters.proxmox import ProxmoxAdapter
    from adapters.base import NodeError
    import pytest
    monkeypatch.setattr(proxmox, 'vm_action', lambda *a, **k: 'x')
    a = ProxmoxAdapter()
    for bad in ('bogus', 'qemu-pve', 'qemu-pve-notanum', 'kvm-pve-1'):
        with pytest.raises(NodeError):
            a._vm_action('h', 8006, 'u', 'p', False, bad, 'start')


def test_vm_action_endpoint(client, monkeypatch):
    import app as A
    from collectors import proxmox as P
    with client.session_transaction() as s:
        s['user'] = 'admin'
    cfg = A.load_config(); cfg.setdefault('users', {})['admin'] = {
        'password': A.generate_password_hash('x' * 10), 'role': 'admin'}
    A.save_config(cfg)
    A.save_nodes({'nodes': [{'id': 'p1', 'name': 'pve', 'host_type': 'proxmox',
                             'base_url': 'https://10.0.0.5:8006',
                             'username': 'root@pam',
                             'password_enc': A.encrypt_secret('pw')}]})   # no cert_fp → pin check skipped
    calls = []
    monkeypatch.setattr(P, 'vm_action',
                        lambda *a, **k: (calls.append(a) or 'UPID:done'))
    r = client.post('/api/nodes/p1/vm/qemu-pve-100/reboot')
    assert r.status_code == 200 and r.get_json()['task'] == 'UPID:done'
    assert calls and calls[0][4] == 'qemu' and calls[0][6] == 'reboot'
    # bad action → 400
    assert client.post('/api/nodes/p1/vm/qemu-pve-100/destroy').status_code == 400
    # unknown node → 404
    assert client.post('/api/nodes/nope/vm/x/start').status_code == 404


def test_vm_action_rejected_on_nonvirt_host(client, monkeypatch):
    import app as A
    with client.session_transaction() as s:
        s['user'] = 'admin'
    cfg = A.load_config(); cfg.setdefault('users', {})['admin'] = {
        'password': A.generate_password_hash('x' * 10), 'role': 'admin'}
    A.save_config(cfg)
    A.save_nodes({'nodes': [{'id': 'a1', 'name': 'node1', 'host_type': 'agent',
                             'base_url': 'https://10.0.0.6:9143'}]})
    assert client.post('/api/nodes/a1/vm/x/start').status_code == 400


def test_vm_action_viewer_blocked(client, monkeypatch):
    import app as A
    with client.session_transaction() as s:
        s['user'] = 'ro'
    cfg = A.load_config(); cfg.setdefault('users', {})['ro'] = {
        'password': A.generate_password_hash('x' * 10), 'role': 'viewer'}
    A.save_config(cfg)
    A.save_nodes({'nodes': [{'id': 'p2', 'name': 'pve', 'host_type': 'proxmox',
                             'base_url': 'https://10.0.0.5:8006'}]})
    assert client.post('/api/nodes/p2/vm/qemu-pve-100/start').status_code == 403


# ── task-result waits: async hypervisor failures must surface ────────
class _VmwTaskInfo:
    def __init__(self, state, msg=None):
        self.state = state
        self.error = type('E', (), {'localizedMessage': msg})() if msg else None


class _VmwTask:
    def __init__(self, states):
        self._states = list(states)

    @property
    def info(self):
        return _VmwTaskInfo(*self._states.pop(0)) if len(self._states) > 1 \
            else _VmwTaskInfo(*self._states[0])


def test_vmware_wait_task_error_raises_with_message():
    task = _VmwTask([('error', 'The operation is not allowed in the current state.')])
    try:
        vmware._wait_task(task, timeout=1)
        assert False, 'expected RuntimeError'
    except RuntimeError as e:
        assert 'not allowed' in str(e)


def test_vmware_wait_task_success_returns():
    vmware._wait_task(_VmwTask([('running', None), ('success', None)]), timeout=5)


def test_vmware_wait_task_still_running_at_timeout_is_ok():
    vmware._wait_task(_VmwTask([('running', None)]), timeout=0)


class _PxNode:
    def __init__(self, doc):
        self._doc = doc

    def tasks(self, upid):
        status = type('S', (), {'get': lambda s: self._doc})()
        return type('T', (), {'status': status})()


def test_proxmox_wait_task_failure_raises():
    node = _PxNode({'status': 'stopped', 'exitstatus': 'CT is locked (snapshot)'})
    try:
        proxmox._wait_task(node, 'UPID:x', timeout=1)
        assert False, 'expected RuntimeError'
    except RuntimeError as e:
        assert 'locked' in str(e)


def test_proxmox_wait_task_ok():
    proxmox._wait_task(_PxNode({'status': 'stopped', 'exitstatus': 'OK'}), 'UPID:x', timeout=1)


def test_proxmox_wait_task_still_running_at_timeout_is_ok():
    proxmox._wait_task(_PxNode({'status': 'running'}), 'UPID:x', timeout=0)
