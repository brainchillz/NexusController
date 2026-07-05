"""VirtAdapter — base for background-polled hosts (hypervisors + NAS): cert
pinning, credential decryption, and the poll cache + poller thread. Subclasses
supply the collector call and the native-UI link. `fetch` (fan-out) reads the
cache; `collect` (poller) does the real API call."""
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import (HostAdapter, NodeError, base_envelope, cert_fingerprint,
                   _split_host_port, decrypt_secret, load_nodes,
                   FANOUT_WORKERS, VIRT_POLL_INTERVAL)

_cache = {}          # node_id -> {'env': envelope, 'ts': float}
_lock = threading.Lock()


def seed_cache(node_id, envelope):
    """Prime the cache from an enroll/edit probe's metrics so the row doesn't
    show 'awaiting first poll' until the next background cycle."""
    with _lock:
        _cache[node_id] = {'env': envelope, 'ts': time.time()}


def evict_cache(node_id):
    """Drop a host's cached poll envelope so the next fan-out reflects a fresh
    poll rather than a stale one (e.g. after a cert re-pin clears a
    fingerprint-mismatch error). No-op if nothing is cached."""
    with _lock:
        _cache.pop(node_id, None)


def build_virt_envelope(node, metrics):
    """Map a collector metric dict (see collectors/*.build_metrics) into the
    fan-out envelope. Pure → unit-tested. Splits LXC containers out of the VM
    list (Proxmox tags them 'lxc-…'); VMware has none. Populates `resources`
    and used/size bytes so the existing CPU/Mem meters + storage rollup light up
    for virt hosts unchanged."""
    out = base_envelope(node)
    vms = metrics.get('vms') or []
    is_ct = lambda v: str(v.get('vm_id', '')).startswith('lxc-')
    running = lambda v: v.get('power_state') in ('running', 'poweredOn')
    containers = [v for v in vms if is_ct(v)]
    guests = [v for v in vms if not is_ct(v)]
    out['ok'] = True
    out['resources'] = {'cpu_pct': metrics.get('cpu_usage_percent'),
                        'memory': {'pct': metrics.get('memory_usage_percent')}}
    out['used_bytes'] = int((metrics.get('storage_used_gb') or 0) * 1024 ** 3)
    out['size_bytes'] = int((metrics.get('storage_total_gb') or 0) * 1024 ** 3)
    out['virt'] = {
        'kind': node.get('host_type'),
        'hosts': metrics.get('host_count') or 0,
        'vms': len(guests), 'vms_running': sum(1 for v in guests if running(v)),
        'containers': len(containers), 'containers_running': sum(1 for v in containers if running(v)),
        'mem_used_gb': round(metrics.get('memory_used_gb') or 0, 1),
        'mem_total_gb': round(metrics.get('memory_total_gb') or 0, 1),
        'storage_used_gb': round(metrics.get('storage_used_gb') or 0, 1),
        'storage_total_gb': round(metrics.get('storage_total_gb') or 0, 1),
        'vm_list': vms,
    }
    out['type_auto'] = 'Virtualization'
    return out


class VirtAdapter(HostAdapter):
    """Base for hypervisor hosts (proxmox/vmware): username+password auth, cert
    pinning, background polling into the cache."""
    auth = 'userpass'
    default_port = 443
    default_type = 'Virtualization'
    polled = True
    supports_write = False       # guest lifecycle actions (start/stop/…)
    VM_ACTIONS = {'start', 'stop', 'shutdown', 'reboot'}

    def envelope(self, node, metrics):
        """Collector metric dict → fan-out envelope (per host-type)."""
        return build_virt_envelope(node, metrics)

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        raise NotImplementedError

    def vm_action(self, node, vm_id, action):
        """Perform a guest (VM/CT) lifecycle action. Re-verifies the pinned
        cert (fail-closed on a changed cert, same as a poll), decrypts creds,
        and delegates to the collector. Returns a task/op label. Raises
        NodeError."""
        if not self.supports_write:
            raise NodeError('guest actions are not supported for this host type')
        if action not in self.VM_ACTIONS:
            raise NodeError('unsupported action: %s' % action)
        host, port = _split_host_port(node['base_url'])
        self._verify_poll_pin(node, host, port)
        pw = decrypt_secret(node.get('password_enc', '')) or ''
        try:
            return self._vm_action(host, port, node.get('username', ''), pw,
                                   bool(node.get('verify_ssl')), vm_id, action)
        except NodeError:
            raise
        except Exception as e:
            raise NodeError(str(e))

    def _vm_action(self, host, port, user, pw, verify_ssl, vm_id, action):
        raise NotImplementedError

    def probe(self, base_url, creds):
        """Validate credentials by doing a real collect + capture the cert
        fingerprint for pinning. Returns identity incl. the initial metrics so
        the caller can seed the cache (no second connect)."""
        creds = creds or {}
        if not creds.get('username') or not creds.get('password'):
            raise NodeError('username and password are required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except OSError as e:   # socket.error / ssl.SSLError are OSError subclasses
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        try:
            metrics = self._collect_metrics(host, port, creds['username'],
                                            creds['password'], bool(creds.get('verify_ssl')))
        except Exception as e:
            raise NodeError(f'connection/credentials rejected: {e}')
        return {'cert_fp': fp, 'role': None, 'version': None, 'fqdn': None,
                'capabilities': [self.kind], 'metrics': metrics}

    def _verify_poll_pin(self, node, host, port):
        """Pre-poll pin check. The collector libraries (proxmoxer/pyVmomi/
        websocket-client) own their own connections, so unlike NodeClient this
        cannot pin in-handshake — it fails closed on a changed cert but keeps
        the enroll-time TOFU model. Set verify_ssl for full CA verification."""
        if node.get('cert_fp'):
            live = cert_fingerprint(host, port)
            if live != node['cert_fp']:
                raise NodeError('certificate fingerprint changed for %s:%s '
                                '(pinned %s…, saw %s…)'
                                % (host, port, node['cert_fp'][:16], live[:16]))

    def collect(self, node):
        """Poller entry point: verify the pinned cert, decrypt creds, poll the
        hypervisor, and return an envelope. Never raises."""
        try:
            host, port = _split_host_port(node['base_url'])
            self._verify_poll_pin(node, host, port)
            pw = decrypt_secret(node.get('password_enc', '')) or ''
            metrics = self._collect_metrics(host, port, node.get('username', ''),
                                            pw, bool(node.get('verify_ssl')))
            return self.envelope(node, metrics)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def fetch(self, node):
        """Fan-out: serve this host's last polled envelope from the cache."""
        with _lock:
            entry = _cache.get(node['id'])
        if not entry:
            out = base_envelope(node)
            out['error'] = 'awaiting first poll'
            out['type_auto'] = self.default_type
            return out
        env = dict(entry['env'])
        # Reflect live registry metadata (type/tags edits shouldn't wait a poll).
        env['type'] = node.get('type', self.default_type)
        env['type_pinned'] = node.get('type_pinned', False)
        env['tags'] = node.get('tags', [])
        env['stale'] = (time.time() - entry['ts']) > VIRT_POLL_INTERVAL * 3
        return env

    def native_url(self, node):
        # Virt hosts serve their own native UI; the browser reaches it directly.
        return node['base_url'] + '/'


def _is_virt(node):
    """True when this host is served by the background poller. Keyed off the
    adapter's `polled` flag, NOT host_type != nexus — live-fetched types like
    the bare-Linux agent must never be swept into the poller."""
    from . import adapter_for
    return adapter_for(node).polled


def _poll_once():
    from . import adapter_for   # runtime import — registry lives in the package root
    nodes = [n for n in load_nodes().get('nodes', []) if _is_virt(n)]
    ids = {n['id'] for n in nodes}
    if nodes:
        with ThreadPoolExecutor(max_workers=FANOUT_WORKERS) as pool:
            futs = {pool.submit(adapter_for(n).collect, n): n for n in nodes}
            for fut in as_completed(futs):
                n = futs[fut]
                with _lock:
                    _cache[n['id']] = {'env': fut.result(), 'ts': time.time()}
    with _lock:  # drop cache entries for removed hosts
        for k in [k for k in _cache if k not in ids]:
            del _cache[k]


def _poller_loop():
    while True:
        try:
            _poll_once()
        except Exception:
            pass  # a poll cycle must never kill the poller thread
        time.sleep(VIRT_POLL_INTERVAL)


def start_virt_poller():
    threading.Thread(target=_poller_loop, daemon=True, name='virt-poller').start()
