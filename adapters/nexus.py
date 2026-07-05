"""NexusAdapter — a single-host Nexus Dashboard node over its token-authed
REST API, plus the node-type classification heuristics."""
import re

from .base import (HostAdapter, NodeClient, NodeError, base_envelope,
                   cert_fingerprint, pinned_request, _split_host_port,
                   NODE_TIMEOUT)

# Nodes report ZFS used/size as human strings (e.g. "1.2T") from the node's
# _human_bytes (suffixes B/K/M/G/T/P). Parse them back to bytes so the
# controller can sum fleet-wide storage.
_UNIT_MULT = {'B': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3,
              'T': 1024 ** 4, 'P': 1024 ** 5}


def parse_human_bytes(s):
    if not s:
        return 0
    m = re.match(r'^\s*([\d.]+)\s*([BKMGTP])?\s*$', str(s))
    if not m:
        return 0
    return int(float(m.group(1)) * _UNIT_MULT.get(m.group(2) or 'B', 1))


def probe_node(base_url, token):
    """Test-connection at enroll: capture cert fingerprint, validate the token
    via /api/me, return role + version + capabilities. Raises NodeError.
    TOFU: the fingerprint captured here pins the very request that validates
    the token (in-handshake), so there is no unpinned window."""
    host, port = _split_host_port(base_url)
    if not host:
        raise NodeError('invalid base URL')
    try:
        fp = cert_fingerprint(host, port)
    except OSError as e:
        raise NodeError(f'cannot reach {host}:{port} ({e})')
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    r = pinned_request('GET', f"{base_url.rstrip('/')}/api/me", fp,
                       headers=headers, timeout=NODE_TIMEOUT)
    if r.status_code == 401:
        raise NodeError('token rejected (401) — check the token and that it is admin/readonly')
    if r.status_code != 200:
        raise NodeError(f'unexpected response (HTTP {r.status_code})')
    data = r.json()
    return {
        'cert_fp': fp,
        'role': data.get('role'),
        'version': data.get('version'),
        'fqdn': data.get('fqdn'),
        'capabilities': data.get('capabilities', []),
    }


def _serves_ai(llama):
    """A node is serving AI if its llama-server is healthy, or the service is
    active with a model loaded. `llama` is the node's /api/llama (+ embedded
    health), which the node's /api/summary does NOT include — the controller
    fetches it separately for llamacpp-capable nodes."""
    if not isinstance(llama, dict):
        return False
    health = llama.get('health') or {}
    if health.get('ok'):
        return True
    svc = llama.get('service') or {}
    return svc.get('active') == 'active' and bool(llama.get('model'))


# Node module ids (see the node app's MODULES): AI = llamacpp + gpu; storage
# feature areas (disks/replication/schedules are weak evidence but count);
# instances = the v2 Containers module (LXD).
_AI_CAPS = {'llamacpp', 'llama', 'ai', 'gpu'}
_STORAGE_CAPS = {'zfs', 'iscsi', 'nfs', 'smb', 'lvm', 'mdraid', 'disks',
                 'replication', 'schedules', 'minidlna'}


def classify_node(summary, capabilities, llama=None, instances=None):
    """Suggest a node type (Storage / AI / Mixed / Virtualization / Unknown)
    from a node's /api/summary + (separately fetched) llama status + instance
    counts + capabilities. Heuristic per proposal §6.7; manual override lives
    in the registry. Storage/AI evidence outranks containers, so a storage box
    that also runs LXD stays Storage."""
    serves_storage = False
    serves_ai = _serves_ai(llama)
    serves_ct = bool(isinstance(instances, dict) and instances.get('running'))
    if isinstance(summary, dict):
        zfs = summary.get('zfs') or {}
        nfs = summary.get('nfs') or {}
        smb = summary.get('smb') or {}
        iscsi = summary.get('iscsi') or {}
        pools = len(zfs.get('pools', []) or []) if isinstance(zfs.get('pools'), list) else zfs.get('pools', 0)
        serves_storage = bool(pools or smb.get('shares') or nfs.get('exports') or iscsi.get('targets'))
    if not (serves_storage or serves_ai):
        if serves_ct:
            return 'Virtualization'   # runs LXD instances, nothing else
        # idle — fall back to enabled capabilities
        caps = set(capabilities or [])
        has_ai = bool(caps & _AI_CAPS)
        has_storage = bool(caps & _STORAGE_CAPS)
        if has_ai and has_storage:
            return 'Mixed'
        if has_ai:
            return 'AI'
        if has_storage:
            return 'Storage'
        if 'instances' in caps:
            return 'Virtualization'
        return 'Unknown'
    if serves_storage and serves_ai:
        return 'Mixed'
    return 'Storage' if serves_storage else 'AI'


class NexusAdapter(HostAdapter):
    """A single-host Nexus Dashboard node, over its token-authed REST API."""
    kind = 'nexus'
    label = 'Nexus Dashboard node'
    auth = 'token'
    secret_label = 'API token'
    secret_placeholder = 'sd_…'
    url_placeholder = 'https://192.168.1.88:8443'
    verify_tls = False   # nexus nodes are pin-only (self-signed by design)

    def probe(self, base_url, creds):
        return probe_node(base_url, (creds or {}).get('token'))

    def fetch(self, node):
        """Pull one node's summary + resources. Never raises — returns an
        envelope. Adds parsed storage bytes so the rollup can sum capacity."""
        out = base_envelope(node)
        try:
            client = NodeClient(node)
            out['summary'] = client.get_json('summary')
            try:
                out['resources'] = client.get_json('system/resources')
            except NodeError:
                pass  # resources are best-effort
            zfs = (out['summary'] or {}).get('zfs') or {}
            out['used_bytes'] = parse_human_bytes(zfs.get('used'))
            out['size_bytes'] = parse_human_bytes(zfs.get('size'))
            out['ok'] = True
            # Refresh version + capabilities straight from the node so the
            # registry self-heals — no manual "test connection" / token re-entry
            # to update the version column after a node upgrade. Best-effort.
            try:
                me = client.get_json('me')
                if me.get('version'):
                    out['version'] = me['version']
                if isinstance(me.get('capabilities'), list):
                    out['capabilities'] = me['capabilities']
            except NodeError:
                pass
            caps = out.get('capabilities') or []
            # AI nodes: pull llama config + health (not in /api/summary) for the
            # row and for AI/Mixed classification. Best-effort.
            if 'llamacpp' in caps:
                try:
                    li = client.get_json('llama')
                    try:
                        li['health'] = client.get_json('llama/health')
                    except NodeError:
                        li['health'] = {'ok': False}
                    # Only surface llama on nodes that actually run/serve it — a
                    # storage node with the module merely toggled on (no model
                    # configured) shouldn't show a 'down' AI card.
                    if li.get('configured') or _serves_ai(li):
                        out['llama'] = li
                except NodeError:
                    pass
            # Containers nodes (v2 'instances' module): LXD instance counts for
            # the row chip + rollup. Best-effort — a node without LXD answers
            # 502, a disabled module 403; both just skip the chip.
            if 'instances' in caps:
                try:
                    insts = client.get_json('instances')
                    if isinstance(insts, list):
                        is_vm = lambda i: i.get('type') == 'virtual-machine'
                        run = lambda i: str(i.get('status') or '').lower() == 'running'
                        out['instances'] = {
                            'total': len(insts),
                            'running': sum(1 for i in insts if run(i)),
                            'vms': sum(1 for i in insts if is_vm(i)),
                            'containers': sum(1 for i in insts if not is_vm(i)),
                        }
                except NodeError:
                    pass
            out['type_auto'] = classify_node(out['summary'], out.get('capabilities'),
                                             out.get('llama'), out.get('instances'))
        except NodeError as e:
            out['error'] = str(e)
        except Exception as e:
            # Defense in depth: one node must never crash the whole fan-out.
            out['error'] = str(e)
        return out
