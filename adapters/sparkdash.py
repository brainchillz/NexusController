"""SparkDash adapter — a sparkrun DGX Spark cluster's monitoring dashboard
(github.com/brainchillz/sparkdash), enrolled as ONE host fronting the whole
cluster (like vCenter fronting its ESXi hosts).

Integration surface (all sparkdash-native — its API is not reshaped):
  * ``GET /api/v1/snapshot`` — public, stable-schema one-shot cluster state
    (per-node vitals incl. GPU/VRAM/disk, Ray, vLLM, recipe, cluster_healthy).
  * Bearer **API tokens** (minted in sparkdash's admin UI) — OPTIONAL here:
    reads are public, so a blank token enrolls monitor-only; a valid token is
    verified at probe (against an admin GET) and recorded as role 'admin',
    which arms the controller's reverse-proxy for future write actions
    (sparkdash writes live under /api/ and accept Bearer — proxy-compatible).
  * HTTPS self-signed by default → TOFU fingerprint pinning, asserted
    in-handshake on every poll (pinned_request), same as nexus nodes.
"""
from .base import (NodeError, base_envelope, cert_fingerprint,
                   _split_host_port, pinned_request, NODE_TIMEOUT)
from .virt import VirtAdapter


def build_spark_envelope(node, snap):
    """Map a sparkdash /api/v1/snapshot into the fan-out envelope. Pure →
    unit-tested. Adds a `spark` block + `resources` (head-node CPU/mem) +
    summed disk used/size bytes so the CPU/Mem meters, storage rollup, and
    overview rows light up like every other host type."""
    out = base_envelope(node)
    out['ok'] = True
    nodes = snap.get('nodes') or []
    head = next((n for n in nodes if n.get('role') == 'head'), nodes[0] if nodes else {})
    out['resources'] = {'cpu_pct': head.get('cpu_pct'),
                        'memory': {'pct': head.get('mem_used_pct')}}
    out['used_bytes'] = sum(int(n.get('disk_used') or 0) for n in nodes)
    out['size_bytes'] = sum(int(n.get('disk_total') or 0) for n in nodes)
    vllm = snap.get('vllm') or {}
    recipe = snap.get('recipe') or {}
    ray = snap.get('ray') or {}
    gpu_utils = [n.get('gpu_util_pct') for n in nodes if n.get('gpu_util_pct') is not None]
    out['spark'] = {
        'kind': 'sparkdash',
        'healthy': bool(snap.get('cluster_healthy')),
        'nodes': snap.get('node_count') or len(nodes),
        'nodes_online': sum(1 for n in nodes if n.get('online')),
        'gpu_util_pct': max(gpu_utils) if gpu_utils else None,
        'vram_used_mb': sum(n.get('vram_used_mb') or 0 for n in nodes),
        'model': vllm.get('model'),
        'vllm_healthy': bool(vllm.get('healthy')),
        'recipe': recipe.get('name'),
        'recipe_running': bool(recipe.get('running')),
        'ray_alive': ray.get('nodes_alive'),
        'ray_total': ray.get('nodes_total'),
        'node_list': [{'name': n.get('name'), 'ip': n.get('ip'),
                       'role': n.get('role'), 'online': bool(n.get('online')),
                       'gpu_util_pct': n.get('gpu_util_pct'),
                       'vram_used_mb': n.get('vram_used_mb')} for n in nodes],
    }
    out['type_auto'] = 'AI'
    return out


class SparkDashAdapter(VirtAdapter):
    kind = 'sparkdash'
    label = 'SparkDash (DGX Spark cluster)'
    auth = 'token'
    secret_label = 'API token'
    secret_placeholder = 'spk_… (optional — blank = monitor-only)'
    url_placeholder = 'https://spark-head.local:7862'
    default_port = 7862
    default_type = 'AI'
    verify_tls = False   # pin-only, like nexus nodes (self-signed by design)

    def envelope(self, node, snap):
        return build_spark_envelope(node, snap)

    def _snapshot(self, base_url, fingerprint):
        """One pinned GET of the versioned snapshot. Raises NodeError."""
        r = pinned_request('GET', base_url.rstrip('/') + '/api/v1/snapshot',
                           fingerprint, timeout=NODE_TIMEOUT)
        if r.status_code != 200:
            raise NodeError(f'snapshot failed (HTTP {r.status_code})')
        try:
            return r.json()
        except ValueError:
            raise NodeError('snapshot returned non-JSON (is this a sparkdash URL?)')

    def probe(self, base_url, creds):
        """Enroll/test: pin the cert, fetch a snapshot, and — if a token was
        supplied — verify it against an admin read (sparkdash's /api/auth/me
        only reflects sessions, so a Bearer-gated GET is the token check)."""
        token = ((creds or {}).get('token') or '').strip()
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except OSError as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        snap = self._snapshot(base_url, fp)
        if not isinstance(snap.get('nodes'), list):
            raise NodeError('unexpected snapshot shape (is this a sparkdash URL?)')
        role = None
        if token:
            r = pinned_request('GET', base_url.rstrip('/') + '/api/admin/cert', fp,
                               headers={'Authorization': 'Bearer ' + token},
                               timeout=NODE_TIMEOUT)
            if r.status_code in (401, 403):
                raise NodeError('API token rejected (%d) — mint one in SparkDash '
                                'admin → API tokens' % r.status_code)
            if r.status_code != 200:
                raise NodeError(f'token check failed (HTTP {r.status_code})')
            role = 'admin'    # valid token = write-capable via the proxy
        head = next((n for n in snap['nodes'] if n.get('role') == 'head'), {})
        return {'cert_fp': fp, 'role': role, 'version': None,
                'fqdn': head.get('hostname'), 'capabilities': [self.kind],
                'metrics': snap}

    def collect(self, node):
        """Poller entry point. The snapshot is plain HTTPS JSON, so unlike the
        hypervisor adapters this pins in-handshake (no pre-check race)."""
        try:
            snap = self._snapshot(node['base_url'], node.get('cert_fp'))
            return build_spark_envelope(node, snap)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/'   # sparkdash's own UI
