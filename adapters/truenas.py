"""TrueNAS SCALE/CORE adapter over the JSON-RPC 2.0 WebSocket API (REST v2.0 is
removed in TrueNAS 26.04). Reuses the virt background-poller + cert-pinning
machinery, but authenticates with an API key via ``auth.login_with_api_key``
(not username/password), classifies as Storage, and normalizes into the `nas`
envelope. Read-only — the poller only ever calls read methods (+ one reporting
read). Collector: collectors/truenas.py (lazy websocket-client)."""
from .base import NodeError, base_envelope, cert_fingerprint, _split_host_port, decrypt_secret
from .virt import VirtAdapter


def build_nas_envelope(node, metrics):
    """Map a NAS collector metric dict (collectors/truenas.build_metrics) into the
    fan-out envelope. Pure → unit-tested. Adds a `nas` block + `resources` +
    used/size bytes so the CPU/Mem meters, storage rollup, and overview rows all
    light up for a NAS the same way they do for nexus/virt hosts."""
    out = base_envelope(node)
    out['ok'] = True
    out['resources'] = {'cpu_pct': metrics.get('cpu_usage_percent'),
                        'memory': {'pct': metrics.get('memory_usage_percent')}}
    out['used_bytes'] = int((metrics.get('storage_used_gb') or 0) * 1024 ** 3)
    out['size_bytes'] = int((metrics.get('storage_total_gb') or 0) * 1024 ** 3)
    out['nas'] = {
        'kind': node.get('host_type'),
        'hostname': metrics.get('hostname'),
        'model': metrics.get('model'),
        'version': metrics.get('version'),
        'pools': metrics.get('pool_count') or 0,
        'pools_healthy': metrics.get('pools_healthy') or 0,
        'pools_degraded': metrics.get('pools_degraded') or 0,
        'disks': metrics.get('disk_count') or 0,
        'alerts': metrics.get('alert_count') or 0,
        'alert_list': metrics.get('alerts') or [],
        'pool_list': metrics.get('pools') or [],
        'storage_used_gb': round(metrics.get('storage_used_gb') or 0, 1),
        'storage_total_gb': round(metrics.get('storage_total_gb') or 0, 1),
    }
    out['type_auto'] = 'Storage'
    return out


class TrueNasAdapter(VirtAdapter):
    kind = 'truenas'
    label = 'TrueNAS (SCALE / CORE)'
    auth = 'token'
    secret_label = 'API key'
    secret_placeholder = '1-…'
    url_placeholder = 'https://truenas.local'
    default_port = 443
    default_type = 'Storage'
    verify_tls = True

    def envelope(self, node, metrics):
        return build_nas_envelope(node, metrics)

    def probe(self, base_url, creds):
        creds = creds or {}
        token = (creds.get('token') or '').strip()
        if not token:
            raise NodeError('an API key is required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except OSError as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        from collectors import truenas
        try:
            metrics = truenas.collect_metrics(host, token, port=port,
                                              verify_ssl=bool(creds.get('verify_ssl')))
        except Exception as e:
            raise NodeError(f'connection/API key rejected: {e}')
        return {'cert_fp': fp, 'role': None, 'version': metrics.get('version'),
                'fqdn': metrics.get('hostname'), 'capabilities': [self.kind],
                'metrics': metrics}

    def collect(self, node):
        try:
            host, port = _split_host_port(node['base_url'])
            self._verify_poll_pin(node, host, port)
            from collectors import truenas
            tok = decrypt_secret(node.get('token_enc', '')) or ''
            metrics = truenas.collect_metrics(host, tok, port=port,
                                              verify_ssl=bool(node.get('verify_ssl')))
            return build_nas_envelope(node, metrics)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/ui/dashboard'   # TrueNAS SCALE web UI
