"""Nexus Agent adapter — a bare Linux (later: Windows) machine running the
ultra-light read-only agent from this repo's agent/ directory instead of a
full Nexus Dashboard.

Token auth + self-signed TLS → the same TOFU in-handshake pinning as a
dashboard node. Reading /proc is instant, so the agent is fetched LIVE in the
fan-out (polled=False — the background poller must skip it). An http:// base
URL (agent behind a TLS proxy with AGENT_TLS=0) skips pinning, like ZimaOS."""
from .base import (HostAdapter, NodeError, base_envelope, envelope_error, cert_fingerprint,
                   _split_host_port, pinned_request, decrypt_secret,
                   NODE_TIMEOUT)


def build_agent_envelope(node, payload):
    """Map an agent /api/v1/metrics payload into the fan-out envelope. Pure →
    unit-tested. resources + summed mount bytes light up the CPU/Mem/Store
    meters and storage rollup; the `agent` block feeds the row chips."""
    out = base_envelope(node)
    out['ok'] = True
    cpu = payload.get('cpu') or {}
    mem = payload.get('memory') or {}
    mounts = payload.get('mounts') or []
    out['resources'] = {'cpu_pct': cpu.get('percent'),
                        'memory': {'pct': mem.get('percent')}}
    out['used_bytes'] = sum(int(m.get('used') or 0) for m in mounts)
    out['size_bytes'] = sum(int(m.get('total') or 0) for m in mounts)
    if payload.get('version'):
        out['version'] = payload['version']
    out['agent'] = {
        'platform': payload.get('platform'),
        'os': payload.get('os'),
        'kernel': payload.get('kernel'),
        'hostname': payload.get('hostname'),
        'uptime_seconds': payload.get('uptime_seconds'),
        'load1': cpu.get('load1'),
        'mounts': len(mounts),
        'mount_list': [{'mountpoint': m.get('mountpoint'),
                        'fstype': m.get('fstype'),
                        'percent': m.get('percent'),
                        'total': m.get('total'), 'used': m.get('used')}
                       for m in mounts],
    }
    out['type_auto'] = 'Unknown'   # generic host — pin a type/tags if you like
    return out


def _scheme(base_url):
    return 'https' if (base_url or '').lower().startswith('https://') else 'http'


class AgentAdapter(HostAdapter):
    kind = 'agent'
    label = 'Nexus Agent (bare Linux host)'
    auth = 'token'
    secret_label = 'Agent token'
    secret_placeholder = 'na_…'
    url_placeholder = 'https://192.168.1.88:9143'
    verify_tls = False   # pin-only (self-signed by design)
    default_type = 'Unknown'
    polled = False       # live fan-out fetch — /proc reads are instant

    def _metrics(self, base_url, fingerprint, token):
        r = pinned_request('GET', base_url.rstrip('/') + '/api/v1/metrics',
                           fingerprint,
                           headers={'Authorization': 'Bearer ' + (token or '')},
                           timeout=NODE_TIMEOUT)
        if r.status_code == 401:
            raise NodeError('agent token rejected (401) — token is printed by '
                            'install.sh (or: /opt/nexus-agent/data/token)')
        if r.status_code != 200:
            raise NodeError(f'agent answered HTTP {r.status_code}')
        try:
            payload = r.json()
        except ValueError:
            raise NodeError('non-JSON response (is this a nexus-agent URL?)')
        if payload.get('agent') != 'nexus-agent':
            raise NodeError('not a nexus-agent endpoint')
        return payload

    def probe(self, base_url, creds):
        token = ((creds or {}).get('token') or '').strip()
        if not token:
            raise NodeError('the agent token is required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        fp = None
        if _scheme(base_url) == 'https':
            try:
                fp = cert_fingerprint(host, port)
            except OSError as e:
                raise NodeError(f'cannot reach {host}:{port} ({e})')
        payload = self._metrics(base_url, fp, token)
        return {'cert_fp': fp, 'role': 'readonly', 'version': payload.get('version'),
                'fqdn': payload.get('hostname'), 'capabilities': [self.kind],
                'metrics': payload}

    def fetch(self, node):
        out = base_envelope(node)
        try:
            token = decrypt_secret(node.get('token_enc', '')) if node.get('token_enc') else ''
            payload = self._metrics(node['base_url'], node.get('cert_fp'), token)
            return build_agent_envelope(node, payload)
        except NodeError as e:
            out['error'] = envelope_error(node, e)
        except Exception as e:
            out['error'] = envelope_error(node, e)   # one host must never crash the fan-out
        return out

    def native_url(self, node):
        return None   # the agent has no web UI — the row shows no Open link
