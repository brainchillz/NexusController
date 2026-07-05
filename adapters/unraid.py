"""Unraid (7.x) NAS adapter — webGui username/password (the collector drives
Unraid's GraphQL API through a cached webGui session; see collectors/unraid.py).
Reuses the VirtAdapter poller and the `nas` envelope: the parity array and
every mounted pool appear as pools; disk/pool problems and unread Unraid
alert/warning notifications surface as alerts + the amber dot.

Scheme-aware like ZimaOS: Unraid commonly serves plain HTTP on the LAN
(http:// → no cert pin); an https:// URL gets the normal TOFU pin."""
from .base import NodeError, base_envelope, cert_fingerprint, _split_host_port, decrypt_secret
from .virt import VirtAdapter
from .truenas import build_nas_envelope
from .zimaos import _scheme


class UnraidAdapter(VirtAdapter):
    kind = 'unraid'
    label = 'Unraid (7.x)'
    default_port = 80
    default_type = 'Storage'
    url_placeholder = 'http://unraid.local'
    username_placeholder = 'webGui user (e.g. root)'
    verify_tls = False   # typically plain HTTP on the LAN; https URLs get pinned

    def envelope(self, node, metrics):
        return build_nas_envelope(node, metrics)

    def probe(self, base_url, creds):
        creds = creds or {}
        if not creds.get('username') or not creds.get('password'):
            raise NodeError('username and password are required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        sch = _scheme(base_url)
        fp = None
        if sch == 'https':
            try:
                fp = cert_fingerprint(host, port)
            except OSError as e:
                raise NodeError(f'cannot reach {host}:{port} ({e})')
        from collectors import unraid
        try:
            metrics = unraid.collect_metrics(host, creds['username'], creds['password'],
                                             port=port, scheme=sch,
                                             verify_ssl=bool(creds.get('verify_ssl')))
        except Exception as e:
            raise NodeError(f'connection/credentials rejected: {e}')
        return {'cert_fp': fp, 'role': None, 'version': metrics.get('version'),
                'fqdn': metrics.get('hostname'), 'capabilities': [self.kind],
                'metrics': metrics}

    def collect(self, node):
        try:
            host, port = _split_host_port(node['base_url'])
            sch = _scheme(node['base_url'])
            if sch == 'https':
                self._verify_poll_pin(node, host, port)
            from collectors import unraid
            pw = decrypt_secret(node.get('password_enc', '')) or ''
            metrics = unraid.collect_metrics(host, node.get('username', ''), pw,
                                             port=port, scheme=sch,
                                             verify_ssl=bool(node.get('verify_ssl')))
            return build_nas_envelope(node, metrics)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/Dashboard'   # Unraid webGui
