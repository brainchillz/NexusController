"""OpenMediaVault NAS adapter — web-UI admin username/password (the collector
drives OMV's JSON-RPC API with a cached session; see collectors/omv.py).
Reuses the VirtAdapter poller and the `nas` envelope: OMV's managed data
filesystems appear as pools (mdadm array state folded in), SMART problems on
monitored disks surface as alerts.

Scheme-aware like ZimaOS/Unraid: OMV serves plain HTTP on :80 by default
(http:// → no cert pin); an https:// URL gets the normal TOFU pin."""
from .base import NodeError, base_envelope, envelope_error, cert_fingerprint, _split_host_port, decrypt_secret
from .virt import VirtAdapter
from .truenas import build_nas_envelope
from .zimaos import _scheme


class OmvAdapter(VirtAdapter):
    kind = 'omv'
    label = 'OpenMediaVault'
    default_port = 80
    default_type = 'Storage'
    url_placeholder = 'http://omv.local'
    username_placeholder = 'web-UI admin (usually admin)'
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
        from collectors import omv
        try:
            metrics = omv.collect_metrics(host, creds['username'], creds['password'],
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
            from collectors import omv
            pw = decrypt_secret(node.get('password_enc', '')) or ''
            metrics = omv.collect_metrics(host, node.get('username', ''), pw,
                                          port=port, scheme=sch,
                                          verify_ssl=bool(node.get('verify_ssl')))
            return build_nas_envelope(node, metrics)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = envelope_error(node, e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/'   # OMV workbench UI
