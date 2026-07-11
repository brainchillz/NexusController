"""ZimaOS (ZimaCube) NAS adapter — username/password of a local ZimaOS
account. Reuses the VirtAdapter poller and the TrueNAS `nas` envelope (ZimaOS
"storages" appear as pools; RAID/member/disk problems surface as alerts and
the amber dot).

ZimaOS serves PLAIN HTTP on the LAN (no TLS listener), so this adapter is
scheme-aware: an http:// base URL records no certificate fingerprint and the
poller connects http; an https:// URL (e.g. a TLS reverse proxy in front)
gets the normal TOFU pin + pre-poll check."""
from .base import NodeError, base_envelope, envelope_error, cert_fingerprint, _split_host_port, decrypt_secret
from .virt import VirtAdapter
from .truenas import build_nas_envelope


def _scheme(base_url):
    return 'https' if (base_url or '').lower().startswith('https://') else 'http'


class ZimaOSAdapter(VirtAdapter):
    kind = 'zimaos'
    label = 'ZimaOS (ZimaCube)'
    default_port = 80
    default_type = 'Storage'
    url_placeholder = 'http://zimacube.local'
    username_placeholder = 'ZimaOS account'
    verify_tls = False   # plain HTTP on the LAN — nothing to verify/pin

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
        from collectors import zimaos
        try:
            metrics = zimaos.collect_metrics(host, creds['username'], creds['password'],
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
            from collectors import zimaos
            pw = decrypt_secret(node.get('password_enc', '')) or ''
            metrics = zimaos.collect_metrics(host, node.get('username', ''), pw,
                                             port=port, scheme=sch,
                                             verify_ssl=bool(node.get('verify_ssl')))
            return build_nas_envelope(node, metrics)
        except Exception as e:
            out = base_envelope(node)
            out['error'] = envelope_error(node, e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/'   # ZimaOS web UI
