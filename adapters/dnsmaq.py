"""DNSMAQ-MGR adapter — a Nexus dnsmasq Manager instance (the DNS/DHCP
management app, github.com/brainchillz/nexus-dnsmasq-mgr).

It shares a Nexus dashboard node's auth + TLS model exactly — ``dm_`` API
tokens (Bearer/X-API-Token), method-based RBAC, self-signed-→-wildcard cert
with in-handshake fingerprint pinning — but a DIFFERENT API surface: it has no
``/api/summary`` (its module/registry system was dropped), so it gets its own
adapter instead of riding the nexus one.

Fetched LIVE in the fan-out (``polled=False``): its status is a cheap CHAOS
query plus a lease-file read, like the agent's /proc reads. Enroll with a
**readonly** ``dm_`` token (the instance's Settings → API Tokens).

The envelope's ``dnsmaq`` block carries DNS health plus the mirror role, so the
fleet row shows which instance is the **primary** and which is a **secondary**
(a read-only replica synced from the primary).
"""
from .base import (HostAdapter, NodeError, NodeClient, base_envelope, envelope_error,
                   cert_fingerprint, _split_host_port, pinned_request, NODE_TIMEOUT)


def _classify_role(mirror, peers):
    """Determine this instance's mirror role from the receive side
    (/api/mirror/status → sources) and the push side (/api/peers). A node can
    be both (a relay). Returns (role, source_names, peer_count)."""
    sources = sorted((mirror or {}).get('sources') or {}) if isinstance(mirror, dict) else []
    peer_list = (peers or {}).get('peers') or [] if isinstance(peers, dict) else []
    npeers = len(peer_list)
    if sources and npeers:
        return 'relay', sources, npeers
    if sources:
        return 'secondary', sources, 0
    if npeers:
        return 'primary', [], npeers
    return 'standalone', [], 0


def build_dnsmaq_envelope(node, status, stats, mirror, peers):
    """Map DNSMAQ-MGR endpoints into the fan-out envelope. Pure → unit-tested.

    status = /api/dnsmasq/status (required); stats = /api/stats/current;
    mirror = /api/mirror/status; peers = /api/peers. The last three are
    best-effort and may be None."""
    out = base_envelope(node)
    out['ok'] = True
    status = status or {}
    dns = (stats or {}).get('dns') or {}
    dhcp = (stats or {}).get('dhcp') or {}
    role, sources, npeers = _classify_role(mirror, peers)
    peer_list = (peers or {}).get('peers') or [] if isinstance(peers, dict) else []
    out['dnsmaq'] = {
        'running': bool(status.get('running')),
        'dnsmasq_version': status.get('version'),
        'mode': status.get('mode'),
        'dns_enabled': status.get('dns_enabled'),
        'dhcp_enabled': status.get('dhcp_enabled'),
        'tftp_enabled': status.get('tftp_enabled'),
        'hit_ratio': dns.get('hit_ratio'),
        'cache_size': dns.get('cachesize'),
        'active_leases': dhcp.get('active_leases'),
        'pools': [{'tag': p.get('tag'), 'pct': p.get('pct')}
                  for p in (dhcp.get('pools') or [])],
        'role': role,
        'mirror_from': ', '.join(sources) if sources else None,
        'peers_total': npeers,
        'peers_ok': sum(1 for p in peer_list if p.get('last_status') == 'ok'),
    }
    # Surface dnsmasq itself in the Services matrix (green when running). Same
    # {name, active, enabled} shape a nexus node's summary.services uses, so the
    # existing Services page renders a status dot with no frontend change.
    out['summary'] = {'services': {'dnsmasq': {
        'name': 'dnsmasq',
        'active': 'active' if status.get('running') else 'inactive',
        'enabled': 'enabled',
    }}}
    out['type_auto'] = 'DNS'
    return out


class DnsmaqAdapter(HostAdapter):
    kind = 'dnsmaq'
    label = 'DNSMAQ-MGR (dnsmasq manager)'
    auth = 'token'
    secret_label = 'API token'
    secret_placeholder = 'dm_… (readonly token)'
    url_placeholder = 'https://192.168.1.56:8443'
    verify_tls = False    # pin-only (self-signed by default; a real cert pins fine too)
    default_type = 'DNS'
    polled = False        # live fan-out — status is a cheap query + file read

    def probe(self, base_url, creds):
        """Enroll/test: pin the cert, then validate the token against /api/me
        (which DNSMAQ-MGR inherits from the Nexus auth model)."""
        token = ((creds or {}).get('token') or '').strip()
        if not token:
            raise NodeError('a DNSMAQ-MGR API token is required (the instance\'s '
                            'Settings → API Tokens)')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except OSError as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        r = pinned_request('GET', base_url.rstrip('/') + '/api/me', fp,
                           headers={'Authorization': 'Bearer ' + token},
                           timeout=NODE_TIMEOUT)
        if r.status_code == 401:
            raise NodeError('token rejected (401) — create one on the instance '
                            '(Settings → API Tokens)')
        if r.status_code != 200:
            raise NodeError(f'unexpected response (HTTP {r.status_code})')
        try:
            me = r.json()
        except ValueError:
            raise NodeError('non-JSON response (is this a DNSMAQ-MGR URL?)')
        if not me.get('authenticated'):
            raise NodeError('token not accepted by this instance')
        return {'cert_fp': fp, 'role': me.get('role'), 'version': me.get('version'),
                'fqdn': me.get('fqdn'), 'capabilities': [self.kind]}

    def fetch(self, node):
        """Fan-out: one required call (status) + three best-effort (stats,
        mirror role, peers). MUST NOT raise — a single unreachable instance
        must never crash the fleet view."""
        out = base_envelope(node)
        try:
            client = NodeClient(node)
            status = client.get_json('dnsmasq/status')   # required
            stats = mirror = peers = None
            try:
                stats = client.get_json('stats/current')
            except NodeError:
                pass
            try:
                mirror = client.get_json('mirror/status')
            except NodeError:
                pass
            try:
                peers = client.get_json('peers')
            except NodeError:
                pass  # readonly token can read peers; older instances may 404
            env = build_dnsmaq_envelope(node, status, stats, mirror, peers)
            # Self-heal the app version straight from the node after an upgrade.
            try:
                me = client.get_json('me')
                if me.get('version'):
                    env['version'] = me['version']
            except NodeError:
                pass
            return env
        except NodeError as e:
            out['error'] = envelope_error(node, e)
        except Exception as e:
            out['error'] = envelope_error(node, e)   # one host must never crash the fan-out
        return out

    def native_url(self, node):
        return node['base_url'] + '/'   # DNSMAQ-MGR's own web UI
