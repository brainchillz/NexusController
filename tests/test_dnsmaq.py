"""DNSMAQ-MGR adapter — envelope mapping (incl. mirror-role classification)
and registration through the host-type seam."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402

STATUS_PRIMARY = {'running': True, 'version': '2.92', 'mode': 'systemd',
                  'dns_enabled': True, 'dhcp_enabled': False, 'tftp_enabled': False}
STATS = {'dns': {'cachesize': 1000, 'hits': 900, 'misses': 100, 'hit_ratio': 90.0},
         'dhcp': {'active_leases': 0, 'pools': []}}


def _node(nid='d1', name='dns1'):
    return {'id': nid, 'name': name, 'base_url': 'https://192.168.1.56:8443',
            'host_type': 'dnsmaq'}


def test_envelope_primary():
    # push side has a peer that is in sync; no receive-side sources → primary.
    peers = {'peers': [{'id': 'p1', 'name': 'node1', 'last_status': 'ok'}]}
    mirror = {'accept': False, 'sources': {}, 'locked': []}
    env = app.build_dnsmaq_envelope(_node(), STATUS_PRIMARY, STATS, mirror, peers)
    assert env['ok'] and env['type_auto'] == 'DNS'
    d = env['dnsmaq']
    assert d['running'] is True and d['dnsmasq_version'] == '2.92'
    assert d['hit_ratio'] == 90.0 and d['cache_size'] == 1000
    assert d['role'] == 'primary'
    assert d['peers_total'] == 1 and d['peers_ok'] == 1
    assert d['mirror_from'] is None
    # dnsmasq shows in the Services matrix (green when running).
    svc = env['summary']['services']['dnsmasq']
    assert svc['active'] == 'active' and svc['enabled'] == 'enabled'


def test_envelope_service_down_when_stopped():
    env = app.build_dnsmaq_envelope(_node(), {'running': False, 'version': '2.92'},
                                    None, None, None)
    svc = env['summary']['services']['dnsmasq']
    assert svc['active'] == 'inactive' and svc['enabled'] == 'enabled'  # → red dot


def test_envelope_secondary():
    # receive side has a source → secondary (read-only replica), regardless of
    # having no outbound peers.
    mirror = {'accept': True, 'sources': {'dns1': {'serial': 12,
              'last_received': 1, 'sections': ['hosts', 'dns']}}, 'locked': ['hosts', 'dns']}
    env = app.build_dnsmaq_envelope(_node('d2', 'node1'),
                                    {'running': True, 'version': '2.90', 'mode': 'child',
                                     'dns_enabled': True, 'dhcp_enabled': False},
                                    STATS, mirror, {'peers': []})
    d = env['dnsmaq']
    assert d['role'] == 'secondary'
    assert d['mirror_from'] == 'dns1'
    assert d['peers_total'] == 0
    assert d['mode'] == 'child'


def test_envelope_relay_and_standalone():
    # both sources and peers → relay
    both = app.build_dnsmaq_envelope(_node(), STATUS_PRIMARY, STATS,
                                     {'sources': {'up': {}}}, {'peers': [{'last_status': 'ok'}]})
    assert both['dnsmaq']['role'] == 'relay'
    # neither → standalone
    alone = app.build_dnsmaq_envelope(_node(), STATUS_PRIMARY, STATS, {'sources': {}}, {'peers': []})
    assert alone['dnsmaq']['role'] == 'standalone'


def test_envelope_tolerates_missing_optional_calls():
    # stats/mirror/peers all unreadable (None) — must still produce a valid
    # envelope from status alone.
    env = app.build_dnsmaq_envelope(_node(), STATUS_PRIMARY, None, None, None)
    d = env['dnsmaq']
    assert env['ok'] and d['running'] is True
    assert d['role'] == 'standalone' and d['hit_ratio'] is None
    assert d['active_leases'] is None


def test_envelope_dhcp_leases_and_pools():
    stats = {'dns': {'hit_ratio': 55.0, 'cachesize': 500},
             'dhcp': {'active_leases': 7, 'pools': [{'tag': 'lan', 'pct': 3.5},
                                                    {'tag': 'iot', 'pct': 12.0}]}}
    status = dict(STATUS_PRIMARY, dhcp_enabled=True)
    env = app.build_dnsmaq_envelope(_node(), status, stats, {'sources': {}}, {'peers': []})
    d = env['dnsmaq']
    assert d['dhcp_enabled'] is True and d['active_leases'] == 7
    assert [p['tag'] for p in d['pools']] == ['lan', 'iot']


def test_adapter_registered_live_fetch():
    a = app._adapter_for({'host_type': 'dnsmaq'})
    assert a.kind == 'dnsmaq' and a.auth == 'token'
    assert a.polled is False           # live fan-out; the poller must skip it
    assert a.default_type == 'DNS'
    d = a.descriptor()
    assert d['label'].startswith('DNSMAQ-MGR') and not d['verify_tls']


def test_dnsmaq_in_host_types():
    from adapters import descriptors
    kinds = [d['kind'] for d in descriptors()]
    assert 'dnsmaq' in kinds


def test_poller_skips_dnsmaq():
    from adapters.virt import _is_virt
    assert not _is_virt({'host_type': 'dnsmaq'})   # live-fetched, not polled
